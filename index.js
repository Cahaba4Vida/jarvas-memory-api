// index.js — Jarvas Memory API (Redis-backed)
// Best-product rebuild path:
// - Admin vs Coach enforced server-side (never trust prompts)
// - Coach can ONLY read/write allowed client keys
// - Coach cannot delete/restore/history
// - JSON-native API boundary (store strings in Redis, return parsed JSON)
// - Adds OTP + JWT + /me endpoints (true client scoping; no phone params on /me)
//
// Dependencies:
//   npm i express cors redis dotenv jsonwebtoken
//
// Required env:
//   REDIS_URL
//   MEMORY_API_KEY_ADMIN
//   MEMORY_API_KEY_COACH
//   JWT_SECRET
//
// Optional env:
//   PORT=3000
//   CORS_ORIGINS="https://yourdomain.com,https://www.yoursite.com"
//   OTP_TTL_SECONDS=600
//   JWT_TTL_DAYS=30
//   OTP_DEV_MODE=true   (returns OTP code in response for testing ONLY)

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { createClient } = require("redis");

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "10mb" }));

// ---------- CORS ----------
const CORS_ORIGINS = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: CORS_ORIGINS.length ? CORS_ORIGINS : true,
    credentials: true,
  })
);

const PORT = process.env.PORT || 3000;

// ---------- Secrets / Auth ----------
const ADMIN_KEY = process.env.MEMORY_API_KEY_ADMIN;
const COACH_KEY = process.env.MEMORY_API_KEY_COACH;
const JWT_SECRET = process.env.JWT_SECRET;

if (!ADMIN_KEY || !COACH_KEY || !JWT_SECRET) {
  console.error("❌ Missing env vars. Required: MEMORY_API_KEY_ADMIN, MEMORY_API_KEY_COACH, JWT_SECRET");
  process.exit(1);
}

const OTP_TTL_SECONDS = Math.max(Number(process.env.OTP_TTL_SECONDS || 600), 60); // default 10m
const JWT_TTL_DAYS = Math.max(Number(process.env.JWT_TTL_DAYS || 30), 1);
const OTP_DEV_MODE = String(process.env.OTP_DEV_MODE || "false").toLowerCase() === "true";
const ALLOW_PHONE_LOGIN_NO_OTP =
  String(process.env.ALLOW_PHONE_LOGIN_NO_OTP || "false").toLowerCase() === "true";


// ---------- Redis ----------
const REDIS_URL = process.env.REDIS_URL;
if (!REDIS_URL) {
  console.error("❌ REDIS_URL is missing. Refusing to start.");
  process.exit(1);
}

const redis = createClient({
  url: REDIS_URL,
  socket: { reconnectStrategy: (retries) => Math.min(retries * 200, 2000) },
});
redis.on("error", (err) => console.error("Redis error:", err));

// ---------- Key layout ----------
function userHashKey(userId) {
  return `jarvas:${userId || "zach"}`; // one hash per user namespace
}
function trashHashKey(userId) {
  return `jarvas_trash:${userId || "zach"}`;
}
function trashMetaKey(userId) {
  return `jarvas_trash_meta:${userId || "zach"}`;
}
function historyListKey(userId, key) {
  return `jarvas_hist:${userId || "zach"}:${key}`;
}
function otpKey(phone10) {
  return `jarvas:otp:${phone10}`;
}

// ---------- Phone normalization ----------
function normalizePhone(input) {
  const digits = String(input || "").replace(/\D/g, "");
  if (digits.length === 11 && digits.startsWith("1")) return digits.slice(1);
  if (digits.length !== 10) return null;
  return digits;
}

// ---------- JSON helpers (JSON-native API boundary) ----------
function encodeValue(v) {
  return JSON.stringify(v === undefined ? null : v);
}

function maybeParseJsonString(v) {
  if (typeof v !== "string") return v;
  const t = v.trim();
  if (
    (t.startsWith("{") && t.endsWith("}")) ||
    (t.startsWith("[") && t.endsWith("]"))
  ) {
    try {
      return JSON.parse(t);
    } catch {
      return v;
    }
  }
  return v;
}

// decodeValue returns real JSON types whenever possible
function decodeValue(s) {
  if (s == null) return null;
  try {
    const parsed = JSON.parse(s);
    return maybeParseJsonString(parsed); // handles double-encoded JSON strings
  } catch {
    return maybeParseJsonString(s);
  }
}

// ---------- History ----------
async function pushHistoryIfExists(userId, key) {
  const hashKey = userHashKey(userId);
  const prevRaw = await redis.hGet(hashKey, key);
  if (prevRaw == null) return;

  const entry = JSON.stringify({
    ts: new Date().toISOString(),
    prev_raw: prevRaw,
  });

  const histKey = historyListKey(userId, key);
  await redis.lPush(histKey, entry);
  await redis.lTrim(histKey, 0, 49);
  await redis.expire(histKey, 60 * 60 * 24 * 30); // 30 days
}

// ---------- RBAC rules ----------
const ADMIN_ONLY_KEYS = new Set(["training_clients"]);

const COACH_ALLOWED_KEYS = new Set([
  "client_meta",
  "training_profile",
  "program_current",
  "program_history",
  "checkin_history",
  "last_checkin",
  "notes",
]);

const PROTECTED_KEYS = new Set([
  "reminders",
  "meetings",
  "weekly_objectives",
  "weekly_mission",
  "todo_list",
  "training_clients",
]);

function isEmptyValue(v) {
  if (v === null || v === undefined) return true;
  if (typeof v === "string" && v.trim() === "") return true;
  if (Array.isArray(v) && v.length === 0) return true;
  if (typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === 0) return true;
  return false;
}

function isForbiddenError(e) {
  return String(e?.message || "").startsWith("forbidden:");
}

// ---------- API Key auth (server-to-server / legacy tooling) ----------
function checkApiKey(req, res, next) {
  const headerKey = req.headers["x-api-key"];
  if (headerKey === ADMIN_KEY) req.role = "admin";
  else if (headerKey === COACH_KEY) req.role = "coach";
  else return res.status(401).json({ error: "invalid api key" });
  next();
}

function assertAllowedByApiKeyRole(req, userId, keyOrNull) {
  if (req.role === "admin") return;

  const uid = String(userId || "");
  if (!uid) throw new Error("forbidden: coach requires explicit user_id");
  if (uid === "zach") throw new Error("forbidden: coach key cannot access zach");
  if (!uid.startsWith("client:")) throw new Error('forbidden: coach user_id must start with "client:"');

  if (keyOrNull != null) {
    const k = String(keyOrNull);
    if (ADMIN_ONLY_KEYS.has(k)) throw new Error(`forbidden: key "${k}" is admin-only`);
    if (!COACH_ALLOWED_KEYS.has(k)) throw new Error(`forbidden: key "${k}" not allowed for coach`);
  }
}

// ---------- JWT auth (true client scoping) ----------
function requireClientJwt(req, res, next) {
  const auth = String(req.headers.authorization || "");
  if (!auth.toLowerCase().startsWith("bearer ")) {
    return res.status(401).json({ error: "missing bearer token" });
  }
  const token = auth.slice(7).trim();
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload || payload.role !== "client" || typeof payload.sub !== "string") {
      return res.status(403).json({ error: "invalid token role" });
    }
    const phone10 = normalizePhone(payload.sub);
    if (!phone10) return res.status(403).json({ error: "invalid token subject" });
    req.clientPhone = phone10;
    req.clientUserId = `client:${phone10}`;
    next();
  } catch (e) {
    return res.status(401).json({ error: "invalid or expired token" });
  }
}

// ---------- Client defaults / repair ----------
function clientDefaults(nowIso) {
  return {
    client_meta: {
      coaching_tier: "unknown",
      billing_status: "none",
      billing: null,
      created_at: nowIso,
      updated_at: nowIso,
    },
    training_profile: {},
    program_current: null,
    program_history: [],
    checkin_history: [],
    last_checkin: null,
    notes: "",
  };
}

function coerceClientShape(obj, nowIso) {
  // Only repairs missing keys and obvious wrong types; avoids wiping existing.
  const d = clientDefaults(nowIso);
  const out = { ...d, ...(obj && typeof obj === "object" ? obj : {}) };

  // Type repairs (gentle)
  if (!out.client_meta || typeof out.client_meta !== "object" || Array.isArray(out.client_meta)) out.client_meta = d.client_meta;
  if (!out.training_profile || typeof out.training_profile !== "object" || Array.isArray(out.training_profile)) out.training_profile = d.training_profile;

  if (out.program_current === undefined) out.program_current = null;

  if (!Array.isArray(out.program_history)) out.program_history = d.program_history;
  if (!Array.isArray(out.checkin_history)) out.checkin_history = d.checkin_history;

  if (out.last_checkin === undefined) out.last_checkin = null;
  if (typeof out.notes !== "string") out.notes = String(out.notes ?? "");

  // Timestamp hygiene
  out.client_meta.updated_at = nowIso;
  if (!out.client_meta.created_at) out.client_meta.created_at = nowIso;

  return out;
}

async function readClientMap(userId) {
  const hash = await redis.hGetAll(userHashKey(userId));
  const out = {};
  for (const [k, raw] of Object.entries(hash)) out[k] = decodeValue(raw);
  return out;
}

async function writeClientKeys(userId, patch, { forceProtected = false } = {}) {
  const nowIso = new Date().toISOString();
  const entries = Object.entries(patch || {});
  for (const [k, v] of entries) {
    const key = String(k);
    const normalizedVal = maybeParseJsonString(v);

    if (PROTECTED_KEYS.has(key) && isEmptyValue(normalizedVal) && !forceProtected) {
      throw new Error(`forbidden: refusing empty overwrite for protected key "${key}"`);
    }

    await pushHistoryIfExists(userId, key);
    await redis.hSet(userHashKey(userId), key, encodeValue(normalizedVal));
  }

  // auto set updated_at if client_meta included
  if (patch && patch.client_meta && typeof patch.client_meta === "object" && !Array.isArray(patch.client_meta)) {
    // already handled by caller typically
  }

  return nowIso;
}

// ---------- Roster helpers (canonical = zach/training_clients) ----------
async function updateRosterAtomic(mutatorFn) {
  const zachHash = userHashKey("zach");
  const field = "training_clients";

  for (let attempt = 0; attempt < 6; attempt++) {
    await redis.watch(zachHash);
    const raw = await redis.hGet(zachHash, field);
    let roster = raw == null ? [] : decodeValue(raw);
    if (!Array.isArray(roster)) roster = [];

    const next = mutatorFn(roster) || roster;
    const multi = redis.multi();
    multi.hSet(zachHash, field, encodeValue(next));
    const execRes = await multi.exec();
    if (execRes) {
      await redis.unwatch();
      return next;
    }
    // conflict — loop
  }
  throw new Error("memory store conflict: failed to update roster");
}

function upsertRosterEntry(roster, entry) {
  const phone = entry.phone;
  const idx = roster.findIndex((c) => c && c.phone === phone);
  if (idx >= 0) roster[idx] = { ...roster[idx], ...entry };
  else roster.push(entry);
  return roster;
}

// ---------- Health ----------
app.get("/healthz", async (req, res) => {
  try {
    const pong = await redis.ping();
    res.json({ ok: true, redis: pong });
  } catch {
    res.status(503).json({ ok: false, error: "redis unavailable" });
  }
});

// ============================================================================
// AUTH (OTP -> JWT) — clients
// ============================================================================

// Request OTP (send text in real world; dev mode can return the code)
app.post("/auth/request_otp", async (req, res) => {
  const phone10 = normalizePhone(req.body?.phone);
  if (!phone10) return res.status(400).json({ error: "invalid phone (need 10 digits)" });

  // Generate 6-digit code
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const salt = JWT_SECRET; // reuse secret as salt (fine); you can set OTP_SALT separately if you want
  const hash = crypto.createHash("sha256").update(code + ":" + phone10 + ":" + salt).digest("hex");

  const payload = {
    hash,
    created_at: new Date().toISOString(),
  };

  await redis.set(otpKey(phone10), JSON.stringify(payload), { EX: OTP_TTL_SECONDS });

  // TODO: integrate Twilio here. For now:
  if (OTP_DEV_MODE) {
    return res.json({ status: "ok", dev_code: code, ttl_seconds: OTP_TTL_SECONDS });
  }
  return res.json({ status: "ok" });
});

// Verify OTP -> issue JWT
app.post("/auth/verify_otp", async (req, res) => {
  const phone10 = normalizePhone(req.body?.phone);
  const code = String(req.body?.code || "").trim();
  if (!phone10) return res.status(400).json({ error: "invalid phone (need 10 digits)" });
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: "invalid code" });

  const raw = await redis.get(otpKey(phone10));
  if (!raw) return res.status(401).json({ error: "code expired or not found" });

  let stored;
  try { stored = JSON.parse(raw); } catch { return res.status(401).json({ error: "code expired or not found" }); }

  const salt = JWT_SECRET;
  const hash = crypto.createHash("sha256").update(code + ":" + phone10 + ":" + salt).digest("hex");
  if (hash !== stored.hash) return res.status(401).json({ error: "invalid code" });

  await redis.del(otpKey(phone10));

  const token = jwt.sign(
    { role: "client", sub: phone10 },
    JWT_SECRET,
    { expiresIn: `${JWT_TTL_DAYS}d` }
  );

  res.json({ status: "ok", token });
});
// OPTIONAL: phone-only login (no OTP) — enable with ALLOW_PHONE_LOGIN_NO_OTP=true
app.post("/auth/phone_login", async (req, res) => {
  if (!ALLOW_PHONE_LOGIN_NO_OTP) {
    return res.status(403).json({ error: "phone_login disabled by config" });
  }

  const phone10 = normalizePhone(req.body?.phone);
  if (!phone10) {
    return res.status(400).json({ error: "invalid phone (need 10 digits)" });
  }

  try {
    const token = jwt.sign(
      { role: "client", sub: phone10 },
      JWT_SECRET,
      { expiresIn: `${JWT_TTL_DAYS}d` }
    );

    return res.json({ status: "ok", token });
  } catch (e) {
    console.error("/auth/phone_login failed:", e);
    return res.status(503).json({ error: "token generation failed" });
  }
});

// ============================================================================
// CLIENT-SCOPED ENDPOINTS (/me/*) — require Bearer JWT
// ============================================================================

// Get current client memory (allowed keys only)
app.get("/me", requireClientJwt, async (req, res) => {
  try {
    const full = await readClientMap(req.clientUserId);

    // Return only allowed keys (even if other keys exist)
    const out = {};
    for (const k of COACH_ALLOWED_KEYS) {
      if (k in full) out[k] = full[k];
    }

    // If empty, return 404 so client can call /me/register
    if (Object.keys(out).length === 0) {
      return res.status(404).json({ error: "client namespace not initialized" });
    }

    res.json({ user_id: req.clientUserId, data: out });
  } catch (e) {
    console.error("/me failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// Register/initialize current client (safe repair + roster upsert)
app.post("/me/register", requireClientJwt, async (req, res) => {
  const nowIso = new Date().toISOString();
  const name = String(req.body?.name || "").trim();
  const coaching_tier = req.body?.coaching_tier ? String(req.body.coaching_tier) : undefined;

  try {
    // Read existing
    const existing = await readClientMap(req.clientUserId);

    // Build a single client object from allowed keys
    const clientObj = {};
    for (const k of COACH_ALLOWED_KEYS) {
      if (k in existing) clientObj[k] = existing[k];
    }

    const repaired = coerceClientShape(clientObj, nowIso);
    if (name) repaired.client_meta.name = name;
    if (coaching_tier) repaired.client_meta.coaching_tier = coaching_tier;

    // Write repaired keys back (allowed keys only)
    await writeClientKeys(req.clientUserId, repaired);

    // Server-side roster upsert (canonical roster lives in zach/training_clients)
    await updateRosterAtomic((roster) => {
      const entry = {
        phone: req.clientPhone,
        name: repaired.client_meta?.name || name || "Unknown",
        tier: repaired.client_meta?.coaching_tier || "unknown",
        status: "active",
        created_at: repaired.client_meta?.created_at || nowIso,
        updated_at: nowIso,
        source: "me/register",
      };
      return upsertRosterEntry(roster, entry);
    });

    res.json({ status: "ok", user_id: req.clientUserId, data: repaired });
  } catch (e) {
    console.error("/me/register failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// Patch current client (allowed keys only)
app.patch("/me", requireClientJwt, async (req, res) => {
  const nowIso = new Date().toISOString();
  const updates = req.body?.updates;

  if (!updates || typeof updates !== "object" || Array.isArray(updates)) {
    return res.status(400).json({ error: "body must be { updates: { key: value, ... } }" });
  }

  // Validate allowed keys only
  for (const k of Object.keys(updates)) {
    if (!COACH_ALLOWED_KEYS.has(k)) {
      return res.status(403).json({ error: `forbidden: key "${k}" not allowed` });
    }
  }

  try {
    // Merge with existing, repair shape, write only changed keys
    const existing = await readClientMap(req.clientUserId);
    const current = {};
    for (const k of COACH_ALLOWED_KEYS) if (k in existing) current[k] = existing[k];

    const merged = { ...current, ...updates };

    // If client_meta exists, auto-touch updated_at
    if (merged.client_meta && typeof merged.client_meta === "object" && !Array.isArray(merged.client_meta)) {
      merged.client_meta.updated_at = nowIso;
      if (!merged.client_meta.created_at) merged.client_meta.created_at = nowIso;
    }

    const repaired = coerceClientShape(merged, nowIso);

    // Write only keys present in updates (+ client_meta if it was updated)
    const toWrite = {};
    for (const k of Object.keys(updates)) toWrite[k] = repaired[k];
    if ("client_meta" in updates) toWrite.client_meta = repaired.client_meta;

    await writeClientKeys(req.clientUserId, toWrite);

    // Optional: if coaching_tier changed, keep roster in sync
    if (updates.client_meta && typeof updates.client_meta === "object") {
      const tier = repaired.client_meta?.coaching_tier;
      const name = repaired.client_meta?.name;
      await updateRosterAtomic((roster) => {
        const entry = {
          phone: req.clientPhone,
          name: name || "Unknown",
          tier: tier || "unknown",
          status: "active",
          updated_at: nowIso,
          source: "me/patch",
        };
        return upsertRosterEntry(roster, entry);
      });
    }

    res.json({ status: "ok" });
  } catch (e) {
    console.error("/me patch failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// ============================================================================
// ADMIN ENDPOINTS (/admin/*) — x-api-key must be ADMIN
// ============================================================================

function requireAdminApiKey(req, res, next) {
  const headerKey = req.headers["x-api-key"];
  if (headerKey !== ADMIN_KEY) return res.status(401).json({ error: "invalid api key" });
  req.role = "admin";
  next();
}

// List roster
app.get("/admin/clients", requireAdminApiKey, async (req, res) => {
  try {
    const raw = await redis.hGet(userHashKey("zach"), "training_clients");
    const roster = raw == null ? [] : decodeValue(raw);
    res.json({ status: "ok", clients: Array.isArray(roster) ? roster : [] });
  } catch (e) {
    console.error("/admin/clients failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// Create/Upsert client (writes roster + repairs namespace)
app.post("/admin/clients", requireAdminApiKey, async (req, res) => {
  const phone10 = normalizePhone(req.body?.phone);
  if (!phone10) return res.status(400).json({ error: "invalid phone (need 10 digits)" });

  const nowIso = new Date().toISOString();
  const name = String(req.body?.name || "").trim() || "Unknown";
  const tier = String(req.body?.tier || "unknown");
  const status = String(req.body?.status || "active");

  const userId = `client:${phone10}`;

  try {
    // Repair client namespace
    const existing = await readClientMap(userId);
    const current = {};
    for (const k of COACH_ALLOWED_KEYS) if (k in existing) current[k] = existing[k];

    const repaired = coerceClientShape(current, nowIso);
    repaired.client_meta.name = name;
    repaired.client_meta.coaching_tier = tier;
    repaired.client_meta.updated_at = nowIso;

    await writeClientKeys(userId, repaired);

    // Upsert roster atomically
    const roster = await updateRosterAtomic((arr) => {
      const entry = {
        phone: phone10,
        name,
        tier,
        status,
        created_at: repaired.client_meta.created_at || nowIso,
        updated_at: nowIso,
        source: "admin/create",
      };
      return upsertRosterEntry(arr, entry);
    });

    res.json({ status: "ok", user_id: userId, roster_count: roster.length });
  } catch (e) {
    console.error("/admin/clients POST failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// Patch client roster fields (and optionally sync into client_meta)
app.patch("/admin/clients/:phone", requireAdminApiKey, async (req, res) => {
  const phone10 = normalizePhone(req.params.phone);
  if (!phone10) return res.status(400).json({ error: "invalid phone" });

  const nowIso = new Date().toISOString();
  const patch = req.body || {};
  const allowed = ["name", "tier", "status"];
  for (const k of Object.keys(patch)) {
    if (!allowed.includes(k)) return res.status(400).json({ error: `unknown field "${k}"` });
  }

  try {
    await updateRosterAtomic((roster) => {
      const idx = roster.findIndex((c) => c && c.phone === phone10);
      const cur = idx >= 0 ? roster[idx] : { phone: phone10 };
      const next = { ...cur, ...patch, updated_at: nowIso, source: "admin/patch" };
      return upsertRosterEntry(roster, next);
    });

    // Optional: also sync tier/name into client_meta if that namespace exists
    const userId = `client:${phone10}`;
    const existing = await readClientMap(userId);
    if (Object.keys(existing).length) {
      const cm = existing.client_meta && typeof existing.client_meta === "object" ? existing.client_meta : {};
      if (patch.name) cm.name = patch.name;
      if (patch.tier) cm.coaching_tier = patch.tier;
      cm.updated_at = nowIso;
      await writeClientKeys(userId, { client_meta: cm });
    }

    res.json({ status: "ok" });
  } catch (e) {
    console.error("/admin/clients PATCH failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// Delete client (default = deactivate; hard delete requires ?hard=true)
app.delete("/admin/clients/:phone", requireAdminApiKey, async (req, res) => {
  const phone10 = normalizePhone(req.params.phone);
  if (!phone10) return res.status(400).json({ error: "invalid phone" });

  const hard = String(req.query.hard || "false").toLowerCase() === "true";
  const nowIso = new Date().toISOString();
  const userId = `client:${phone10}`;

  try {
    if (!hard) {
      await updateRosterAtomic((roster) => {
        const idx = roster.findIndex((c) => c && c.phone === phone10);
        const cur = idx >= 0 ? roster[idx] : { phone: phone10, name: "Unknown", tier: "unknown" };
        const next = { ...cur, status: "inactive", updated_at: nowIso, source: "admin/deactivate" };
        return upsertRosterEntry(roster, next);
      });
      return res.json({ status: "ok", deactivated: true });
    }

    // Hard delete: remove roster entry + delete client hash
    await updateRosterAtomic((roster) => roster.filter((c) => !(c && c.phone === phone10)));
    await redis.del(userHashKey(userId));
    await redis.del(trashHashKey(userId));
    await redis.del(trashMetaKey(userId));
    res.json({ status: "ok", hard_deleted: true });
  } catch (e) {
    console.error("/admin/clients DELETE failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// ============================================================================
// LEGACY ENDPOINTS (/get_memory, /save_memory, /delete_memory, /restore_memory, /history)
// Keep these for bots/tools that still use them.
// Coach key is now fully restricted (client:* only, allowed keys only, no delete/restore/history).
// ============================================================================

// GET /get_memory?user_id=...&format=list|map
app.get("/get_memory", checkApiKey, async (req, res) => {
  const format = String(req.query.format || "list").toLowerCase();
  const userId = req.query.user_id || (req.role === "admin" ? "zach" : "");

  try {
    assertAllowedByApiKeyRole(req, userId, null);

    const hash = await redis.hGetAll(userHashKey(userId));
    const data = {};
    const memories = [];

    for (const [key, raw] of Object.entries(hash)) {
      // Coach sees ONLY allowed keys even if extra exist
      if (req.role === "coach" && !COACH_ALLOWED_KEYS.has(key)) continue;

      const value = decodeValue(raw);
      data[key] = value;
      memories.push({ key, value });
    }

    if (format === "map") return res.json({ user_id: userId, data });
    return res.json({ user_id: userId, memories });
  } catch (e) {
    if (isForbiddenError(e)) return res.status(403).json({ error: e.message });
    console.error("get_memory failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// POST /save_memory?force=true|false  Body: { user_id, key, value }
app.post("/save_memory", checkApiKey, async (req, res) => {
  const { user_id, key, value } = req.body || {};
  if (!key) return res.status(400).json({ error: "key is required" });

  const userId = user_id || (req.role === "admin" ? "zach" : "");
  const force = String(req.query.force || "false").toLowerCase() === "true";

  try {
    assertAllowedByApiKeyRole(req, userId, key);

    const normalized = maybeParseJsonString(value);

    if (PROTECTED_KEYS.has(String(key)) && isEmptyValue(normalized) && !force) {
      return res.status(400).json({
        error: `Refusing empty overwrite for protected key "${key}". Use ?force=true if intentional.`,
      });
    }

    // Coach key: still only allowed keys (enforced above)
    await pushHistoryIfExists(userId, key);
    await redis.hSet(userHashKey(userId), key, encodeValue(normalized));

    res.json({ status: "ok" });
  } catch (e) {
    if (isForbiddenError(e)) return res.status(403).json({ error: e.message });
    console.error("save_memory failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// POST /delete_memory  (Admin-only)
app.post("/delete_memory", checkApiKey, async (req, res) => {
  if (req.role === "coach") return res.status(403).json({ error: "forbidden: coach cannot delete" });

  const { user_id = "zach", key } = req.body || {};
  if (!key) return res.status(400).json({ error: "key is required" });

  try {
    // admin can delete anything; still enforce admin-only keys logic by policy (you control via Jarvas prompt)
    const hashKey = userHashKey(user_id);
    const prevRaw = await redis.hGet(hashKey, key);
    if (prevRaw == null) return res.json({ status: "ok", note: "key not found" });

    await pushHistoryIfExists(user_id, key);

    await redis.hSet(trashHashKey(user_id), key, prevRaw);
    await redis.hSet(
      trashMetaKey(user_id),
      key,
      JSON.stringify({ deleted_at: new Date().toISOString() })
    );

    await redis.expire(trashHashKey(user_id), 60 * 60 * 24 * 30);
    await redis.expire(trashMetaKey(user_id), 60 * 60 * 24 * 30);

    await redis.hDel(hashKey, key);

    res.json({ status: "ok", soft_deleted: true });
  } catch (e) {
    console.error("delete_memory failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// POST /restore_memory (Admin-only)
app.post("/restore_memory", checkApiKey, async (req, res) => {
  if (req.role === "coach") return res.status(403).json({ error: "forbidden: coach cannot restore" });

  const { user_id = "zach", key } = req.body || {};
  if (!key) return res.status(400).json({ error: "key is required" });

  try {
    const raw = await redis.hGet(trashHashKey(user_id), key);
    if (raw == null) return res.status(404).json({ error: "no trash entry for key" });

    await pushHistoryIfExists(user_id, key);
    await redis.hSet(userHashKey(user_id), key, raw);

    await redis.hDel(trashHashKey(user_id), key);
    await redis.hDel(trashMetaKey(user_id), key);

    res.json({ status: "ok", restored: true });
  } catch (e) {
    console.error("restore_memory failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// GET /history (Admin-only)
app.get("/history", checkApiKey, async (req, res) => {
  if (req.role === "coach") return res.status(403).json({ error: "forbidden: coach cannot access history" });

  const userId = req.query.user_id || "zach";
  const key = req.query.key;
  const limit = Math.min(Number(req.query.limit || 10) || 10, 50);

  if (!key) return res.status(400).json({ error: "key is required" });

  try {
    const entries = await redis.lRange(historyListKey(userId, key), 0, limit - 1);
    res.json({ status: "ok", user_id: userId, key, entries: entries.map((s) => JSON.parse(s)) });
  } catch (e) {
    console.error("history failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// ---------- Start ----------
(async () => {
  try {
    await redis.connect();
    console.log("✅ Connected to Redis");
    app.listen(PORT, () => console.log(`✅ Jarvas Memory API running on port ${PORT}`));
  } catch (e) {
    console.error("❌ Failed to connect to Redis. Refusing to start.", e);
    process.exit(1);
  }
})();
