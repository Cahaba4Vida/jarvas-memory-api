/* eslint-disable no-console */
require("dotenv").config();

const express = require("express");
const crypto = require("crypto");
const { createClient } = require("redis");

const app = express();

// 10mb JSON body limit
app.use(express.json({ limit: "10mb" }));

// -------------------------
// ENV / CONFIG
// -------------------------
const { REDIS_URL, MEMORY_API_KEY_ADMIN, MEMORY_API_KEY_COACH, PORT } =
  process.env;

const REQUIRED = ["REDIS_URL", "MEMORY_API_KEY_ADMIN", "MEMORY_API_KEY_COACH"];
const missing = REQUIRED.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`❌ Missing env vars. Required: ${missing.join(", ")}`);
  process.exit(1);
}

const LIST_HISTORY = true;
const HISTORY_LIST_KEY = "mem_history"; // admin-only

// Session settings
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const SESSION_PREFIX = "sess:";

// Only these keys are ever returned from /me (client bundle)
const COACH_ALLOWED_KEYS = [
  "client_meta",
  "training_profile",
  "program_current",
  "program_history",
  "checkin_history",
  "last_checkin",
  "notes",
];

// Coach key can only touch these keys via legacy /get_memory, /save_memory
const COACH_ALLOWED_WRITE_KEYS = new Set(COACH_ALLOWED_KEYS);

// Redis key for user hash
const userHashKey = (userId) => `mem:${userId}`;

// -------------------------
// REDIS
// -------------------------
const redis = createClient({ url: REDIS_URL });

redis.on("error", (err) => {
  console.error("Redis error:", err);
});

async function ensureRedis() {
  if (!redis.isOpen) await redis.connect();
}

// -------------------------
// UTIL: JSON safe
// -------------------------
function safeJsonParse(s) {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}
function safeJsonStringify(v) {
  return JSON.stringify(v);
}
function nowIso() {
  return new Date().toISOString();
}

// -------------------------
// AUTH: API KEY (admin/coach)
// -------------------------
function requireApiKey(req, res, next) {
  const apiKey = req.header("x-api-key");
  if (!apiKey) return res.status(401).json({ error: "missing_api_key" });

  if (apiKey === MEMORY_API_KEY_ADMIN) {
    req.apiRole = "admin";
    return next();
  }
  if (apiKey === MEMORY_API_KEY_COACH) {
    req.apiRole = "coach";
    return next();
  }
  return res.status(401).json({ error: "invalid_api_key" });
}

// -------------------------
// AUTH: CLIENT SESSION
// -------------------------
// IMPORTANT CHANGE:
// Accept session key from either header OR query param.
// This is needed because ChatGPT Actions is unreliable with dynamic headers.
async function requireClientSession(req, res, next) {
  try {
    await ensureRedis();

    const sk =
      req.header("x-session-key") ||
      (req.query?.session_key ? String(req.query.session_key) : "");

    if (!sk) return res.status(401).json({ error: "missing_session_key" });

    const uid = await redis.get(`${SESSION_PREFIX}${sk}`);
    if (!uid) return res.status(401).json({ error: "invalid_session_key" });

    if (typeof uid !== "string" || !uid.startsWith("client:")) {
      return res.status(403).json({ error: "forbidden_session_subject" });
    }

    req.clientUserId = uid; // e.g. client:208...
    req.sessionKey = sk;
    return next();
  } catch (e) {
    console.error("requireClientSession failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
}

// -------------------------
// PASSCODE AUTH (NO SMS)
// -------------------------
// Stored under a private field in the user's Redis hash: "__auth_passcode"
const AUTH_FIELD = "__auth_passcode";

// PBKDF2 parameters
const PASSCODE_ITER = 120000;
const PASSCODE_KEYLEN = 32;
const PASSCODE_DIGEST = "sha256";

function pbkdf2Hash(passcode, saltHex) {
  const salt = Buffer.from(saltHex, "hex");
  const derived = crypto.pbkdf2Sync(
    passcode,
    salt,
    PASSCODE_ITER,
    PASSCODE_KEYLEN,
    PASSCODE_DIGEST
  );
  return derived.toString("hex");
}

function normalizePhone(phone) {
  const digits = String(phone || "").replace(/\D/g, "");
  if (digits.length !== 10) return null;
  return digits;
}

function newSessionKey() {
  return crypto.randomBytes(32).toString("hex");
}

// Create/Update passcode for a phone (client can do this themselves)
app.post("/auth/set_passcode", async (req, res) => {
  try {
    await ensureRedis();

    const phone = normalizePhone(req.body?.phone);
    const passcode = String(req.body?.passcode || "");

    if (!phone) return res.status(400).json({ error: "invalid_phone" });
    if (!passcode || passcode.length < 6) {
      return res.status(400).json({ error: "passcode_too_short_min_6" });
    }

    const uid = `client:${phone}`;
    const saltHex = crypto.randomBytes(16).toString("hex");
    const hashHex = pbkdf2Hash(passcode, saltHex);

    const authObj = {
      v: 1,
      iter: PASSCODE_ITER,
      digest: PASSCODE_DIGEST,
      salt: saltHex,
      hash: hashHex,
      updated_at: nowIso(),
    };

    await redis.hSet(userHashKey(uid), {
      [AUTH_FIELD]: safeJsonStringify(authObj),
    });

    return res.json({ status: "ok", message: "passcode_set" });
  } catch (e) {
    console.error("POST /auth/set_passcode failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// Login: phone + passcode -> session_key (no JWT)
app.post("/auth/login", async (req, res) => {
  try {
    await ensureRedis();

    const phone = normalizePhone(req.body?.phone);
    const passcode = String(req.body?.passcode || "");

    if (!phone) return res.status(400).json({ error: "invalid_phone" });
    if (!passcode) return res.status(400).json({ error: "missing_passcode" });

    const uid = `client:${phone}`;
    const h = await redis.hGet(userHashKey(uid), AUTH_FIELD);
    if (!h) return res.status(401).json({ error: "passcode_not_set" });

    const authObj = safeJsonParse(h);
    if (!authObj?.salt || !authObj?.hash) {
      return res.status(401).json({ error: "passcode_not_set" });
    }

    const attempt = pbkdf2Hash(passcode, authObj.salt);
    const ok = crypto.timingSafeEqual(
      Buffer.from(attempt, "hex"),
      Buffer.from(authObj.hash, "hex")
    );

    if (!ok) return res.status(401).json({ error: "invalid_passcode" });

    const session_key = newSessionKey();
    await redis.set(`${SESSION_PREFIX}${session_key}`, uid, {
      EX: SESSION_TTL_SECONDS,
    });

    return res.json({ session_key, expires_in_seconds: SESSION_TTL_SECONDS });
  } catch (e) {
    console.error("POST /auth/login failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// Optional: logout (invalidate session)
// Now supports either header x-session-key OR query ?session_key=...
app.post("/auth/logout", async (req, res) => {
  try {
    await ensureRedis();

    const sk =
      req.header("x-session-key") ||
      (req.query?.session_key ? String(req.query.session_key) : "");

    if (!sk) return res.status(400).json({ error: "missing_session_key" });

    await redis.del(`${SESSION_PREFIX}${sk}`);
    return res.json({ status: "ok", message: "logged_out" });
  } catch (e) {
    console.error("POST /auth/logout failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// -------------------------
// MEMORY HELPERS (Redis hash per user)
// -------------------------
async function readUserMap(userId) {
  await ensureRedis();
  const raw = await redis.hGetAll(userHashKey(userId));
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    if (k === AUTH_FIELD) continue; // never return auth field
    out[k] = safeJsonParse(v);
  }
  return out;
}

async function writeUserKeys(userId, updates, actor = "unknown") {
  await ensureRedis();

  const payload = {};
  for (const [k, v] of Object.entries(updates || {})) {
    payload[k] = safeJsonStringify(v);
  }

  if (Object.keys(payload).length) {
    await redis.hSet(userHashKey(userId), payload);
  }

  if (LIST_HISTORY) {
    const entry = {
      at: nowIso(),
      user_id: userId,
      actor,
      keys: Object.keys(payload),
    };
    await redis.lPush(HISTORY_LIST_KEY, safeJsonStringify(entry));
    await redis.lTrim(HISTORY_LIST_KEY, 0, 2000);
  }
}

// -------------------------
// HEALTH
// -------------------------
app.get("/healthz", async (req, res) => {
  try {
    await ensureRedis();
    return res.json({ ok: true, at: nowIso() });
  } catch {
    return res.status(503).json({ ok: false });
  }
});

// ============================================================================
// LEGACY ADMIN/COACH ENDPOINTS (API KEY)
// ============================================================================

app.get("/get_memory", requireApiKey, async (req, res) => {
  try {
    const userId = String(req.query?.user_id || "");
    const format = String(req.query?.format || "");
    if (!userId) return res.status(400).json({ error: "missing_user_id" });
    if (format && format !== "map")
      return res.status(400).json({ error: "invalid_format" });

    if (req.apiRole === "coach") {
      if (userId === "zach")
        return res
          .status(403)
          .json({ error: "forbidden: coach key cannot access zach" });
      if (!userId.startsWith("client:"))
        return res
          .status(403)
          .json({ error: "forbidden: coach can only access client:*" });
    }

    const full = await readUserMap(userId);

    if (req.apiRole === "coach") {
      const filtered = {};
      for (const k of COACH_ALLOWED_KEYS) {
        if (k in full) filtered[k] = full[k];
      }
      return res.json({ user_id: userId, data: filtered });
    }

    return res.json({ user_id: userId, data: full });
  } catch (e) {
    console.error("GET /get_memory failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

app.post("/save_memory", requireApiKey, async (req, res) => {
  try {
    const { user_id: userId, key, value } = req.body || {};
    if (!userId || !key)
      return res.status(400).json({ error: "missing_user_id_or_key" });

    if (req.apiRole === "coach") {
      if (userId === "zach")
        return res
          .status(403)
          .json({ error: "forbidden: coach key cannot access zach" });
      if (!String(userId).startsWith("client:"))
        return res
          .status(403)
          .json({ error: "forbidden: coach can only access client:*" });
      if (!COACH_ALLOWED_WRITE_KEYS.has(String(key)))
        return res.status(403).json({ error: "forbidden_key" });
    }

    await writeUserKeys(String(userId), { [String(key)]: value }, req.apiRole);
    return res.json({ status: "ok" });
  } catch (e) {
    console.error("POST /save_memory failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

app.post("/delete_memory", requireApiKey, async (req, res) => {
  if (req.apiRole !== "admin")
    return res.status(403).json({ error: "admin_only" });

  try {
    const userId = String(req.body?.user_id || "");
    const keys = req.body?.keys;

    if (!userId) return res.status(400).json({ error: "missing_user_id" });

    if (!keys) {
      await ensureRedis();
      await redis.del(userHashKey(userId));
      return res.json({ status: "ok", deleted: "all" });
    }

    if (!Array.isArray(keys) || keys.some((k) => typeof k !== "string")) {
      return res
        .status(400)
        .json({ error: "keys_must_be_array_of_strings_or_omit_for_all" });
    }

    await ensureRedis();
    await redis.hDel(userHashKey(userId), keys);
    return res.json({ status: "ok", deleted: keys });
  } catch (e) {
    console.error("POST /delete_memory failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

app.post("/restore_memory", requireApiKey, async (req, res) => {
  if (req.apiRole !== "admin")
    return res.status(403).json({ error: "admin_only" });

  try {
    const userId = String(req.body?.user_id || "");
    const data = req.body?.data;

    if (!userId) return res.status(400).json({ error: "missing_user_id" });
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return res.status(400).json({ error: "data_must_be_object" });
    }

    await writeUserKeys(userId, data, "admin_restore");
    return res.json({ status: "ok" });
  } catch (e) {
    console.error("POST /restore_memory failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

app.get("/history", requireApiKey, async (req, res) => {
  if (req.apiRole !== "admin")
    return res.status(403).json({ error: "admin_only" });

  try {
    await ensureRedis();
    const n = Math.min(
      Math.max(parseInt(String(req.query?.limit || "50"), 10) || 50, 1),
      200
    );
    const items = await redis.lRange(HISTORY_LIST_KEY, 0, n - 1);
    return res.json({ items: items.map(safeJsonParse).filter(Boolean) });
  } catch (e) {
    console.error("GET /history failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// ============================================================================
// CLIENT-SCOPED ENDPOINTS (/me/*) — require session_key (header or query)
// ============================================================================

// Get current client memory (allowed keys only)
app.get("/me", requireClientSession, async (req, res) => {
  try {
    const full = await readUserMap(req.clientUserId);

    const out = {};
    for (const k of COACH_ALLOWED_KEYS) {
      if (k in full) out[k] = full[k];
    }

    if (Object.keys(out).length === 0) {
      return res.status(404).json({ error: "client_namespace_not_initialized" });
    }

    return res.json({ user_id: req.clientUserId, data: out });
  } catch (e) {
    console.error("GET /me failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// Returns today's date + ISO weekday in the client's timezone (or provided timezone)
app.get("/me/today", requireClientSession, async (req, res) => {
  try {
    const tzFromQuery = req.query?.timezone ? String(req.query.timezone) : null;

    let tz = tzFromQuery;
    if (!tz) {
      const full = await readUserMap(req.clientUserId);
      tz =
        full?.program_current?.state?.timezone ||
        full?.program_current?.timezone ||
        "America/Boise";
    }

    const dateFmt = new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    });
    const date = dateFmt.format(new Date());

    const weekdayShort = new Intl.DateTimeFormat("en-US", {
      timeZone: tz,
      weekday: "short",
    }).format(new Date());

    const map = { Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6, Sun: 7 };
    const weekday = map[weekdayShort];

    return res.json({
      timezone: tz,
      date,
      weekday,
      now_iso: nowIso(),
    });
  } catch (e) {
    console.error("GET /me/today failed:", e);
    return res.status(400).json({ error: "invalid_timezone_or_request" });
  }
});

// Initialize the client namespace (idempotent)
app.post("/me/register", requireClientSession, async (req, res) => {
  try {
    const full = await readUserMap(req.clientUserId);

    const already = COACH_ALLOWED_KEYS.some((k) => k in full);
    if (already) return res.json({ status: "ok", initialized: true });

    const initial = req.body && typeof req.body === "object" ? req.body : {};

    const defaults = {
      client_meta: initial.client_meta || {},
      training_profile: initial.training_profile || {},
      program_current: initial.program_current || null,
      program_history: initial.program_history || [],
      checkin_history: initial.checkin_history || [],
      last_checkin: initial.last_checkin || null,
      notes: initial.notes || [],
    };

    await writeUserKeys(req.clientUserId, defaults, "client_register");
    return res.json({ status: "ok", initialized: true });
  } catch (e) {
    console.error("POST /me/register failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// Patch allowed keys for the logged-in client
app.patch("/me", requireClientSession, async (req, res) => {
  try {
    const updates = req.body?.updates;
    if (!updates || typeof updates !== "object" || Array.isArray(updates)) {
      return res.status(400).json({ error: "updates_must_be_object" });
    }

    const filtered = {};
    for (const [k, v] of Object.entries(updates)) {
      if (COACH_ALLOWED_WRITE_KEYS.has(k)) filtered[k] = v;
    }

    if (Object.keys(filtered).length === 0) {
      return res.status(400).json({ error: "no_allowed_keys_in_updates" });
    }

    await writeUserKeys(req.clientUserId, filtered, "client_patch");
    return res.json({ status: "ok", updated: Object.keys(filtered) });
  } catch (e) {
    console.error("PATCH /me failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// Program sync verification endpoint
app.get("/me/program/status", requireClientSession, async (req, res) => {
  try {
    const full = await readUserMap(req.clientUserId);
    const p = full.program_current;

    if (
      !p ||
      typeof p !== "object" ||
      Array.isArray(p) ||
      !Array.isArray(p.weeks)
    ) {
      return res.json({ ready: false, reason: "no_program" });
    }

    const total = Number(p.weeks_total || 0);
    const saved = p.weeks.filter(Boolean).length;

    return res.json({
      weeks_total: total,
      weeks_saved: saved,
      complete: total > 0 && saved === total,
      updated_at: p.updated_at || null,
    });
  } catch (e) {
    console.error("GET /me/program/status failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// Upsert a single week inside program_current (full day-level persistence)
app.put("/me/program/week/:weekNumber", requireClientSession, async (req, res) => {
  const weekNumber = parseInt(String(req.params.weekNumber || ""), 10);
  if (!Number.isInteger(weekNumber) || weekNumber < 1 || weekNumber > 52) {
    return res.status(400).json({ error: "weekNumber_must_be_1_to_52" });
  }

  const weekObj = req.body?.week;
  if (!weekObj || typeof weekObj !== "object" || Array.isArray(weekObj)) {
    return res.status(400).json({ error: 'body_must_be_{ "week": { ... } }' });
  }
  if (!Array.isArray(weekObj.days) || weekObj.days.length === 0) {
    return res.status(400).json({ error: "week.days_must_be_non_empty_array" });
  }
  if (weekObj.week != null && Number(weekObj.week) !== weekNumber) {
    return res.status(400).json({ error: "week.week_must_match_weekNumber" });
  }

  try {
    const full = await readUserMap(req.clientUserId);
    const program = full.program_current;

    if (!program || typeof program !== "object" || Array.isArray(program)) {
      return res.status(400).json({
        error: "program_current_not_found_create_shell_first",
      });
    }

    // Enforce Phase 1: weeks_total must be set before persisting weeks
    const weeksTotal = Number(program.weeks_total || 0);
    if (!weeksTotal) {
      return res
        .status(400)
        .json({ error: "weeks_total_not_set_create_shell_first" });
    }
    if (weekNumber > weeksTotal) {
      return res
        .status(400)
        .json({ error: `weekNumber_exceeds_weeks_total_${weeksTotal}` });
    }

    if (!Array.isArray(program.weeks)) program.weeks = [];

    const targetLen = Math.max(program.weeks.length, weeksTotal, weekNumber);
    while (program.weeks.length < targetLen) program.weeks.push(null);

    const normalized = { ...weekObj, week: weekNumber, updated_at: nowIso() };
    program.weeks[weekNumber - 1] = normalized;
    program.updated_at = nowIso();

    await writeUserKeys(
      req.clientUserId,
      { program_current: program },
      "client_program_week_upsert"
    );

    return res.json({
      status: "ok",
      weekNumber,
      daysCount: normalized.days.length,
    });
  } catch (e) {
    console.error("PUT /me/program/week failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// -------------------------
// START
// -------------------------
const listenPort = Number(PORT || 10000);
app.listen(listenPort, () => {
  console.log(`Jarvas Memory API running on port ${listenPort}`);
});
