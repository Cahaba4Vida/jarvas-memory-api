
/* eslint-disable no-console */
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const { createClient } = require("redis");

const app = express();

// -------------------------
// CORS (Portal + local dev)
// -------------------------
// Note: CORS only affects browser requests. Server-to-server calls are unaffected.
const CORS_ALLOWLIST = new Set([
  "https://appzachedwards.netlify.app",
  "https://appzachedwardsllc.netlify.app",
  "https://app.edwardszachllc.com",
  "http://localhost:5173",
  "http://localhost:3000",
]);

app.use(
  cors({
    origin(origin, cb) {
      // Allow non-browser calls (no origin header)
      if (!origin) return cb(null, true);
      return cb(null, CORS_ALLOWLIST.has(origin));
    },
    credentials: false,
  })
);

// 10mb JSON body limit
app.use(express.json({ limit: "10mb" }));

// -------------------------
// ENV / CONFIG
// -------------------------
const {
  REDIS_URL,
  MEMORY_API_KEY_ADMIN,
  MEMORY_API_KEY_COACH,
  PORT,

  // Portal auth (optional but required for OTP routes)
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM,
  JWT_SECRET,
} = process.env;

const REQUIRED = ["REDIS_URL", "MEMORY_API_KEY_ADMIN", "MEMORY_API_KEY_COACH"];
const missing = REQUIRED.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`❌ Missing env vars. Required: ${missing.join(", ")}`);
  process.exit(1);
}

const LIST_HISTORY = true;
const HISTORY_LIST_KEY = "mem_history"; // admin-only

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

// Portal registry (so Jarvas can list all portal users)
const PORTAL_USERS_INDEX_KEY = "portal_users:index"; // Redis SET of portal user ids

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

function normalizePhone(phone) {
  const digits = String(phone || "").replace(/\D/g, "");
  if (digits.length !== 10) return null;
  return digits;
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function portalUserIdFromEmail(email) {
  // Using a dedicated namespace avoids colliding with your client:* ids.
  return `portal:${normalizeEmail(email)}`;
}

function otpKey(email) {
  return `otp:${normalizeEmail(email)}`;
}

function generateOtpCode() {
  return String(Math.floor(100000 + Math.random() * 900000)); // 6 digits
}

function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

// -------------------------
// SMTP (Zoho) - used only by OTP routes
// -------------------------
function smtpConfigured() {
  return Boolean(SMTP_HOST && SMTP_USER && SMTP_PASS && (SMTP_FROM || SMTP_USER));
}

const mailer = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT || 587),
  secure: false, // STARTTLS on 587
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS,
  },
  requireTLS: true,
});

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
// AUTH: JWT (portal users)
// -------------------------
function requireJwt(req, res, next) {
  try {
    const auth = String(req.headers.authorization || "");
    if (!auth.startsWith("Bearer ")) {
      return res.status(401).json({ error: "missing_bearer_token" });
    }
    if (!JWT_SECRET) {
      return res.status(500).json({ error: "jwt_secret_not_configured" });
    }
    const token = auth.slice(7);
    const payload = jwt.verify(token, JWT_SECRET);
    req.portal = payload; // { sub, email, ... }
    return next();
  } catch (e) {
    return res.status(401).json({ error: "invalid_or_expired_token" });
  }
}

// -------------------------
// OPTION A: COACH-SCOPED CLIENT (PHONE REQUIRED)
// -------------------------
// For /me/* routes: require coach/admin API key AND a 10-digit phone query param.
// This removes passcodes/sessions while keeping the API protected.
function requireCoachPhone(req, res, next) {
  if (req.apiRole !== "coach" && req.apiRole !== "admin") {
    return res.status(403).json({ error: "forbidden_role" });
  }

  const phone = normalizePhone(req.query?.phone);
  if (!phone) return res.status(400).json({ error: "invalid_phone" });

  req.clientUserId = `client:${phone}`;
  req.clientPhone = phone;
  return next();
}

// -------------------------
// MEMORY HELPERS (Redis hash per user)
// -------------------------
async function readUserMap(userId) {
  await ensureRedis();
  const raw = await redis.hGetAll(userHashKey(userId));
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
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

// ============================================================================
// PORTAL AUTH (OTP) — DOES NOT AFFECT EXISTING API KEY ROUTES
// ============================================================================

// Request a 6-digit login code via email
app.post("/auth/request-code", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    if (!email || !email.includes("@")) {
      return res.status(400).json({ error: "invalid_email" });
    }

    if (!smtpConfigured()) {
      return res.status(500).json({ error: "smtp_not_configured" });
    }

    await ensureRedis();

    const code = generateOtpCode();
    const codeHash = sha256(code);

    // Store the hashed code for 10 minutes
    await redis.set(otpKey(email), codeHash, { EX: 600 });

    await mailer.sendMail({
      from: SMTP_FROM || SMTP_USER,
      to: email,
      subject: "Your ZachFit login code",
      text:
        `Your ZachFit login code is: ${code}\n\n` +
        `This code expires in 10 minutes.\n\n` +
        `If you didn’t request this, you can ignore this email.`,
    });

    return res.json({ ok: true });
  } catch (e) {
    console.error("POST /auth/request-code failed:", e);
    return res.status(500).json({ error: "failed_to_send_code" });
  }
});

// Verify code and issue JWT
app.post("/auth/verify-code", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const code = String(req.body?.code || "").trim();

    if (!email || !email.includes("@") || !code) {
      return res.status(400).json({ error: "missing_email_or_code" });
    }
    if (!JWT_SECRET) {
      return res.status(500).json({ error: "jwt_secret_not_configured" });
    }

    await ensureRedis();

    const storedHash = await redis.get(otpKey(email));
    if (!storedHash) {
      return res.status(400).json({ error: "code_expired_or_not_found" });
    }

    const providedHash = sha256(code);
    if (providedHash !== storedHash) {
      return res.status(401).json({ error: "invalid_code" });
    }

    // Consume the OTP
    await redis.del(otpKey(email));

    const userId = portalUserIdFromEmail(email);

    // Maintain a portal user registry so Jarvas can list all portal users
    await redis.sAdd(PORTAL_USERS_INDEX_KEY, userId);

    // Upsert a minimal profile record
    const existing = await readUserMap(userId);
    const createdAt = existing?.portal_meta?.created_at || nowIso();

    await writeUserKeys(
      userId,
      {
        portal_meta: {
          email,
          created_at: createdAt,
          last_login_at: nowIso(),
        },
      },
      "portal_auth"
    );

    const token = jwt.sign(
      { sub: userId, email },
      JWT_SECRET,
      { expiresIn: "30d" }
    );

    return res.json({ ok: true, token, user_id: userId });
  } catch (e) {
    console.error("POST /auth/verify-code failed:", e);
    return res.status(500).json({ error: "failed_to_verify_code" });
  }
});

// Portal “me” endpoint (returns allowed keys from the portal user's namespace)
app.get("/portal/me", requireJwt, async (req, res) => {
  try {
    const userId = String(req.portal?.sub || "");
    if (!userId.startsWith("portal:")) {
      return res.status(401).json({ error: "invalid_subject" });
    }

    const full = await readUserMap(userId);

    // Reuse the same safe key list for now
    const out = {};
    for (const k of COACH_ALLOWED_KEYS) {
      if (k in full) out[k] = full[k];
    }

    return res.json({
      ok: true,
      user_id: userId,
      email: req.portal?.email || null,
      data: out,
    });
  } catch (e) {
    console.error("GET /portal/me failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// Admin: list all portal users (IDs only)
// Uses existing admin API key to avoid exposing to clients.
app.get("/admin/portal-users", requireApiKey, async (req, res) => {
  if (req.apiRole !== "admin") {
    return res.status(403).json({ error: "admin_only" });
  }
  try {
    await ensureRedis();
    const ids = await redis.sMembers(PORTAL_USERS_INDEX_KEY);
    return res.json({ count: ids.length, user_ids: ids.sort() });
  } catch (e) {
    console.error("GET /admin/portal-users failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// ============================================================================
// HEALTH
// ============================================================================
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
// COACH-SCOPED ENDPOINTS (/me/*) — Option A (x-api-key + ?phone=...)
// ============================================================================

// Get current client memory (allowed keys only)
app.get("/me", requireApiKey, requireCoachPhone, async (req, res) => {
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
app.get("/me/today", requireApiKey, requireCoachPhone, async (req, res) => {
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
app.post("/me/register", requireApiKey, requireCoachPhone, async (req, res) => {
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

    await writeUserKeys(req.clientUserId, defaults, "coach_register");
    return res.json({ status: "ok", initialized: true });
  } catch (e) {
    console.error("POST /me/register failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// Patch allowed keys for the scoped client
app.patch("/me", requireApiKey, requireCoachPhone, async (req, res) => {
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

    await writeUserKeys(req.clientUserId, filtered, "coach_patch");
    return res.json({ status: "ok", updated: Object.keys(filtered) });
  } catch (e) {
    console.error("PATCH /me failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// Program sync verification endpoint
app.get(
  "/me/program/status",
  requireApiKey,
  requireCoachPhone,
  async (req, res) => {
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
  }
);

// Upsert a single week inside program_current (full day-level persistence)
app.put(
  "/me/program/week/:weekNumber",
  requireApiKey,
  requireCoachPhone,
  async (req, res) => {
    const weekNumber = parseInt(String(req.params.weekNumber || ""), 10);
    if (!Number.isInteger(weekNumber) || weekNumber < 1 || weekNumber > 52) {
      return res.status(400).json({ error: "weekNumber_must_be_1_to_52" });
    }

    const weekObj = req.body?.week;
    if (!weekObj || typeof weekObj !== "object" || Array.isArray(weekObj)) {
      return res
        .status(400)
        .json({ error: 'body_must_be_{ "week": { ... } }' });
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
        "coach_program_week_upsert"
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
  }
);

// -------------------------
// START
// -------------------------
const listenPort = Number(PORT || 10000);
app.listen(listenPort, () => {
  console.log(`Jarvas Memory API running on port ${listenPort}`);
});
