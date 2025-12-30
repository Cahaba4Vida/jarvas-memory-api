/* eslint-disable no-console */
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const { createClient } = require("redis");

const BUILD_TAG = "otp_portal_v1";

const app = express();

// 10mb JSON body limit
app.use(express.json({ limit: "10mb" }));

// -------------------------
// CORS (Portal + local dev)
// -------------------------
const CORS_ALLOWLIST = new Set([
  "https://zachedwardsllc.netlify.app",
  "https://zachedwardsllc.com",
  "https://www.zachedwardsllc.com",
  "https://edwardszachllc.com",
  "https://www.edwardszachllc.com",
  "http://localhost:8888",
  "http://localhost:5173",
  "http://localhost:3000",
]);

app.use(
  cors({
    origin: (origin, cb) => {
      // Allow server-to-server / curl / PowerShell (no Origin header)
      if (!origin) return cb(null, true);
      if (CORS_ALLOWLIST.has(origin)) return cb(null, true);
      return cb(new Error(`CORS blocked for origin: ${origin}`));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-api-key"],
  })
);
app.options(/.*/, cors());

// -------------------------
// ENV / CONFIG
// -------------------------
const {
  REDIS_URL,
  MEMORY_API_KEY_ADMIN,
  MEMORY_API_KEY_COACH,
  PORT,
  JWT_SECRET,
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  SMTP_FROM,
  // SendGrid (recommended on Render free tier)
  SENDGRID_API_KEY,
  OTP_FROM_EMAIL,
  OTP_FROM_NAME,
} = process.env;

const REQUIRED = ["REDIS_URL", "MEMORY_API_KEY_ADMIN", "MEMORY_API_KEY_COACH"];
const missing = REQUIRED.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`❌ Missing env vars. Required: ${missing.join(", ")}`);
  process.exit(1);
}

const LIST_HISTORY = true;
const HISTORY_LIST_KEY = "mem_history"; // admin-only

// Only these keys are returned to coach/portal clients
const COACH_ALLOWED_KEYS = [
  "client_meta",
  "training_profile",
  "program_current",
  "program_history",
  "checkin_history",
  "last_checkin",
  "notes",
];

// Coach key can only write these keys via legacy /get_memory, /save_memory and /me/*
const COACH_ALLOWED_WRITE_KEYS = new Set(COACH_ALLOWED_KEYS);

// Redis key for user hash
const userHashKey = (userId) => `mem:${userId}`;

// OTP + portal user registry
const otpKey = (email) => `otp:${email}`;
const portalUsersSetKey = "portal_users";

// -------------------------
// REDIS
// -------------------------
const redis = createClient({ url: REDIS_URL });
redis.on("error", (err) => console.error("Redis error:", err));

async function ensureRedis() {
  if (!redis.isOpen) await redis.connect();
}

// -------------------------
// UTIL
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
  const e = String(email || "").trim().toLowerCase();
  if (!e || !e.includes("@")) return null;
  return e;
}

function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

function generateOtpCode() {
  // 6-digit numeric
  return String(Math.floor(100000 + Math.random() * 900000));
}


function sendgridConfigured() {
  return Boolean(SENDGRID_API_KEY && (OTP_FROM_EMAIL || SMTP_FROM));
}

function emailProvider() {
  if (sendgridConfigured()) return "sendgrid";
  if (smtpConfigured()) return "smtp";
  return "none";
}

function jwtConfigured() {
  return Boolean(JWT_SECRET);
}

// -------------------------
// MAILER (Zoho SMTP)
// -------------------------
function makeTransport() {
  if (!smtpConfigured()) return null;
  const portNum = parseInt(String(SMTP_PORT), 10);
  const secure = portNum === 465;
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: portNum,
    secure,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
}

async function sendOtpEmail(toEmail, code) {
  const fromEmail = OTP_FROM_EMAIL || SMTP_FROM;
  const fromName = OTP_FROM_NAME || "ZachFit";

  // Preferred: SendGrid Web API (HTTPS) — avoids SMTP port blocks on Render free tier
  if (sendgridConfigured()) {
    const subject = `${fromName} login code`;
    const text = `Your ${fromName} login code is: ${code}

This code expires in 10 minutes.`;

    const payload = {
      personalizations: [{ to: [{ email: toEmail }] }],
      from: { email: fromEmail, name: fromName },
      subject,
      content: [{ type: "text/plain", value: text }],
    };

    const r = await fetch("https://api.sendgrid.com/v3/mail/send", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${SENDGRID_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!r.ok) {
      const body = await r.text().catch(() => "");
      throw new Error(`SENDGRID_FAILED:${r.status}:${body}`);
    }

    return;
  }

  // Fallback: SMTP (useful for local dev / paid Render instances that allow SMTP ports)
  const transporter = makeTransport();
  if (!transporter) throw new Error("SMTP not configured");

  const subject = `${fromName} login code`;
  const text = `Your ${fromName} login code is: ${code}

This code expires in 10 minutes.`;

  await transporter.sendMail({
    from: SMTP_FROM,
    to: toEmail,
    subject,
    text,
  });
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
// AUTH: JWT (portal)
// -------------------------
function requireJwt(req, res, next) {
  if (!jwtConfigured()) {
    return res.status(500).json({ error: "jwt_not_configured" });
  }

  const auth = String(req.header("authorization") || "");
  if (!auth.toLowerCase().startsWith("bearer ")) {
    return res.status(401).json({ error: "missing_bearer_token" });
  }

  const token = auth.slice(7).trim();
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const email = normalizeEmail(decoded?.email || decoded?.sub);
    if (!email) return res.status(401).json({ error: "invalid_token" });
    req.portalEmail = email;
    return next();
  } catch {
    return res.status(401).json({ error: "invalid_or_expired_token" });
  }
}

// -------------------------
// OPTION A: COACH-SCOPED CLIENT (PHONE REQUIRED)
// -------------------------
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

// -------------------------
// HEALTH / VERSION
// -------------------------
app.get("/healthz", async (req, res) => {
  try {
    await ensureRedis();
    return res.json({
      ok: true,
      at: nowIso(),
      build: BUILD_TAG,
      email_provider: emailProvider(),
      sendgrid_configured: sendgridConfigured(),
      smtp_configured: smtpConfigured(),
      jwt_configured: jwtConfigured(),
    });
  } catch {
    return res.status(503).json({ ok: false, build: BUILD_TAG });
  }
});

app.get("/version", (req, res) => {
  return res.json({
    build: BUILD_TAG,
    at: nowIso(),
    email_provider: emailProvider(),
    sendgrid_configured: sendgridConfigured(),
    smtp_configured: smtpConfigured(),
    jwt_configured: jwtConfigured(),
  });
});

// ============================================================================
// PORTAL OTP AUTH (NO API KEY)
// ============================================================================

app.post("/auth/request-code", async (req, res) => {
  try {
    if (!smtpConfigured()) {
      return res.status(500).json({ error: "smtp_not_configured" });
    }

    const email = normalizeEmail(req.body?.email);
    if (!email) return res.status(400).json({ error: "invalid_email" });

    const code = generateOtpCode();
    const hash = sha256(code);

    await ensureRedis();
    await redis.set(otpKey(email), hash, { EX: 600 }); // 10 minutes

    await sendOtpEmail(email, code);

    // Add to portal registry (so Jarvas can list users)
    await redis.sAdd(portalUsersSetKey, email);

    return res.json({ ok: true });
  } catch (e) {
    console.error("POST /auth/request-code failed:", e);
    return res.status(503).json({ error: "otp_unavailable" });
  }
});

app.post("/auth/verify-code", async (req, res) => {
  try {
    if (!jwtConfigured()) {
      return res.status(500).json({ error: "jwt_not_configured" });
    }

    const email = normalizeEmail(req.body?.email);
    const code = String(req.body?.code || "").trim();

    if (!email || !code) {
      return res.status(400).json({ error: "missing_email_or_code" });
    }

    await ensureRedis();
    const stored = await redis.get(otpKey(email));
    if (!stored) return res.status(400).json({ error: "code_expired_or_missing" });

    const ok = stored === sha256(code);
    if (!ok) return res.status(401).json({ error: "invalid_code" });

    await redis.del(otpKey(email));

    const token = jwt.sign({ sub: email, email }, JWT_SECRET, { expiresIn: "7d" });

    // Ensure registry
    await redis.sAdd(portalUsersSetKey, email);

    return res.json({ ok: true, token });
  } catch (e) {
    console.error("POST /auth/verify-code failed:", e);
    return res.status(503).json({ error: "otp_unavailable" });
  }
});

// ============================================================================
// PORTAL (JWT)
// ============================================================================

// Portal user memory lives in its own namespace: portal:<email>
function portalUserId(email) {
  return `portal:${email}`;
}

app.get("/portal/me", requireJwt, async (req, res) => {
  try {
    const userId = portalUserId(req.portalEmail);
    const full = await readUserMap(userId);

    const out = {};
    for (const k of COACH_ALLOWED_KEYS) {
      if (k in full) out[k] = full[k];
    }

    return res.json({ user_id: userId, email: req.portalEmail, data: out });
  } catch (e) {
    console.error("GET /portal/me failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

app.post("/portal/register", requireJwt, async (req, res) => {
  try {
    const userId = portalUserId(req.portalEmail);
    const full = await readUserMap(userId);

    const already = COACH_ALLOWED_KEYS.some((k) => k in full);
    if (already) return res.json({ status: "ok", initialized: true });

    const initial = req.body && typeof req.body === "object" ? req.body : {};

    const defaults = {
      client_meta: initial.client_meta || { email: req.portalEmail },
      training_profile: initial.training_profile || {},
      program_current: initial.program_current || null,
      program_history: initial.program_history || [],
      checkin_history: initial.checkin_history || [],
      last_checkin: initial.last_checkin || null,
      notes: initial.notes || [],
    };

    await writeUserKeys(userId, defaults, "portal_register");
    await ensureRedis();
    await redis.sAdd(portalUsersSetKey, req.portalEmail);

    return res.json({ status: "ok", initialized: true });
  } catch (e) {
    console.error("POST /portal/register failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

app.patch("/portal/me", requireJwt, async (req, res) => {
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

    const userId = portalUserId(req.portalEmail);
    await writeUserKeys(userId, filtered, "portal_patch");

    return res.json({ status: "ok", updated: Object.keys(filtered) });
  } catch (e) {
    console.error("PATCH /portal/me failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
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

    return res.json({ timezone: tz, date, weekday, now_iso: nowIso() });
  } catch (e) {
    console.error("GET /me/today failed:", e);
    return res.status(400).json({ error: "invalid_timezone_or_request" });
  }
});

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

// Admin endpoint to list portal users (emails) for Jarvas
app.get("/admin/portal-users", requireApiKey, async (req, res) => {
  if (req.apiRole !== "admin") return res.status(403).json({ error: "admin_only" });

  try {
    await ensureRedis();
    const emails = await redis.sMembers(portalUsersSetKey);
    emails.sort();
    return res.json({ items: emails.map((email) => ({ email, user_id: portalUserId(email) })) });
  } catch (e) {
    console.error("GET /admin/portal-users failed:", e);
    return res.status(503).json({ error: "memory_store_unavailable" });
  }
});

// -------------------------
// START
// -------------------------
const listenPort = parseInt(String(PORT || 10000), 10);
app.listen(listenPort, () => {
  console.log(`✅ jarvas-memory-api listening on :${listenPort} (${BUILD_TAG})`);
});
