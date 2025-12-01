// index.js - Jarvas Redis-backed memory API
// Persistent (Redis), JSON-safe, bot-forgiving, wipe-resistant,
// PLUS role-based access control (Admin vs Coach) so clients can't read Zach's memory.

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { createClient } = require("redis");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(cors());

const PORT = process.env.PORT || 3000;

// =====================
// Security / Auth (Admin vs Coach keys)
// =====================
const ADMIN_KEY = process.env.MEMORY_API_KEY_ADMIN;
const COACH_KEY = process.env.MEMORY_API_KEY_COACH;

if (!ADMIN_KEY || !COACH_KEY) {
  console.error("❌ MEMORY_API_KEY_ADMIN or MEMORY_API_KEY_COACH missing. Refusing to start.");
  process.exit(1);
}

function checkApiKey(req, res, next) {
  const headerKey = req.headers["x-api-key"];
  if (headerKey === ADMIN_KEY) req.role = "admin";
  else if (headerKey === COACH_KEY) req.role = "coach";
  else return res.status(401).json({ error: "invalid api key" });
  next();
}

// Coach key restrictions:
// - cannot access user_id "zach"
// - must use user_id that starts with "client:"
// - cannot access admin-only keys (even inside client namespace)
const ADMIN_ONLY_KEYS = new Set(["training_clients"]);

function assertAllowed(req, userId, keyOrNull) {
  if (req.role === "admin") return;

  const uid = String(userId || "");
  if (uid === "zach") {
    throw new Error("forbidden: coach key cannot access zach");
  }
  if (!uid.startsWith("client:")) {
    throw new Error('forbidden: coach user_id must start with "client:"');
  }

  if (keyOrNull != null) {
    const k = String(keyOrNull);
    if (ADMIN_ONLY_KEYS.has(k)) {
      throw new Error(`forbidden: key "${k}" is admin-only`);
    }
  }
}

// =====================
// Redis
// =====================
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

function userHashKey(userId) {
  return `jarvas:${userId || "zach"}`; // one hash per user
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

// =====================
// JSON helpers
// =====================
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

function decodeValue(s) {
  if (s == null) return null;
  try {
    const parsed = JSON.parse(s);
    return maybeParseJsonString(parsed);
  } catch {
    return maybeParseJsonString(s);
  }
}

// =====================
// Wipe-proof guardrails
// =====================
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

async function pushHistoryIfExists(userId, key) {
  const hashKey = userHashKey(userId);
  const prevRaw = await redis.hGet(hashKey, key);
  if (prevRaw == null) return;

  const entry = JSON.stringify({
    ts: new Date().toISOString(),
    prev_raw: prevRaw, // raw stored string
  });

  const histKey = historyListKey(userId, key);
  await redis.lPush(histKey, entry);
  await redis.lTrim(histKey, 0, 49);              // keep last 50
  await redis.expire(histKey, 60 * 60 * 24 * 30); // 30 days
}

function isForbiddenError(e) {
  return String(e?.message || "").startsWith("forbidden:");
}

// =====================
// Health (no auth) - OK to keep public
// =====================
app.get("/healthz", async (req, res) => {
  try {
    const pong = await redis.ping();
    res.json({ ok: true, redis: pong });
  } catch {
    res.status(503).json({ ok: false, error: "redis unavailable" });
  }
});

// =====================
// GET /get_memory?user_id=...&format=list|map
// =====================
app.get("/get_memory", checkApiKey, async (req, res) => {
  const userId = req.query.user_id || "zach";
  const format = String(req.query.format || "list").toLowerCase(); // list | map

  try {
    assertAllowed(req, userId, null);

    const hash = await redis.hGetAll(userHashKey(userId));

    const data = {};
    const memories = [];

    for (const [key, raw] of Object.entries(hash)) {
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

// =====================
// POST /save_memory?force=true|false
// Body: { user_id, key, value }
// =====================
app.post("/save_memory", checkApiKey, async (req, res) => {
  const { user_id = "zach", key, value } = req.body || {};
  if (!key) return res.status(400).json({ error: "key is required" });

  const force = String(req.query.force || "false").toLowerCase() === "true";

  try {
    assertAllowed(req, user_id, key);

    const normalized = maybeParseJsonString(value);

    if (PROTECTED_KEYS.has(String(key)) && isEmptyValue(normalized) && !force) {
      return res.status(400).json({
        error: `Refusing empty overwrite for protected key "${key}". Use ?force=true if intentional.`,
      });
    }

    await pushHistoryIfExists(user_id, key);
    await redis.hSet(userHashKey(user_id), key, encodeValue(normalized));

    res.json({ status: "ok" });
  } catch (e) {
    if (isForbiddenError(e)) return res.status(403).json({ error: e.message });
    console.error("save_memory failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// =====================
// POST /delete_memory
// Body: { user_id, key }
// Soft-deletes to trash (30 days), records history
// =====================
app.post("/delete_memory", checkApiKey, async (req, res) => {
  const { user_id = "zach", key } = req.body || {};
  if (!key) return res.status(400).json({ error: "key is required" });

  try {
    assertAllowed(req, user_id, key);

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
    if (isForbiddenError(e)) return res.status(403).json({ error: e.message });
    console.error("delete_memory failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// =====================
// POST /restore_memory
// Body: { user_id, key }
// =====================
app.post("/restore_memory", checkApiKey, async (req, res) => {
  const { user_id = "zach", key } = req.body || {};
  if (!key) return res.status(400).json({ error: "key is required" });

  try {
    assertAllowed(req, user_id, key);

    const raw = await redis.hGet(trashHashKey(user_id), key);
    if (raw == null) return res.status(404).json({ error: "no trash entry for key" });

    await pushHistoryIfExists(user_id, key);
    await redis.hSet(userHashKey(user_id), key, raw);

    await redis.hDel(trashHashKey(user_id), key);
    await redis.hDel(trashMetaKey(user_id), key);

    res.json({ status: "ok", restored: true });
  } catch (e) {
    if (isForbiddenError(e)) return res.status(403).json({ error: e.message });
    console.error("restore_memory failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// =====================
// GET /history?user_id=...&key=...&limit=...
// =====================
app.get("/history", checkApiKey, async (req, res) => {
  const userId = req.query.user_id || "zach";
  const key = req.query.key;
  const limit = Math.min(Number(req.query.limit || 10) || 10, 50);

  if (!key) return res.status(400).json({ error: "key is required" });

  try {
    assertAllowed(req, userId, key);

    const entries = await redis.lRange(historyListKey(userId, key), 0, limit - 1);
    res.json({ status: "ok", user_id: userId, key, entries: entries.map((s) => JSON.parse(s)) });
  } catch (e) {
    if (isForbiddenError(e)) return res.status(403).json({ error: e.message });
    console.error("history failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// =====================
// Start
// =====================
(async () => {
  try {
    await redis.connect();
    console.log("✅ Connected to Redis");
    app.listen(PORT, () => console.log(`Jarvas Memory API running on port ${PORT}`));
  } catch (e) {
    console.error("❌ Failed to connect to Redis. Refusing to start.", e);
    process.exit(1);
  }
})();
