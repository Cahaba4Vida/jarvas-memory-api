// index.js - Jarvas Redis-backed memory API (persistent, JSON-safe)

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { createClient } = require("redis");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(cors());

const PORT = process.env.PORT || 3000;

// --- Security ---
const API_KEY = process.env.MEMORY_API_KEY;
if (!API_KEY) {
  console.error("❌ MEMORY_API_KEY is missing. Refusing to start.");
  process.exit(1);
}

function checkApiKey(req, res, next) {
  const headerKey = req.headers["x-api-key"];
  if (headerKey !== API_KEY) return res.status(401).json({ error: "invalid api key" });
  next();
}

// --- Redis ---
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

// JSON helpers (so arrays/objects survive)
function encodeValue(v) {
  // store EVERYTHING as JSON so round-trips keep types
  return JSON.stringify(v === undefined ? null : v);
}

function decodeValue(s) {
  if (s == null) return null;
  try {
    return JSON.parse(s);
  } catch {
    // fallback for older values that weren't JSON-stringified
    return s;
  }
}

// Health (no auth)
app.get("/healthz", async (req, res) => {
  try {
    const pong = await redis.ping();
    res.json({ ok: true, redis: pong });
  } catch (e) {
    res.status(503).json({ ok: false, error: "redis unavailable" });
  }
});

// GET /get_memory?user_id=zach
app.get("/get_memory", checkApiKey, async (req, res) => {
  const userId = req.query.user_id || "zach";
  try {
    const hash = await redis.hGetAll(userHashKey(userId)); // { field: string, ... }
    const memories = Object.entries(hash).map(([key, raw]) => ({
      key,
      value: decodeValue(raw),
    }));
    res.json({ user_id: userId, memories });
  } catch (e) {
    console.error("get_memory failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// POST /save_memory  { user_id, key, value }
app.post("/save_memory", checkApiKey, async (req, res) => {
  const { user_id = "zach", key, value } = req.body || {};
  if (!key) return res.status(400).json({ error: "key is required" });

  try {
    await redis.hSet(userHashKey(user_id), key, encodeValue(value));
    res.json({ status: "ok" });
  } catch (e) {
    console.error("save_memory failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// POST /delete_memory  { user_id, key }
app.post("/delete_memory", checkApiKey, async (req, res) => {
  const { user_id = "zach", key } = req.body || {};
  if (!key) return res.status(400).json({ error: "key is required" });

  try {
    await redis.hDel(userHashKey(user_id), key);
    res.json({ status: "ok" });
  } catch (e) {
    console.error("delete_memory failed:", e);
    res.status(503).json({ error: "memory store unavailable" });
  }
});

// Start
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
