// index.js - Jarvas file-based memory API

require("dotenv").config();
const express = require("express");
const fs = require("fs");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// Where we store long-term memory
const MEMORY_FILE = "./memory.json";

// Load memory from disk
function loadMemory() {
  try {
    if (!fs.existsSync(MEMORY_FILE)) {
      return {};
    }
    const text = fs.readFileSync(MEMORY_FILE, "utf8");
    if (!text.trim()) return {};
    return JSON.parse(text);
  } catch (err) {
    console.error("Error loading memory:", err);
    return {};
  }
}

// Save memory to disk
function saveMemory(data) {
  try {
    fs.writeFileSync(MEMORY_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error("Error saving memory:", err);
  }
}

// Simple API key protection
const API_KEY = process.env.MEMORY_API_KEY || "supersecret";

function checkApiKey(req, res, next) {
  const headerKey = req.headers["x-api-key"];
  if (headerKey !== API_KEY) {
    return res.status(401).json({ error: "invalid api key" });
  }
  next();
}

// GET /get_memory?user_id=zach
app.get("/get_memory", checkApiKey, (req, res) => {
  const userId = req.query.user_id || "zach";

  const store = loadMemory();
  const userMem = store[userId] || {};

  const memories = Object.entries(userMem).map(([key, value]) => ({
    key,
    value,
  }));

  res.json({ user_id: userId, memories });
});

// POST /save_memory  { user_id, key, value }
app.post("/save_memory", checkApiKey, (req, res) => {
  const { user_id = "zach", key, value } = req.body;

  if (!key) {
    return res.status(400).json({ error: "key is required" });
  }

  const store = loadMemory();
  if (!store[user_id]) {
    store[user_id] = {};
  }

  store[user_id][key] = value;
  saveMemory(store);

  res.json({ status: "ok" });
});

// POST /delete_memory  { user_id, key }
app.post("/delete_memory", checkApiKey, (req, res) => {
  const { user_id = "zach", key } = req.body;

  if (!key) {
    return res.status(400).json({ error: "key is required" });
  }

  const store = loadMemory();

  if (!store[user_id]) {
    return res.json({ status: "ok", message: "no memory for user" });
  }

  delete store[user_id][key];

  // If user has no more keys, remove the user entirely
  if (Object.keys(store[user_id]).length === 0) {
    delete store[user_id];
  }

  saveMemory(store);
  res.json({ status: "ok" });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Jarvas Memory API running on port ${PORT}`);
});
