const fs = require("fs");
const path = require("path");
const { DATA_DIR } = require("../config");
const { randomUUID } = require("crypto");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const USERS_FILE = path.join(DATA_DIR, "users.json");
const TOKENS_FILE = path.join(DATA_DIR, "reset_tokens.json");

function readJson(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const raw = fs.readFileSync(file, "utf8");
    if (!raw.trim()) return fallback;
    return JSON.parse(raw);
  } catch (e) {
    console.error("Failed to read", file, e);
    return fallback;
  }
}

function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
}

function loadUsers() {
  return readJson(USERS_FILE, []);
}

function saveUsers(users) {
  writeJson(USERS_FILE, users);
}

function loadTokens() {
  return readJson(TOKENS_FILE, []);
}

function saveTokens(tokens) {
  writeJson(TOKENS_FILE, tokens);
}

// User operations
function findUserByIdentifier(identifier) {
  const users = loadUsers();
  return users.find(u => u.identifier === identifier) || null;
}

function findUserById(id) {
  const users = loadUsers();
  return users.find(u => u.id === id) || null;
}

function createUser({ method, identifier, passwordHash, totpSecret }) {
  const users = loadUsers();
  if (users.find(u => u.identifier === identifier)) {
    throw new Error("User already exists");
  }
  const id = users.length ? Math.max(...users.map(u => u.id)) + 1 : 1;
  const user = {
    id,
    method,
    identifier,
    passwordHash,
    totpSecret,
    isActive: true
  };
  users.push(user);
  saveUsers(users);
  return user;
}

function updateUser(user) {
  const users = loadUsers();
  const idx = users.findIndex(u => u.id === user.id);
  if (idx === -1) throw new Error("User not found");
  users[idx] = user;
  saveUsers(users);
}

// Reset token operations
function createResetToken({ userId, tokenHash, expiresAt }) {
  const tokens = loadTokens();
  const token = {
    id: tokens.length ? Math.max(...tokens.map(t => t.id)) + 1 : 1,
    userId,
    tokenHash,
    expiresAt: expiresAt.toISOString(),
    used: false
  };
  tokens.push(token);
  saveTokens(tokens);
  return token;
}

function findValidResetTokenByHash(tokenHash) {
  const tokens = loadTokens();
  const now = new Date();
  return tokens.find(t => t.tokenHash === tokenHash && !t.used && new Date(t.expiresAt) > now) || null;
}

function markTokenUsed(tokenId) {
  const tokens = loadTokens();
  const idx = tokens.findIndex(t => t.id === tokenId);
  if (idx === -1) return;
  tokens[idx].used = true;
  saveTokens(tokens);
}

module.exports = {
  loadUsers,
  saveUsers,
  createUser,
  findUserByIdentifier,
  findUserById,
  updateUser,
  createResetToken,
  findValidResetTokenByHash,
  markTokenUsed
};
