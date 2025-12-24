const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const {
  createUser,
  findUserByIdentifier,
  findUserById,
  updateUser,
  createResetToken,
  findValidResetTokenByHash,
  markTokenUsed
} = require("../db/fileDb");

const { generateTotpSecret, verifyTotp } = require("./totp");
const { createAccessToken, createChallengeToken, decodeToken } = require("./jwtManager");
// Audit logging (blockchain ledger)
let logEvent;
try {
  ({ logEvent } = require("../vault/ledger/blockchain"));
} catch (_) {
  logEvent = () => {};
}

const router = express.Router();

// Helpers
function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

router.post("/register", (req, res) => {
  try {
    const { method, emailOrPhone, password } = req.body || {};
    if (!method || !emailOrPhone || !password) {
      return res.status(400).json({ detail: "method, emailOrPhone and password are required" });
    }
    const normalizedMethod = String(method).toLowerCase();
    if (!["email", "phone"].includes(normalizedMethod)) {
      return res.status(400).json({ detail: "Invalid method" });
    }
    if (findUserByIdentifier(emailOrPhone)) {
      return res.status(400).json({ detail: "User already exists" });
    }
    const passwordHash = bcrypt.hashSync(password, 10);
    const totpSecret = generateTotpSecret(); // includes base32 + otpauth_url
    const user = createUser({
      method: normalizedMethod,
      identifier: emailOrPhone,
      passwordHash,
      totpSecret: totpSecret.base32
    });
    logEvent({
      type: "AUTH_REGISTER",
      user_id: user.id,
      method: user.method,
      success: true
    });
    return res.json({
      id: user.id,
      method: user.method,
      identifier: user.identifier,
      totpSecret: totpSecret.base32,
      otpauth_url: totpSecret.otpauth_url
    });
  } catch (e) {
    console.error(e);
    logEvent({ type: "AUTH_REGISTER", success: false, error: String(e.message || e) });
    return res.status(500).json({ detail: "Server error" });
  }
});

router.post("/login/start", (req, res) => {
  try {
    const { method, emailOrPhone, password } = req.body || {};
    if (!method || !emailOrPhone || !password) {
      return res.status(400).json({ detail: "method, emailOrPhone and password are required" });
    }
    const normalizedMethod = String(method).toLowerCase();
    const user = findUserByIdentifier(emailOrPhone);
    if (!user || user.method !== normalizedMethod) {
      logEvent({ type: "AUTH_LOGIN_START", success: false, reason: "user_not_found_or_method" });
      return res.status(401).json({ detail: "Invalid credentials" });
    }
    const ok = bcrypt.compareSync(password, user.passwordHash);
    if (!ok) {
      logEvent({ type: "AUTH_LOGIN_START", user_id: user.id, success: false, reason: "bad_password" });
      return res.status(401).json({ detail: "Invalid credentials" });
    }
    const challenge_token = createChallengeToken(user.id);
    logEvent({ type: "AUTH_LOGIN_START", user_id: user.id, success: true });
    return res.json({ challenge_token });
  } catch (e) {
    console.error(e);
    logEvent({ type: "AUTH_LOGIN_START", success: false, error: String(e.message || e) });
    return res.status(500).json({ detail: "Server error" });
  }
});

router.post("/login/verify", (req, res) => {
  try {
    const { challenge_token, totp_code } = req.body || {};
    if (!challenge_token || !totp_code) {
      return res.status(400).json({ detail: "challenge_token and totp_code are required" });
    }
    let data;
    try {
      data = decodeToken(challenge_token);
    } catch (e) {
      logEvent({ type: "AUTH_LOGIN_VERIFY", success: false, reason: "bad_challenge_token" });
      return res.status(401).json({ detail: "Invalid challenge token" });
    }
    if (data.type !== "login_challenge") {
      logEvent({ type: "AUTH_LOGIN_VERIFY", success: false, reason: "bad_token_type" });
      return res.status(401).json({ detail: "Invalid token type" });
    }
    const userId = parseInt(data.sub, 10);
    const user = findUserById(userId);
    if (!user) {
      logEvent({ type: "AUTH_LOGIN_VERIFY", success: false, reason: "user_not_found" });
      return res.status(401).json({ detail: "User not found" });
    }
    const totpOk = verifyTotp(user.totpSecret, String(totp_code));
    if (!totpOk) {
      logEvent({ type: "AUTH_LOGIN_VERIFY", user_id: user.id, success: false, reason: "bad_totp" });
      return res.status(401).json({ detail: "Invalid TOTP code" });
    }
    const access_token = createAccessToken(user.id, user.identifier);
    logEvent({ type: "AUTH_LOGIN_VERIFY", user_id: user.id, success: true });
    return res.json({ access_token, token_type: "bearer" });
  } catch (e) {
    console.error(e);
    logEvent({ type: "AUTH_LOGIN_VERIFY", success: false, error: String(e.message || e) });
    return res.status(500).json({ detail: "Server error" });
  }
});

// Middleware to get current user
function authMiddleware(req, res, next) {
  const header = req.headers["authorization"] || "";
  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({ detail: "Missing token" });
  }
  const token = header.slice("Bearer ".length);
  let data;
  try {
    data = decodeToken(token);
  } catch (e) {
    return res.status(401).json({ detail: "Invalid token" });
  }
  if (data.type !== "access") {
    return res.status(401).json({ detail: "Invalid token type" });
  }
  const userId = parseInt(data.sub, 10);
  const user = findUserById(userId);
  if (!user) {
    return res.status(401).json({ detail: "User not found" });
  }
  req.user = user;
  next();
}

router.get("/me", authMiddleware, (req, res) => {
  const user = req.user;
  return res.json({
    id: user.id,
    method: user.method,
    identifier: user.identifier
  });
});

router.post("/reset/request", (req, res) => {
  try {
    const { emailOrPhone } = req.body || {};
    if (!emailOrPhone) {
      return res.status(400).json({ detail: "emailOrPhone is required" });
    }
    const user = findUserByIdentifier(emailOrPhone);
    if (!user) {
      // do not leak existence
      return res.json({ message: "If account exists, a reset link was sent." });
    }
    const rawToken = crypto.randomBytes(32);
    const tokenHex = rawToken.toString("hex");
    const tokenHash = sha256Hex(rawToken);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    createResetToken({ userId: user.id, tokenHash, expiresAt });
    // For demo: return token directly
    return res.json({ reset_token: tokenHex });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ detail: "Server error" });
  }
});

router.post("/reset/confirm", (req, res) => {
  try {
    const { token, new_password } = req.body || {};
    if (!token || !new_password) {
      return res.status(400).json({ detail: "token and new_password are required" });
    }
    let raw;
    try {
      raw = Buffer.from(token, "hex");
    } catch (e) {
      return res.status(400).json({ detail: "Invalid token format" });
    }
    const tokenHash = sha256Hex(raw);
    const reset = findValidResetTokenByHash(tokenHash);
    if (!reset) {
      return res.status(400).json({ detail: "Invalid or expired token" });
    }
    const user = findUserById(reset.userId);
    if (!user) {
      return res.status(400).json({ detail: "User not found" });
    }
    user.passwordHash = bcrypt.hashSync(new_password, 10);
    updateUser(user);
    markTokenUsed(reset.id);
    return res.json({ message: "Password updated successfully" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ detail: "Server error" });
  }
});

module.exports = router;
