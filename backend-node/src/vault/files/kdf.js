const crypto = require("crypto");

// PBKDF2 parameters (>=100k per rubric); choose 200k for margin.
const PBKDF2_ITERS = 200_000;

function deriveMasterKey(vaultPassword, salt) {
  const pwd = Buffer.from(String(vaultPassword), "utf8");
  return crypto.pbkdf2Sync(pwd, salt, PBKDF2_ITERS, 32, "sha256");
}

module.exports = { PBKDF2_ITERS, deriveMasterKey };
