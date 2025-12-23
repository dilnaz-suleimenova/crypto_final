const crypto = require("crypto");

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest();
}

function sha256Hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

module.exports = { sha256, sha256Hex };
