const speakeasy = require("speakeasy");

function generateTotpSecret() {
  const secret = speakeasy.generateSecret({ length: 20 });
  return {
    ascii: secret.ascii,
    hex: secret.hex,
    base32: secret.base32,
    otpauth_url: secret.otpauth_url
  };
}

function verifyTotp(secretBase32, token) {
  return speakeasy.totp.verify({
    secret: secretBase32,
    encoding: "base32",
    token,
    window: 1
  });
}

module.exports = { generateTotpSecret, verifyTotp };
