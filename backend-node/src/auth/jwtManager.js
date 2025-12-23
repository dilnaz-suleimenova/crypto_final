const jwt = require("jsonwebtoken");
const { loadPrivateKey, loadPublicKey, ensureKeypair } = require("../crypto/rsaKeys");
const { ACCESS_TOKEN_EXPIRE_MINUTES, CHALLENGE_EXPIRE_MINUTES } = require("../config");

ensureKeypair();

function signToken(payload, minutes) {
  const privateKey = loadPrivateKey();
  const expSeconds = Math.floor(Date.now() / 1000) + minutes * 60;
  return jwt.sign({ ...payload, exp: expSeconds, iat: Math.floor(Date.now() / 1000) }, privateKey, {
    algorithm: "RS256"
  });
}

function createAccessToken(userId, identifier) {
  return signToken({ sub: String(userId), identifier, type: "access" }, ACCESS_TOKEN_EXPIRE_MINUTES);
}

function createChallengeToken(userId) {
  return signToken({ sub: String(userId), type: "login_challenge" }, CHALLENGE_EXPIRE_MINUTES);
}

function decodeToken(token) {
  const publicKey = loadPublicKey();
  return jwt.verify(token, publicKey, { algorithms: ["RS256"] });
}

module.exports = { createAccessToken, createChallengeToken, decodeToken };
