const path = require("path");

const ROOT_DIR = path.resolve(__dirname, "..");

module.exports = {
  ROOT_DIR,
  PORT: 8000,
  FRONTEND_ORIGIN: "http://localhost:3000",
  ACCESS_TOKEN_EXPIRE_MINUTES: 30,
  CHALLENGE_EXPIRE_MINUTES: 5,
  DATA_DIR: path.join(ROOT_DIR, "data"),
  KEYS_DIR: path.join(ROOT_DIR, "keys"),
  RSA_PRIVATE_KEY_PATH: path.join(ROOT_DIR, "keys", "rsa_private.pem"),
  RSA_PUBLIC_KEY_PATH: path.join(ROOT_DIR, "keys", "rsa_public.pem")
};
