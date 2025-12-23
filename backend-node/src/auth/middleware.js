const { findUserById } = require("../db/fileDb");
const { decodeToken } = require("./jwtManager");

/**
 * Re-usable auth middleware for protected routes.
 * Keeps existing /api auth routes unchanged.
 */
function requireAuth(req, res, next) {
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

module.exports = { requireAuth };
