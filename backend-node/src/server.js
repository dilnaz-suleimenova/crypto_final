const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");

const { PORT, FRONTEND_ORIGIN } = require("./config");
const authRoutes = require("./auth/routes");
const vaultRoutes = require("./vault/routes");

const app = express();

app.use(express.json());
app.use(cors({
  origin: [FRONTEND_ORIGIN, "http://localhost:3000"],
  credentials: true
}));

app.get("/", (req, res) => {
  res.json({ message: "Secure Auth Node.js backend running" });
});

app.use("/api", authRoutes);
app.use("/api/vault", vaultRoutes);

app.listen(PORT, () => {
  console.log(`Secure Auth Node backend listening on http://localhost:${PORT}`);
});
