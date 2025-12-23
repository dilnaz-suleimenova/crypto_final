const fs = require("fs");
const path = require("path");

const DATA_DIR = path.join(__dirname, "..", "..", "data");
const LEDGER_PATH = path.join(DATA_DIR, "ledger.json");

function ensureLedgerFile() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(LEDGER_PATH)) {
    fs.writeFileSync(LEDGER_PATH, JSON.stringify({ chain: [], pending: [] }, null, 2));
  }
}

function readLedger() {
  ensureLedgerFile();
  return JSON.parse(fs.readFileSync(LEDGER_PATH, "utf8"));
}

function writeLedger(data) {
  ensureLedgerFile();
  fs.writeFileSync(LEDGER_PATH, JSON.stringify(data, null, 2));
}

module.exports = { LEDGER_PATH, readLedger, writeLedger };
