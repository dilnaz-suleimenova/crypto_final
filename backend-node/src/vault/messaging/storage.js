const fs = require("fs");
const path = require("path");

const DATA_DIR = path.join(__dirname, "..", "..", "data");
const MSG_PATH = path.join(DATA_DIR, "messages.json");

function ensure() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(MSG_PATH)) {
    fs.writeFileSync(MSG_PATH, JSON.stringify({ next_id: 1, messages: [] }, null, 2));
  }
}

function readMessages() {
  ensure();
  return JSON.parse(fs.readFileSync(MSG_PATH, "utf8"));
}

function writeMessages(data) {
  ensure();
  fs.writeFileSync(MSG_PATH, JSON.stringify(data, null, 2));
}

module.exports = { MSG_PATH, readMessages, writeMessages };
