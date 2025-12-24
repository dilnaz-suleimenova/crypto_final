const fs = require("fs");
const path = require("path");

const DATA_DIR = path.join(__dirname, "..", "..", "data");
const BLOBS_DIR = path.join(DATA_DIR, "file_blobs");
const FILES_PATH = path.join(DATA_DIR, "files.json");

function ensure() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(BLOBS_DIR)) fs.mkdirSync(BLOBS_DIR, { recursive: true });
  if (!fs.existsSync(FILES_PATH)) {
    fs.writeFileSync(FILES_PATH, JSON.stringify({ next_id: 1, files: [] }, null, 2));
  }
}

function readFilesDb() {
  ensure();
  return JSON.parse(fs.readFileSync(FILES_PATH, "utf8"));
}

function writeFilesDb(data) {
  ensure();
  fs.writeFileSync(FILES_PATH, JSON.stringify(data, null, 2));
}

function blobPath(fileId) {
  ensure();
  return path.join(BLOBS_DIR, `file_${fileId}.bin`);
}

module.exports = { FILES_PATH, BLOBS_DIR, readFilesDb, writeFilesDb, blobPath };
