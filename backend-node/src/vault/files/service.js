const fs = require("fs");
const { readFilesDb, writeFilesDb, blobPath } = require("./storage");
const { encryptFile, decryptFile } = require("./fileCrypto");

function encryptAndStore({ userId, vaultPassword, filename, dataBase64 }) {
  const plaintext = Buffer.from(String(dataBase64), "base64");
  const { meta, ciphertext } = encryptFile({ userId, vaultPassword, filename, plaintext });

  const db = readFilesDb();
  const fileId = db.next_id++;
  const record = { id: fileId, ...meta };
  db.files.push(record);
  writeFilesDb(db);
  fs.writeFileSync(blobPath(fileId), ciphertext);
  return record;
}

function listFiles(userId) {
  const db = readFilesDb();
  return db.files.filter(f => f.user_id === userId).map(f => ({
    id: f.id,
    filename: f.filename,
    created_at: f.created_at,
    ciphertext_sha256_hex: f.ciphertext_sha256_hex
  }));
}

function decryptFromStore({ userId, vaultPassword, fileId }) {
  const db = readFilesDb();
  const meta = db.files.find(f => f.id === Number(fileId));
  if (!meta) throw new Error("File not found");
  if (meta.user_id !== userId) throw new Error("Forbidden");
  const ciphertext = fs.readFileSync(blobPath(fileId));
  const plaintext = decryptFile({ userId, vaultPassword, meta, ciphertext });
  return { meta, plaintext };
}

module.exports = { encryptAndStore, listFiles, decryptFromStore };
