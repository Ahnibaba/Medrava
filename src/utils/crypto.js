import crypto from "crypto";

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const IV_LENGTH = parseInt(process.env.IV_LENGTH); // AES block size

export const encryptId = (id) => {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(ENCRYPTION_KEY, "hex"),
    iv
  );
  const encrypted = Buffer.concat([
    cipher.update(id.toString()),
    cipher.final()
  ]);
  return `${iv.toString("hex")}:${encrypted.toString("hex")}`;
};

export const decryptId = (encryptedId) => {
  // Fix: Use encryptedId instead of encryptId
  const [ivHex, encryptedHex] = encryptedId.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const encrypted = Buffer.from(encryptedHex, "hex");
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    Buffer.from(ENCRYPTION_KEY, "hex"),
    iv
  );

  // Fix: Use encrypted instead of encryptId
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);
  return decrypted.toString();
};