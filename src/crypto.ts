import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";

export interface KdfParams {
  N: number;
  r: number;
  p: number;
}

export const DEFAULT_KDF: KdfParams = { N: 2 ** 17, r: 8, p: 1 };

const IV_LEN = 12;
const TAG_LEN = 16;

/** Derive a 256-bit key-encryption key from the master password (scrypt). */
export function deriveKey(password: string, salt: Buffer, params: KdfParams): Buffer {
  return scryptSync(password.normalize("NFKC"), salt, 32, {
    ...params,
    maxmem: 256 * 1024 * 1024,
  });
}

export function randomKey(): Buffer {
  return randomBytes(32);
}

/** AES-256-GCM. Output layout: iv(12) | tag(16) | ciphertext. `aad` binds the blob to its owner. */
export function encrypt(key: Buffer, plaintext: Buffer, aad: string): Buffer {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

export function decrypt(key: Buffer, blob: Buffer, aad: string): Buffer {
  if (blob.length < IV_LEN + TAG_LEN) throw new Error("ciphertext too short");
  const iv = blob.subarray(0, IV_LEN);
  const tag = blob.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ct = blob.subarray(IV_LEN + TAG_LEN);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}
