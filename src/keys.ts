/**
 * EngramPort key format and hashing for the Postgres store.
 *
 * A key looks like `ep_live_<12 id chars>.<43 secret chars>`. The part before
 * the dot is the prefix: it is stored, shown in logs and used to find the key
 * row. The whole key is hashed with HMAC-SHA256 and a server pepper held in the
 * secrets manager, and only that hash is stored, so a copy of the database
 * alone cannot be used to forge or check a key.
 */

import { createHmac, randomBytes } from "node:crypto";

export const KEY_PREFIX = "ep_live_";
const ID_CHARS = 12;
const BASE62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const KEY_PATTERN = /^(ep_live_[A-Za-z0-9]{12})\.([A-Za-z0-9_-]{43})$/;

/** Minimum pepper length in bytes once decoded from its text form. */
export const MIN_PEPPER_BYTES = 32;

export interface ParsedKey {
  /** Stored, logged and used for lookup. Never enough to authenticate. */
  prefix: string;
  /** The full key, for hashing only. */
  key: string;
}

/** Returns undefined for anything that is not a well-formed key. */
export function parseKey(raw: string): ParsedKey | undefined {
  const match = KEY_PATTERN.exec(raw);
  if (!match) return undefined;
  return { prefix: match[1], key: raw };
}

/** HMAC-SHA256 of the whole key under the pepper: the value stored as key_hash. */
export function hashKey(key: string, pepper: Buffer): Buffer {
  return createHmac("sha256", pepper).update(key, "utf8").digest();
}

/**
 * The pepper is configured as base64 or hex text. Anything shorter than
 * MIN_PEPPER_BYTES once decoded is refused.
 */
export function decodePepper(text: string): Buffer | undefined {
  const t = text.trim();
  if (!t) return undefined;
  const buf = /^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0 ? Buffer.from(t, "hex") : Buffer.from(t, "base64");
  return buf.length >= MIN_PEPPER_BYTES ? buf : undefined;
}

/** n random base62 characters, each equally likely. */
export function randomBase62(n: number): string {
  // Rejection sampling keeps every character equally likely.
  let out = "";
  while (out.length < n) {
    for (const b of randomBytes(n * 2)) {
      if (b < 248 && out.length < n) out += BASE62[b % 62];
    }
  }
  return out;
}

/** A fresh key: 12 random id characters and 256 random secret bits. */
export function mintKey(): ParsedKey {
  const prefix = KEY_PREFIX + randomBase62(ID_CHARS);
  const key = `${prefix}.${randomBytes(32).toString("base64url")}`;
  return { prefix, key };
}
