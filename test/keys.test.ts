import { test } from "node:test";
import assert from "node:assert/strict";
import { decodePepper, hashKey, mintKey, parseKey } from "../src/keys.ts";

test("minted keys parse back to their prefix", () => {
  const k = mintKey();
  assert.match(k.prefix, /^ep_live_[A-Za-z0-9]{12}$/);
  assert.match(k.key, /^ep_live_[A-Za-z0-9]{12}\.[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(parseKey(k.key), k);
  assert.notEqual(mintKey().key, k.key);
});

test("the prefix fits the schema's prefix rule", () => {
  assert.match(mintKey().prefix, /^[A-Za-z0-9_]{8,32}$/);
});

test("malformed keys are refused", () => {
  for (const bad of ["", "ek_old_style_key", "ep_live_short.x", `ep_live_${"a".repeat(12)}`, `${mintKey().key} `]) {
    assert.equal(parseKey(bad), undefined, bad);
  }
});

test("hashes depend on the pepper and the whole key", () => {
  const k = mintKey();
  const p1 = Buffer.alloc(32, 1);
  const p2 = Buffer.alloc(32, 2);
  assert.equal(hashKey(k.key, p1).length, 32);
  assert.notDeepEqual(hashKey(k.key, p1), hashKey(k.key, p2));
  // Change the last character to one it is not, so the two keys always differ.
  const other = k.key.slice(0, -1) + (k.key.endsWith("A") ? "B" : "A");
  assert.notEqual(other, k.key);
  assert.notDeepEqual(hashKey(k.key, p1), hashKey(other, p1));
});

test("the pepper must be at least 32 bytes, as base64 or hex", () => {
  assert.equal(decodePepper(""), undefined);
  assert.equal(decodePepper(Buffer.alloc(16, 7).toString("base64")), undefined);
  assert.equal(decodePepper(Buffer.alloc(32, 7).toString("base64"))?.length, 32);
  assert.equal(decodePepper("ab".repeat(32))?.length, 32);
});
