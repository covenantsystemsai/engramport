// Unit checks for the per-request caller key: header parsing and the
// fail-closed rule that hosted mode never falls back to the server's own key.
import { test } from "node:test";
import assert from "node:assert/strict";

import { backendKey, keyFromHeaders, runAsCaller, setCallerRequired } from "../src/caller.ts";

test("keyFromHeaders reads Bearer first, then X-API-Key, and rejects junk", () => {
  assert.equal(keyFromHeaders({ authorization: "Bearer ek_a" }), "ek_a");
  assert.equal(keyFromHeaders({ authorization: "bearer ek_a" }), "ek_a");
  assert.equal(keyFromHeaders({ "x-api-key": "ek_b" }), "ek_b");
  assert.equal(keyFromHeaders({ authorization: "Bearer ek_a", "x-api-key": "ek_b" }), "ek_a");
  assert.equal(keyFromHeaders({}), undefined);
  assert.equal(keyFromHeaders({ authorization: "Basic abc" }), undefined);
  assert.equal(keyFromHeaders({ authorization: "Bearer a b" }), undefined);
  assert.equal(keyFromHeaders({ authorization: `Bearer ${"x".repeat(513)}` }), undefined);
  // A bad Authorization header is not rescued by an X-API-Key.
  assert.equal(keyFromHeaders({ authorization: "Basic abc", "x-api-key": "ek_b" }), undefined);
});

test("backendKey uses the caller's key and fails closed when a caller is required", () => {
  setCallerRequired(false);
  assert.equal(backendKey("ek_server"), "ek_server");
  assert.equal(runAsCaller({ apiKey: "ek_caller" }, () => backendKey("ek_server")), "ek_caller");

  setCallerRequired(true);
  try {
    assert.throws(() => backendKey("ek_server"), /No authenticated caller/);
    assert.equal(runAsCaller({ apiKey: "ek_caller" }, () => backendKey("ek_server")), "ek_caller");
  } finally {
    setCallerRequired(false);
  }
});
