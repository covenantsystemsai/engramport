/**
 * EngramPort config smoke tests — the first tests for this package (2.2.0).
 *
 * Guards the 2.1.0 onboarding bug: the README + dashboard tell users to set
 * ENGRAMPORT_API_KEY, but the code only read EIDETIC_API_KEY, so a by-the-book
 * setup silently produced an empty key and every request failed. resolveConfig()
 * must read ENGRAMPORT_* primary with EIDETIC_* as a legacy fallback.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveConfig } from "../src/config.ts";

const env = (o: Record<string, string>) => o as unknown as NodeJS.ProcessEnv;

test("ENGRAMPORT_API_KEY is the primary key var (the onboarding fix)", () => {
  assert.equal(resolveConfig(env({ ENGRAMPORT_API_KEY: "ek_primary" })).apiKey, "ek_primary");
});

test("EIDETIC_API_KEY still works as a legacy fallback", () => {
  assert.equal(resolveConfig(env({ EIDETIC_API_KEY: "ek_legacy" })).apiKey, "ek_legacy");
});

test("ENGRAMPORT_API_KEY wins when both are set", () => {
  assert.equal(
    resolveConfig(env({ ENGRAMPORT_API_KEY: "primary", EIDETIC_API_KEY: "legacy" })).apiKey,
    "primary",
  );
});

test("apiUrl: ENGRAMPORT_API_URL primary, EIDETIC_API_URL fallback, localhost default", () => {
  assert.equal(resolveConfig(env({ ENGRAMPORT_API_URL: "https://primary" })).apiUrl, "https://primary");
  assert.equal(resolveConfig(env({ EIDETIC_API_URL: "https://legacy" })).apiUrl, "https://legacy");
  assert.equal(resolveConfig(env({})).apiUrl, "http://localhost:8000");
});

test("namespace: ENGRAMPORT_NAMESPACE primary, EIDETIC_NAMESPACE fallback, 'default' default", () => {
  assert.equal(resolveConfig(env({ ENGRAMPORT_NAMESPACE: "brain-a" })).namespace, "brain-a");
  assert.equal(resolveConfig(env({ EIDETIC_NAMESPACE: "brain-b" })).namespace, "brain-b");
  assert.equal(resolveConfig(env({})).namespace, "default");
});
