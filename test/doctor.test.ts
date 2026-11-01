// `engramport doctor` reports settings without printing the key and checks /health.
import { test } from "node:test";
import assert from "node:assert/strict";

import { resolveConfig } from "../src/config.ts";
import { keyPreview, runDoctor } from "../src/doctor.ts";

const env = (o: Record<string, string>) => o as unknown as NodeJS.ProcessEnv;
const KEY = "ek_live_abcdefghijklmnopqrstuvwxyz0123456789";

const okFetch = (async () => new Response("{}", { status: 200 })) as typeof fetch;
const downFetch = (async () => {
  throw new Error("ECONNREFUSED");
}) as typeof fetch;

test("doctor never prints the key", async () => {
  const lines: string[] = [];
  const cfg = resolveConfig(env({ ENGRAMPORT_MODE: "stdio", ENGRAMPORT_API_URL: "https://api.example.com", ENGRAMPORT_API_KEY: KEY }));
  const code = await runDoctor(cfg, (l) => lines.push(l), okFetch);
  assert.equal(code, 0);
  const text = lines.join("\n");
  assert.ok(!text.includes(KEY.slice(7)), "no more than a short prefix of the key is printed");
  assert.match(text, /health:\s+200 ok/);
});

test("doctor exits 1 and names the problem when the URL is missing", async () => {
  const lines: string[] = [];
  const code = await runDoctor(resolveConfig(env({ ENGRAMPORT_MODE: "stdio" })), (l) => lines.push(l), okFetch);
  assert.equal(code, 1);
  assert.match(lines.join("\n"), /ENGRAMPORT_API_URL is not set/);
});

test("doctor exits 1 when the API is unreachable", async () => {
  const lines: string[] = [];
  const cfg = resolveConfig(env({ ENGRAMPORT_MODE: "stdio", ENGRAMPORT_API_URL: "https://api.example.com", ENGRAMPORT_API_KEY: KEY }));
  assert.equal(await runDoctor(cfg, (l) => lines.push(l), downFetch), 1);
  assert.match(lines.join("\n"), /unreachable/);
});

test("keyPreview shows at most a third of a short key", () => {
  assert.equal(keyPreview(""), "(not set)");
  assert.equal(keyPreview("abcdef"), "ab… (6 chars)");
  assert.ok(keyPreview(KEY).startsWith("ek_live… "));
});
