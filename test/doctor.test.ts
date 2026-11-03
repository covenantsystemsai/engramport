// `engramport doctor` reports settings without printing the key and checks /health.
import { test } from "node:test";
import assert from "node:assert/strict";

import { resolveConfig } from "../src/config.ts";
import { keyPreview, runDoctor } from "../src/doctor.ts";

const env = (o: Record<string, string>) => o as unknown as NodeJS.ProcessEnv;
// Fake key built at runtime so it is not a key-shaped literal in the source.
const KEY = "ek_live_" + "x".repeat(36);

const okFetch = (async () => new Response("{}", { status: 200 })) as typeof fetch;
const downFetch = (async () => {
  throw new Error("ECONNREFUSED");
}) as typeof fetch;
const noToken = async () => "";

test("doctor never prints the key", async () => {
  const lines: string[] = [];
  const cfg = resolveConfig(env({ ENGRAMPORT_MODE: "stdio", ENGRAMPORT_API_URL: "https://api.example.com", ENGRAMPORT_API_KEY: KEY }));
  const code = await runDoctor(cfg, (l) => lines.push(l), okFetch, noToken);
  assert.equal(code, 0);
  const text = lines.join("\n");
  assert.ok(!text.includes(KEY.slice(7)), "no more than a short prefix of the key is printed");
  assert.match(text, /health:\s+200 ok/);
});

test("doctor exits 1 and names the problem when the URL is missing", async () => {
  const lines: string[] = [];
  const code = await runDoctor(resolveConfig(env({ ENGRAMPORT_MODE: "stdio" })), (l) => lines.push(l), okFetch, noToken);
  assert.equal(code, 1);
  assert.match(lines.join("\n"), /ENGRAMPORT_API_URL is not set/);
});

test("doctor exits 1 when the API is unreachable", async () => {
  const lines: string[] = [];
  const cfg = resolveConfig(env({ ENGRAMPORT_MODE: "stdio", ENGRAMPORT_API_URL: "https://api.example.com", ENGRAMPORT_API_KEY: KEY }));
  assert.equal(await runDoctor(cfg, (l) => lines.push(l), downFetch, noToken), 1);
  assert.match(lines.join("\n"), /unreachable/);
});

test("doctor sends the Cloud Run ID token, like normal tool calls", async () => {
  let sent: string | null = null;
  const gated = (async (_url: string, init?: RequestInit) => {
    sent = new Headers(init?.headers).get("X-Serverless-Authorization");
    return new Response("{}", { status: sent ? 200 : 403 });
  }) as typeof fetch;
  const cfg = resolveConfig(env({ ENGRAMPORT_MODE: "stdio", ENGRAMPORT_API_URL: "https://api.example.com", ENGRAMPORT_API_KEY: KEY }));
  assert.equal(await runDoctor(cfg, () => {}, gated, async () => "tok123"), 0);
  assert.equal(sent, "Bearer tok123");

  const lines: string[] = [];
  assert.equal(await runDoctor(cfg, (l) => lines.push(l), gated, noToken), 1);
  assert.match(lines.join("\n"), /no Cloud Run ID token/);
});

test("keyPreview shows at most a third of a short key", () => {
  assert.equal(keyPreview(""), "(not set)");
  assert.equal(keyPreview("abcdef"), "ab… (6 chars)");
  assert.ok(keyPreview(KEY).startsWith("ek_live… "));
});

test("doctor on the postgres store shows the database user and host, never the password", async () => {
  const lines: string[] = [];
  const secret = "pw" + "z".repeat(20);
  const cfg = resolveConfig(env({
    ENGRAMPORT_MODE: "http",
    ENGRAMPORT_STORE: "postgres",
    ENGRAMPORT_DATABASE_URL: `postgresql://engramport_app:${secret}@db.example.com:5432/postgres`,
    ENGRAMPORT_KEY_PEPPER: Buffer.alloc(32, 3).toString("base64"),
  }));
  let pinged = false;
  const code = await runDoctor(cfg, (l) => lines.push(l), okFetch, noToken, async () => {
    pinged = true;
  });
  assert.equal(code, 0);
  assert.ok(pinged);
  const text = lines.join("\n");
  assert.ok(!text.includes(secret));
  assert.match(text, /engramport_app @ db\.example\.com:5432\/postgres/);
  assert.match(text, /keyword and graph search only/);
});

test("doctor on the postgres store exits 1 when the database is unreachable", async () => {
  const lines: string[] = [];
  const cfg = resolveConfig(env({
    ENGRAMPORT_MODE: "http",
    ENGRAMPORT_STORE: "postgres",
    ENGRAMPORT_DATABASE_URL: "postgresql://engramport_app@db.example.com/postgres",
    ENGRAMPORT_KEY_PEPPER: Buffer.alloc(32, 3).toString("base64"),
  }));
  const code = await runDoctor(cfg, (l) => lines.push(l), okFetch, noToken, async () => {
    throw new Error("timeout");
  });
  assert.equal(code, 1);
  assert.match(lines.join("\n"), /database:\s+unreachable \(timeout\)/);
});
