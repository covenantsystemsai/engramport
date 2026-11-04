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
import { configProblems, resolveConfig } from "../src/config.ts";

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

test("apiUrl: ENGRAMPORT_API_URL primary, EIDETIC_API_URL fallback, no localhost default", () => {
  assert.equal(resolveConfig(env({ ENGRAMPORT_API_URL: "https://primary" })).apiUrl, "https://primary");
  assert.equal(resolveConfig(env({ EIDETIC_API_URL: "https://legacy" })).apiUrl, "https://legacy");
  assert.equal(resolveConfig(env({ ENGRAMPORT_API_URL: "https://primary/" })).apiUrl, "https://primary");
  // The old silent default made every hosted call fail; now there is none.
  assert.equal(resolveConfig(env({})).apiUrl, "");
});

test("configProblems: a missing URL is named, a good one passes", () => {
  assert.match(configProblems(resolveConfig(env({})), "stdio")[0], /ENGRAMPORT_API_URL is not set/);
  assert.deepEqual(configProblems(resolveConfig(env({ ENGRAMPORT_API_URL: "https://api.example.com" })), "http"), []);
  assert.match(configProblems(resolveConfig(env({ ENGRAMPORT_API_URL: "not a url" })), "stdio")[0], /not a valid URL/);
});

test("configProblems: hosted mode refuses a localhost backend unless allowed", () => {
  const local = env({ ENGRAMPORT_API_URL: "http://localhost:8000" });
  assert.equal(configProblems(resolveConfig(local), "stdio").length, 0, "stdio may use a local backend");
  assert.match(configProblems(resolveConfig(local), "http")[0], /points at this machine/);
  assert.equal(
    configProblems(resolveConfig(env({ ENGRAMPORT_API_URL: "http://127.0.0.1:8000", ENGRAMPORT_ALLOW_LOCAL_BACKEND: "true" })), "http").length,
    0,
  );
});

test("configProblems: plain http to a remote host is refused", () => {
  assert.match(
    configProblems(resolveConfig(env({ ENGRAMPORT_API_URL: "http://api.example.com" })), "stdio")[0],
    /must use https/,
  );
});

test("namespace: ENGRAMPORT_NAMESPACE primary, EIDETIC_NAMESPACE fallback, 'default' default", () => {
  assert.equal(resolveConfig(env({ ENGRAMPORT_NAMESPACE: "brain-a" })).namespace, "brain-a");
  assert.equal(resolveConfig(env({ EIDETIC_NAMESPACE: "brain-b" })).namespace, "brain-b");
  assert.equal(resolveConfig(env({})).namespace, "default");
});

const pepper = Buffer.alloc(32, 9).toString("base64");
const pg = (o: Record<string, string>) =>
  resolveConfig(env({ ENGRAMPORT_STORE: "postgres", ENGRAMPORT_KEY_PEPPER: pepper, ...o }));

test("store defaults to eidetic; an unknown store is named", () => {
  assert.equal(resolveConfig(env({})).store, "eidetic");
  assert.match(configProblems(resolveConfig(env({ ENGRAMPORT_STORE: "pinecone" })), "stdio")[0], /eidetic or postgres/);
});

test("postgres store: needs no API URL, but a database URL and a pepper", () => {
  assert.deepEqual(
    configProblems(pg({ ENGRAMPORT_DATABASE_URL: "postgresql://engramport_app@db.example.com:5432/postgres" }), "http"),
    [],
  );
  assert.match(configProblems(pg({}), "http")[0], /ENGRAMPORT_DATABASE_URL is not set/);
  assert.match(
    configProblems(
      resolveConfig(env({ ENGRAMPORT_STORE: "postgres", ENGRAMPORT_DATABASE_URL: "postgresql://engramport_app@db.example.com/postgres" })),
      "http",
    )[0],
    /ENGRAMPORT_KEY_PEPPER/,
  );
});

test("postgres store: refuses admin roles, weak sslmode and a local db when hosted", () => {
  assert.match(configProblems(pg({ ENGRAMPORT_DATABASE_URL: "postgresql://postgres@db.example.com/postgres" }), "http")[0], /engramport_app/);
  assert.match(
    configProblems(pg({ ENGRAMPORT_DATABASE_URL: "postgresql://postgres.abc@pooler.example.com/postgres" }), "http")[0],
    /engramport_app/,
  );
  assert.match(
    configProblems(pg({ ENGRAMPORT_DATABASE_URL: "postgresql://engramport_app@db.example.com/postgres?sslmode=require" }), "http")[0],
    /sslmode/,
  );
  const local = { ENGRAMPORT_DATABASE_URL: "postgresql://engramport_app@localhost:5432/postgres" };
  assert.match(configProblems(pg(local), "http")[0], /points at this machine/);
  assert.equal(configProblems(pg(local), "stdio").length, 0);
});

test("oauth: off by default; when on it needs postgres, http mode, an https public origin and Supabase Auth", () => {
  const db = { ENGRAMPORT_DATABASE_URL: "postgresql://engramport_app@db.example.com:5432/postgres" };
  const on = {
    ...db,
    ENGRAMPORT_OAUTH: "true",
    ENGRAMPORT_PUBLIC_URL: "https://mcp.example.com",
    ENGRAMPORT_SUPABASE_URL: "https://ref.supabase.co",
    ENGRAMPORT_SUPABASE_PUBLISHABLE_KEY: "sb_publishable_test",
  };
  assert.equal(resolveConfig(env({})).oauth, false);
  assert.deepEqual(resolveConfig(env({})).oauthRedirectHosts, ["claude.ai", "claude.com"]);
  assert.deepEqual(configProblems(pg(on), "http"), []);
  assert.match(configProblems(pg(on), "stdio").join(" "), /http mode only/);
  assert.match(configProblems(resolveConfig(env({ ENGRAMPORT_OAUTH: "true", ENGRAMPORT_API_URL: "https://api.example.com" })), "http")[0],
    /needs ENGRAMPORT_STORE=postgres/);
  assert.match(configProblems(pg({ ...on, ENGRAMPORT_PUBLIC_URL: "http://mcp.example.com" }), "http").join(" "), /PUBLIC_URL must use https/);
  assert.match(configProblems(pg({ ...on, ENGRAMPORT_PUBLIC_URL: "https://mcp.example.com/x" }), "http").join(" "), /origin only/);
  assert.match(configProblems(pg({ ...on, ENGRAMPORT_SUPABASE_PUBLISHABLE_KEY: "" }), "http").join(" "), /PUBLISHABLE_KEY is not set/);
  assert.match(configProblems(pg({ ...on, ENGRAMPORT_SUPABASE_URL: "" }), "http").join(" "), /SUPABASE_URL is not set/);
});

test("approval page: off by default; when on it needs OAuth for its Google sign-in", () => {
  const on = {
    ENGRAMPORT_DATABASE_URL: "postgresql://engramport_app@db.example.com:5432/postgres",
    ENGRAMPORT_OAUTH: "true",
    ENGRAMPORT_PUBLIC_URL: "https://mcp.example.com",
    ENGRAMPORT_SUPABASE_URL: "https://ref.supabase.co",
    ENGRAMPORT_SUPABASE_PUBLISHABLE_KEY: "sb_publishable_test",
  };
  assert.equal(resolveConfig(env({})).approvalPage, false);
  assert.deepEqual(configProblems(pg({ ...on, ENGRAMPORT_APPROVAL_PAGE: "true" }), "http"), []);
  assert.match(configProblems(pg({ ...on, ENGRAMPORT_OAUTH: "", ENGRAMPORT_APPROVAL_PAGE: "true" }), "http").join(" "),
    /APPROVAL_PAGE needs ENGRAMPORT_OAUTH=true/);
  assert.match(configProblems(resolveConfig(env({ ENGRAMPORT_APPROVAL_PAGE: "true", ENGRAMPORT_API_URL: "https://api.example.com" })), "http")[0],
    /APPROVAL_PAGE needs ENGRAMPORT_STORE=postgres/);
});
