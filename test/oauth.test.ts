// OAuth pieces that need no database: the redirect allowlist, the sealed
// in-flight state, and the Supabase Auth client against a stand-in server.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import express from "express";

import { openState, parseScope, redirectAllowed, sealState, supabaseIdentity } from "../src/oauth.ts";

test("redirectAllowed: https on a listed host, or http on loopback, nothing else", () => {
  const hosts = ["claude.ai", "claude.com"];
  assert.ok(redirectAllowed("https://claude.ai/api/mcp/auth_callback", hosts));
  assert.ok(redirectAllowed("https://claude.com/cb?x=1", hosts));
  assert.ok(redirectAllowed("http://localhost:6274/oauth/callback", hosts));
  assert.ok(redirectAllowed("http://127.0.0.1:1/cb", hosts));
  for (const bad of [
    "https://claude.ai.evil.test/cb", "https://evil.test/cb", "http://claude.ai/cb", "https://a:b@claude.ai/cb",
    "https://claude.ai/cb#frag", "https://claude.ai/c b", "javascript:alert(1)", "not a url", "http://10.0.0.1/cb",
    `https://claude.ai/${"x".repeat(500)}`,
  ]) {
    assert.equal(redirectAllowed(bad, hosts), false, bad);
  }
});

test("sealed state opens only with the same pepper, untouched and in time", () => {
  const pepper = randomBytes(32);
  const value = {
    step: "login" as const, exp: Date.now() + 60_000, clientId: "epc_x", redirectUri: "https://claude.ai/cb",
    challenge: "c", scopes: ["read"], idpVerifier: "v",
  };
  const sealed = sealState(pepper, value);
  assert.ok(!sealed.includes("claude.ai"), "the contents are not readable");
  assert.deepEqual(openState(pepper, sealed), value);
  assert.equal(openState(randomBytes(32), sealed), undefined);
  assert.equal(openState(pepper, sealed.slice(0, -3) + "AAA"), undefined);
  assert.equal(openState(pepper, sealed, value.exp + 1), undefined);
  assert.equal(openState(pepper, "garbage"), undefined);
  assert.equal(openState(pepper, undefined), undefined);
});

test("supabaseIdentity: PKCE sign-in URL, code trade and sign-out against Supabase Auth's API", async () => {
  const seen: Array<{ path: string; apikey?: string; body?: unknown; auth?: string }> = [];
  const userId = randomUUID();
  const sessionId = randomUUID();
  let issuer = "";
  let claims: Record<string, unknown> = {};
  const app = express();
  app.use(express.json());
  app.post("/auth/v1/token", (req, res) => {
    seen.push({ path: req.originalUrl, apikey: req.get("apikey"), body: req.body });
    const jwt = ["e30", Buffer.from(JSON.stringify(claims)).toString("base64url"), "sig"].join(".");
    res.json({ access_token: jwt, token_type: "bearer" });
  });
  app.post("/auth/v1/logout", (req, res) => {
    seen.push({ path: req.originalUrl, auth: req.get("authorization") });
    res.status(204).end();
  });
  const server = await new Promise<import("node:http").Server>((r) => {
    const s = app.listen(0, "127.0.0.1", () => r(s));
  });
  try {
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    issuer = `${base}/auth/v1`;
    const idp = supabaseIdentity(`${base}/`, "sb_publishable_test");

    const url = new URL(idp.signInUrl("CHALLENGE", "https://mcp.example.com/oauth/callback"));
    assert.equal(url.pathname, "/auth/v1/authorize");
    assert.equal(url.searchParams.get("provider"), "google");
    assert.equal(url.searchParams.get("code_challenge"), "CHALLENGE");
    assert.equal(url.searchParams.get("code_challenge_method"), "s256");
    assert.equal(url.searchParams.get("redirect_to"), "https://mcp.example.com/oauth/callback");

    claims = { iss: issuer, sub: userId, session_id: sessionId };
    const who = await idp.exchange("the-code", "the-verifier");
    assert.equal(who.userId, userId);
    assert.equal(who.sessionId, sessionId);
    assert.deepEqual(seen[0], {
      path: "/auth/v1/token?grant_type=pkce", apikey: "sb_publishable_test",
      body: { auth_code: "the-code", code_verifier: "the-verifier" },
    });

    for (const wrong of [
      { iss: "https://other.supabase.co/auth/v1", sub: userId, session_id: sessionId },
      { iss: issuer, sub: "not-a-uuid", session_id: sessionId },
      { iss: issuer, sub: userId },
    ]) {
      claims = wrong;
      await assert.rejects(idp.exchange("c", "v"), /unexpected session/);
    }

    await idp.signOut(who.accessToken);
    assert.deepEqual(seen.at(-1), { path: "/auth/v1/logout?scope=local", auth: `Bearer ${who.accessToken}` });
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("token, revoke and the sign-in pages are rate limited per instance", async () => {
  const { createOAuthRouter } = await import("../src/oauth.ts");
  const app = express();
  app.use(createOAuthRouter({
    publicUrl: "https://mcp.example.com", redirectHosts: ["claude.ai"], pepper: randomBytes(32),
    db: { query: async () => { throw new Error("not reached"); } },
    identity: { signInUrl: () => "https://idp.test", exchange: async () => { throw new Error("x"); }, signOut: async () => {} },
    limits: { browserPerMinute: 2, tokenPerMinute: 2, registerPerHour: 1 },
  }));
  const server = await new Promise<import("node:http").Server>((r) => {
    const s = app.listen(0, "127.0.0.1", () => r(s));
  });
  try {
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const token = (clientId: string) => fetch(`${base}/oauth/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", client_id: clientId, code: "nope" }),
    }).then((r) => r.status);
    assert.deepEqual([await token("epc_a"), await token("epc_a"), await token("epc_a")], [400, 400, 429]);
    assert.equal(await token("epc_b"), 400, "another client has its own budget");
    const cb = () => fetch(`${base}/oauth/callback`).then((r) => r.status);
    assert.deepEqual([await cb(), await cb(), await cb()], [400, 400, 429]);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("parseScope: read and write only, and every grant can read", () => {
  assert.deepEqual(parseScope(undefined), ["read", "write"]);
  assert.deepEqual(parseScope("read"), ["read"]);
  assert.deepEqual(parseScope("write"), ["read", "write"]);
  assert.deepEqual(parseScope("write read write"), ["read", "write"]);
  assert.equal(parseScope("admin"), undefined);
  assert.equal(parseScope("read admin"), undefined);
  assert.equal(parseScope(" "), undefined);
});
