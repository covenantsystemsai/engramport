/**
 * The whole OAuth sign-in over HTTP, the way claude.ai runs it: discover,
 * register, authorize (Google sign-in stood in for), pick a namespace, trade
 * the code, call /mcp with the token, refresh, revoke. Same database rules as
 * store.pg.test.ts: needs ENGRAMPORT_TEST_DATABASE_URL pointing at a THROWAWAY
 * database, as a superuser.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server as HttpServer } from "node:http";
import pg from "pg";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { createHttpApp } from "../src/http.ts";
import { createOAuthRouter, IdentityProvider, openState, resourceMetadataUrl, sealState } from "../src/oauth.ts";
import type { McpDeps } from "../src/server.ts";
import { currentCaller } from "../src/caller.ts";
import { PostgresStore } from "../src/store/postgres.ts";
import { createAuthStub, signInWithGoogle } from "./support/auth-stub.ts";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const ISSUER = "https://mcp.test";
const CALLBACK = "https://claude.ai/api/mcp/auth_callback";
const s256 = (v: string) => createHash("sha256").update(v).digest("base64url");

describe("oauth over http", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const pepper = randomBytes(32);
  const email = `person-${run}@example.com`;
  let admin: pg.Pool;
  let appPool: pg.Pool;
  let server: HttpServer;
  let base: string;
  let cellPath: string;
  let memberId: string;
  let readOnlyMember: string;

  // Google sign-in through Supabase, stood in for: each sign-in URL the server
  // builds yields one code, which trades for a fresh session only with the
  // verifier whose challenge was in that URL.
  const pending = new Map<string, { challenge: string; email: string }>();
  const signedOut: string[] = [];
  let nextEmail = email;
  const identity: IdentityProvider = {
    signInUrl(challenge, returnTo) {
      assert.equal(returnTo, `${ISSUER}/oauth/callback`);
      const code = randomBytes(8).toString("hex");
      pending.set(code, { challenge, email: nextEmail });
      return `https://idp.test/authorize?code=${code}`;
    },
    async exchange(code, verifier) {
      const p = pending.get(code);
      pending.delete(code);
      if (!p || s256(verifier) !== p.challenge) throw new Error("bad code");
      const s = await signInWithGoogle(admin, p.email);
      return { ...s, accessToken: `sb-${s.sessionId}` };
    },
    async signOut(token) {
      signedOut.push(token);
    },
  };

  const calls: Array<{ key?: string }> = [];
  const deps: McpDeps = {
    toolDefinitions: [{ name: "remember", description: "Store a memory", inputSchema: { type: "object", properties: {} } }],
    executeTool: async () => {
      calls.push({ key: currentCaller()?.apiKey });
      return { content: [{ type: "text", text: JSON.stringify({ ok: true }) }] };
    },
  };

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await createAuthStub(admin);
    await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    const ns = async (slug: string, level: string, parent: string | null) =>
      (await admin.query<{ id: string; path: string }>(
        "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, $2, $3) RETURNING id, path", [parent, level, slug],
      )).rows[0];
    const city = await ns(`oh-${run}`, "city", null);
    const tower = await ns("tower", "tower", city.id);
    const cell = await ns("cell", "cell", tower.id);
    const other = await ns("other", "cell", tower.id);
    cellPath = cell.path;
    const actor = (await admin.query<{ id: string }>(
      "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', $1, 'Claude') RETURNING id", [`oh-${run}`],
    )).rows[0].id;
    memberId = (await admin.query<{ id: string }>(
      "INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ($1, $2, $3) RETURNING id",
      [email, cell.id, actor],
    )).rows[0].id;
    readOnlyMember = (await admin.query<{ id: string }>(
      "INSERT INTO memory.oauth_members (email, namespace_id, actor_id, scopes) VALUES ($1, $2, $3, '{read}') RETURNING id",
      [email, other.id, actor],
    )).rows[0].id;

    const appUrl = new URL(ADMIN_URL!);
    appUrl.username = "engramport_app";
    appUrl.password = "engramport-test-only";
    appPool = new pg.Pool({ connectionString: appUrl.toString() });
    const store = new PostgresStore(appPool, { pepper, transport: "streamable_http" });
    const app = createHttpApp({
      apiUrl: "http://stub",
      namespace: "test",
      deps,
      authenticate: (k) => store.checkKey(k),
      resourceMetadataUrl: resourceMetadataUrl(ISSUER),
      oauth: createOAuthRouter({
        publicUrl: ISSUER, redirectHosts: ["claude.ai", "claude.com"], pepper, db: appPool, identity, registerLimit: 50,
      }),
    });
    server = await new Promise((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    await appPool?.end();
    await admin?.end();
  });

  // ── helpers ──

  const cookieOf = (res: Response) =>
    res.headers.getSetCookie().map((c) => c.split(";")[0]).filter((c) => !c.endsWith("=")).at(-1);

  async function register(redirectUris = [CALLBACK]): Promise<string> {
    const res = await fetch(`${base}/oauth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_name: "Claude", redirect_uris: redirectUris, token_endpoint_auth_method: "none" }),
    });
    assert.equal(res.status, 201);
    return (await res.json()).client_id;
  }

  function authorizeUrl(clientId: string, challenge: string, extra: Record<string, string> = {}) {
    const u = new URL(`${base}/oauth/authorize`);
    for (const [k, v] of Object.entries({
      response_type: "code", client_id: clientId, redirect_uri: CALLBACK, code_challenge: challenge,
      code_challenge_method: "S256", state: "st-1", resource: `${ISSUER}/mcp`, ...extra,
    })) u.searchParams.set(k, v);
    return u.toString();
  }

  /** authorize → sign in → the choice page. Returns its cookie, CSRF token and HTML. */
  async function toChoice(clientId: string, challenge: string, extra: Record<string, string> = {}) {
    const a = await fetch(authorizeUrl(clientId, challenge, extra), { redirect: "manual" });
    assert.equal(a.status, 302);
    const idp = new URL(a.headers.get("location")!);
    assert.equal(idp.host, "idp.test");
    const c = await fetch(`${base}/oauth/callback?code=${idp.searchParams.get("code")}`, {
      redirect: "manual", headers: { Cookie: cookieOf(a)! },
    });
    assert.equal(c.status, 200);
    const html = await c.text();
    const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1];
    return { cookie: cookieOf(c)!, csrf: csrf!, html, headers: c.headers };
  }

  async function decide(cookie: string, fields: Record<string, string>) {
    return fetch(`${base}/oauth/decision`, {
      method: "POST", redirect: "manual",
      headers: { Cookie: cookie, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields),
    });
  }

  async function token(fields: Record<string, string>) {
    const res = await fetch(`${base}/oauth/token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields),
    });
    return { status: res.status, body: await res.json(), cacheControl: res.headers.get("cache-control") };
  }

  /** The whole browser half: a code for the given member. */
  async function codeFor(clientId: string, verifier: string, member = memberId) {
    const { cookie, csrf } = await toChoice(clientId, s256(verifier));
    const d = await decide(cookie, { csrf, member_id: member, action: "approve" });
    assert.equal(d.status, 302);
    const back = new URL(d.headers.get("location")!);
    assert.equal(back.origin + back.pathname, CALLBACK);
    assert.equal(back.searchParams.get("state"), "st-1");
    assert.equal(back.searchParams.get("iss"), ISSUER);
    return back.searchParams.get("code")!;
  }

  const mcp = (accessToken: string) =>
    fetch(`${base}/mcp`, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });

  // ── tests ──

  test("discovery: a 401 on /mcp points at the metadata, which points at the server", async () => {
    const res = await fetch(`${base}/mcp`, { method: "POST" });
    assert.equal(res.status, 401);
    assert.equal(
      res.headers.get("www-authenticate"),
      `Bearer realm="engramport", resource_metadata="${ISSUER}/.well-known/oauth-protected-resource/mcp"`,
    );
    const pr = await (await fetch(`${base}/.well-known/oauth-protected-resource/mcp`)).json();
    assert.deepEqual(pr.authorization_servers, [ISSUER]);
    assert.equal(pr.resource, `${ISSUER}/mcp`);
    const as = await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json();
    assert.equal(as.issuer, ISSUER);
    assert.equal(as.token_endpoint, `${ISSUER}/oauth/token`);
    assert.equal(as.registration_endpoint, `${ISSUER}/oauth/register`);
    assert.deepEqual(as.code_challenge_methods_supported, ["S256"]);
    assert.deepEqual(as.token_endpoint_auth_methods_supported, ["none"]);
  });

  test("the full flow: sign in, pick a namespace, use the token, refresh, revoke", async () => {
    const clientId = await register();
    const verifier = randomBytes(32).toString("base64url");

    const choice = await toChoice(clientId, s256(verifier));
    assert.match(choice.html, /Claude<\/strong> wants to use your EngramPort memory/);
    assert.match(choice.html, /return to <strong>claude\.ai<\/strong>/);
    assert.ok(choice.html.includes(cellPath), "the member's namespace is offered");
    assert.match(choice.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'.*form-action 'self' https:\/\/claude\.ai/);

    const d = await decide(choice.cookie, { csrf: choice.csrf, member_id: memberId, action: "approve" });
    assert.equal(d.status, 302);
    const code = new URL(d.headers.get("location")!).searchParams.get("code")!;
    assert.match(code, /^epa_/);
    assert.ok(signedOut.length > 0, "the Supabase session is ended once the choice is made");

    const t = await token({
      grant_type: "authorization_code", client_id: clientId, code, code_verifier: verifier,
      redirect_uri: CALLBACK, resource: `${ISSUER}/mcp`,
    });
    assert.equal(t.status, 200);
    assert.equal(t.cacheControl, "no-store");
    assert.equal(t.body.token_type, "Bearer");
    assert.equal(t.body.scope, "read write");
    assert.ok(t.body.expires_in > 3500 && t.body.expires_in <= 3600);
    assert.match(t.body.access_token, /^ep_live_/);
    assert.match(t.body.refresh_token, /^epr_/);

    // The real MCP client connects with the token, and the token is what runs.
    const client = new Client({ name: "t", version: "0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${t.body.access_token}` } },
    }));
    await client.callTool({ name: "remember", arguments: {} });
    assert.equal(calls.at(-1)?.key, t.body.access_token);
    await client.close();

    // The same code twice: refused, and what the first use got is taken back.
    const again = await token({ grant_type: "authorization_code", client_id: clientId, code, code_verifier: verifier, redirect_uri: CALLBACK });
    assert.equal(again.status, 400);
    assert.equal(again.body.error, "invalid_grant");
    const dead = await mcp(t.body.access_token);
    assert.equal(dead.status, 401);
    assert.match(dead.headers.get("www-authenticate") ?? "", /error="invalid_token"/);

    // A fresh grant: refresh rotates, and the spent refresh token revokes the grant.
    const v2 = randomBytes(32).toString("base64url");
    const t2 = await token({
      grant_type: "authorization_code", client_id: clientId, code: await codeFor(clientId, v2), code_verifier: v2, redirect_uri: CALLBACK,
    });
    assert.equal(t2.status, 200);
    const r = await token({ grant_type: "refresh_token", client_id: clientId, refresh_token: t2.body.refresh_token });
    assert.equal(r.status, 200);
    assert.notEqual(r.body.refresh_token, t2.body.refresh_token);
    assert.equal((await mcp(r.body.access_token)).status, 200);
    const reuse = await token({ grant_type: "refresh_token", client_id: clientId, refresh_token: t2.body.refresh_token });
    assert.equal(reuse.body.error, "invalid_grant");
    assert.equal((await mcp(r.body.access_token)).status, 401, "reusing a refresh token kills the grant");

    // Revoke: the access token of a third grant stops working at once.
    const v3 = randomBytes(32).toString("base64url");
    const t3 = await token({
      grant_type: "authorization_code", client_id: clientId, code: await codeFor(clientId, v3), code_verifier: v3, redirect_uri: CALLBACK,
    });
    assert.equal((await mcp(t3.body.access_token)).status, 200);
    const rv = await fetch(`${base}/oauth/revoke`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: clientId, token: t3.body.access_token }),
    });
    assert.equal(rv.status, 200);
    assert.equal((await mcp(t3.body.access_token)).status, 401);
    const afterRevoke = await token({ grant_type: "refresh_token", client_id: clientId, refresh_token: t3.body.refresh_token });
    assert.equal(afterRevoke.body.error, "invalid_grant");
  });

  test("a read-only membership gives a read-only token, whatever the client asked for", async () => {
    const clientId = await register();
    const v = randomBytes(32).toString("base64url");
    const code = await codeFor(clientId, v, readOnlyMember);
    const t = await token({ grant_type: "authorization_code", client_id: clientId, code, code_verifier: v, redirect_uri: CALLBACK });
    assert.equal(t.status, 200);
    assert.equal(t.body.scope, "read");
  });

  test("the wrong PKCE verifier, client or redirect gets nothing, and spends the code", async () => {
    const clientId = await register();
    const other = await register();
    const v = randomBytes(32).toString("base64url");
    const code = await codeFor(clientId, v);
    const wrongClient = await token({ grant_type: "authorization_code", client_id: other, code, code_verifier: v, redirect_uri: CALLBACK });
    assert.equal(wrongClient.body.error, "invalid_grant");
    const wrongVerifier = await token({
      grant_type: "authorization_code", client_id: clientId, code, code_verifier: randomBytes(32).toString("base64url"), redirect_uri: CALLBACK,
    });
    assert.equal(wrongVerifier.body.error, "invalid_grant");
    const thenRight = await token({ grant_type: "authorization_code", client_id: clientId, code, code_verifier: v, redirect_uri: CALLBACK });
    assert.equal(thenRight.body.error, "invalid_grant", "a failed try spends the code");
    const secret = await token({ grant_type: "authorization_code", client_id: clientId, client_secret: "x", code, code_verifier: v });
    assert.equal(secret.status, 401);
    assert.equal((await token({ grant_type: "password", client_id: clientId })).body.error, "unsupported_grant_type");
  });

  test("authorize never redirects to an address the client did not register", async () => {
    const clientId = await register();
    const challenge = s256(randomBytes(32).toString("base64url"));
    const unknown = await fetch(authorizeUrl("epc_" + "x".repeat(24), challenge), { redirect: "manual" });
    assert.equal(unknown.status, 400);
    assert.equal(unknown.headers.get("location"), null);
    const elsewhere = await fetch(authorizeUrl(clientId, challenge, { redirect_uri: "https://claude.ai/evil" }), { redirect: "manual" });
    assert.equal(elsewhere.status, 400);
    assert.equal(elsewhere.headers.get("location"), null);

    // Once the redirect is known good, request errors go back to the client.
    for (const [extra, error] of [
      [{ code_challenge_method: "plain" }, "invalid_request"],
      [{ code_challenge: "short" }, "invalid_request"],
      [{ response_type: "token" }, "unsupported_response_type"],
      [{ resource: "https://elsewhere.test/mcp" }, "invalid_target"],
      [{ scope: "admin" }, "invalid_scope"],
    ] as Array<[Record<string, string>, string]>) {
      const res = await fetch(authorizeUrl(clientId, challenge, extra), { redirect: "manual" });
      assert.equal(res.status, 302, JSON.stringify(extra));
      const back = new URL(res.headers.get("location")!);
      assert.equal(back.origin + back.pathname, CALLBACK);
      assert.equal(back.searchParams.get("error"), error);
    }
  });

  test("the choice needs its own cookie and CSRF token; deny goes back with access_denied", async () => {
    const clientId = await register();
    const v = randomBytes(32).toString("base64url");
    const { cookie, csrf } = await toChoice(clientId, s256(v));
    const wrong = (csrf[0] === "A" ? "B" : "A") + csrf.slice(1);
    assert.equal((await decide(cookie, { csrf: wrong, member_id: memberId, action: "approve" })).status, 400);
    assert.equal((await decide(cookie, { csrf: "short", member_id: memberId, action: "approve" })).status, 400);
    assert.equal((await decide("", { csrf, member_id: memberId, action: "approve" })).status, 400);
    const tampered = cookie.slice(0, -2) + (cookie.endsWith("AA") ? "BB" : "AA");
    assert.equal((await decide(tampered, { csrf, member_id: memberId, action: "approve" })).status, 400);
    const deny = await decide(cookie, { csrf, action: "deny" });
    assert.equal(deny.status, 302);
    assert.equal(new URL(deny.headers.get("location")!).searchParams.get("error"), "access_denied");
  });

  test("a member of nothing sees no choice and cannot pick someone else's membership", async () => {
    const clientId = await register();
    nextEmail = `stranger-${run}@example.com`;
    try {
      const { cookie, csrf, html } = await toChoice(clientId, s256(randomBytes(32).toString("base64url")));
      assert.match(html, /No access yet/);
      assert.ok(!html.includes(cellPath));
      const forged = await decide(cookie, { csrf, member_id: memberId, action: "approve" });
      assert.equal(forged.status, 302);
      const back = new URL(forged.headers.get("location")!);
      assert.equal(back.searchParams.get("error"), "access_denied");
      assert.equal(back.searchParams.get("code"), null);
    } finally {
      nextEmail = email;
    }
  });

  test("a sign-in that comes back from the wrong browser, or late, is refused", async () => {
    const clientId = await register();
    const a = await fetch(authorizeUrl(clientId, s256(randomBytes(32).toString("base64url"))), { redirect: "manual" });
    const code = new URL(a.headers.get("location")!).searchParams.get("code");
    const noCookie = await fetch(`${base}/oauth/callback?code=${code}`, { redirect: "manual" });
    assert.equal(noCookie.status, 400);
    const sealed = decodeURIComponent(cookieOf(a)!.split("=")[1]);
    const flow = openState(pepper, sealed)!;
    const late = sealState(pepper, { ...flow, exp: Date.now() - 1 });
    const res = await fetch(`${base}/oauth/callback?code=${code}`, {
      redirect: "manual", headers: { Cookie: `__Host-ep_oauth=${late}` },
    });
    assert.equal(res.status, 400);
    assert.equal(openState(randomBytes(32), sealed), undefined, "another server's pepper cannot open it");
  });

  test("registration takes allowed redirect hosts and public clients only", async () => {
    const reg = (body: unknown) =>
      fetch(`${base}/oauth/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    for (const uris of [
      ["https://evil.test/cb"], ["http://claude.ai/cb"], ["https://user@claude.ai/cb"], ["https://claude.ai/cb#x"], [], ["javascript:alert(1)"],
    ]) {
      const res = await reg({ redirect_uris: uris });
      assert.equal(res.status, 400, JSON.stringify(uris));
      assert.equal((await res.json()).error, "invalid_redirect_uri");
    }
    assert.equal((await reg({ redirect_uris: [CALLBACK], token_endpoint_auth_method: "client_secret_basic" })).status, 400);
    assert.equal((await reg({ redirect_uris: [CALLBACK], grant_types: ["client_credentials"] })).status, 400);
    assert.equal((await reg({ redirect_uris: [CALLBACK], client_name: "a\nb" })).status, 400);
    const loop = await reg({ redirect_uris: ["http://127.0.0.1:33418/callback"] });
    assert.equal(loop.status, 201);
  });
});
