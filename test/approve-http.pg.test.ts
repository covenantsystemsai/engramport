/**
 * The approval page over HTTP, the way a person uses it: open the link, sign
 * in with Google (stood in for), review the memory, pick approve or reject,
 * confirm. Same database rules as store.pg.test.ts: needs
 * ENGRAMPORT_TEST_DATABASE_URL pointing at a THROWAWAY database, as a
 * superuser.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server as HttpServer } from "node:http";
import pg from "pg";

import { createHttpApp } from "../src/http.ts";
import { createApprovalRouter, openVisit } from "../src/approve.ts";
import type { IdentityProvider } from "../src/oauth.ts";
import { hashKey, mintKey } from "../src/keys.ts";
import { createAuthStub, signInWithGoogle } from "./support/auth-stub.ts";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const ISSUER = "https://mcp.test";
const s256 = (v: string) => createHash("sha256").update(v).digest("base64url");

describe("approval page over http", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const pepper = randomBytes(32);
  const ownerEmail = `owner-${run}@example.com`;
  const nobodyEmail = `nobody-${run}@example.com`;
  let admin: pg.Pool;
  let appPool: pg.Pool;
  let server: HttpServer;
  let base: string;
  let cellId: string;
  let cellPath: string;
  let agentKey: string;

  const pending = new Map<string, { challenge: string; email: string }>();
  const signedOut: string[] = [];
  let nextEmail = ownerEmail;
  const identity: IdentityProvider = {
    signInUrl(challenge, returnTo) {
      assert.equal(returnTo, `${ISSUER}/approve/callback`);
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

  async function remember(content: string): Promise<string> {
    const c = await appPool.connect();
    try {
      await c.query("BEGIN");
      const key = (await admin.query<{ id: string }>("SELECT id FROM memory.api_keys WHERE key_hash = $1",
        [hashKey(agentKey, pepper)]));
      await c.query("SELECT set_config('app.api_key_id', $1, true), set_config('app.namespace_id', $2, true)",
        [key.rows[0]?.id ?? "", cellId]);
      const id = (await c.query<{ id: string }>(
        "SELECT memory.remember('decision', $1, 'remember', 'rest', p_claim_type => 'decision') AS id", [content],
      )).rows[0].id;
      await c.query("COMMIT");
      return id;
    } catch (err) {
      await c.query("ROLLBACK");
      throw err;
    } finally {
      c.release();
    }
  }

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await createAuthStub(admin);
    await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    const ns = async (slug: string, level: string, parent: string | null) =>
      (await admin.query<{ id: string; path: string }>(
        "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, $2, $3) RETURNING id, path", [parent, level, slug],
      )).rows[0];
    const city = await ns(`ap-${run}`, "city", null);
    const tower = await ns("tower", "tower", city.id);
    const cell = await ns("cell", "cell", tower.id);
    cellId = cell.id;
    cellPath = cell.path;
    const actor = async (kind: string, slug: string) => (await admin.query<{ id: string }>(
      "INSERT INTO memory.actors (kind, slug, display_name) VALUES ($1, $2, $2) RETURNING id", [kind, slug],
    )).rows[0].id;
    const owner = await actor("human", `ap-owner-${run}`);
    const nobody = await actor("human", `ap-nobody-${run}`);
    const agent = await actor("agent", `ap-agent-${run}`);
    await admin.query("INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ($1, $2, $3), ($4, $2, $5)",
      [ownerEmail, cell.id, owner, nobodyEmail, nobody]);
    const k = mintKey();
    agentKey = k.key;
    await admin.query(
      "INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes) VALUES ($1, $2, $3, $4, '{read,write}')",
      [cell.id, agent, k.prefix, hashKey(k.key, pepper)]);

    const appUrl = new URL(ADMIN_URL!);
    appUrl.username = "engramport_app";
    appUrl.password = "engramport-test-only";
    appPool = new pg.Pool({ connectionString: appUrl.toString() });

    // The owner's authority, accepted the real way, with their own sign-in.
    const grant = (await admin.query<{ id: string }>(
      "INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope) VALUES ($1, $2, 'cell_knowledge') RETURNING id",
      [owner, cell.id])).rows[0].id;
    const s = await signInWithGoogle(admin, ownerEmail);
    const offered = (await appPool.query<{ grant_sha256: string }>(
      "SELECT grant_sha256 FROM memory.pending_authority_grants($1, $2) WHERE authority_id = $3",
      [s.userId, s.sessionId, grant])).rows[0];
    await appPool.query("SELECT memory.decide_approval_authority($1, $2, $3, 'accept', $4)",
      [s.userId, s.sessionId, grant, offered.grant_sha256]);

    const app = createHttpApp({
      apiUrl: "http://stub",
      namespace: "test",
      authenticate: async () => false,
      approve: createApprovalRouter({ publicUrl: ISSUER, pepper, db: appPool, identity, perMinute: 1000 }),
      logRequests: false,
    });
    server = await new Promise((resolve) => {
      const srv = app.listen(0, "127.0.0.1", () => resolve(srv));
    });
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    await appPool?.end();
    await admin?.end();
  });

  const cookieOf = (res: Response) =>
    res.headers.getSetCookie().map((c) => c.split(";")[0]).filter((c) => !c.endsWith("=")).at(-1);
  const csrfOf = (html: string) => /name="csrf" value="([^"]+)"/.exec(html)?.[1];
  const post = (path: string, cookie: string | undefined, fields: Record<string, string>) =>
    fetch(`${base}${path}`, {
      method: "POST", redirect: "manual",
      headers: { ...(cookie ? { Cookie: cookie } : {}), "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields),
    });

  /** Open the link and sign in: the review page, its cookie and token. */
  async function toReview(memoryId: string, email = ownerEmail) {
    nextEmail = email;
    const a = await fetch(`${base}/approve/${memoryId}`, { redirect: "manual" });
    assert.equal(a.status, 302);
    const idp = new URL(a.headers.get("location")!);
    assert.equal(idp.host, "idp.test");
    const c = await fetch(`${base}/approve/callback?code=${idp.searchParams.get("code")}`, {
      redirect: "manual", headers: { Cookie: cookieOf(a)! },
    });
    const html = await c.text();
    return { status: c.status, html, cookie: cookieOf(c), csrf: csrfOf(html), headers: c.headers };
  }

  /** Review, pick an action: the confirmation page, its cookie and token. */
  async function toConfirm(memoryId: string, action: "approve" | "reject") {
    const r = await toReview(memoryId);
    assert.equal(r.status, 200, r.html);
    const c = await post("/approve/review", r.cookie, { csrf: r.csrf!, action });
    const html = await c.text();
    return { status: c.status, html, cookie: cookieOf(c), csrf: csrfOf(html) };
  }

  const stateOf = async (id: string) =>
    (await admin.query<{ approval_state: string }>("SELECT approval_state FROM memory.memories WHERE id = $1", [id]))
      .rows[0].approval_state;

  test("a person reviews a memory, approves it and confirms, with one sign-in", async () => {
    const id = await remember("ship on Fridays <b>only</b>");
    const r = await toReview(id);
    assert.equal(r.status, 200);
    assert.match(r.html, /Review this memory/);
    assert.match(r.html, /ship on Fridays &lt;b&gt;only&lt;\/b&gt;/, "the text is shown, escaped");
    assert.ok(r.html.includes(cellPath));
    assert.match(r.html, /<dt>Version<\/dt><dd>1<\/dd>/);
    assert.match(r.headers.get("content-security-policy")!, /default-src 'none'/);
    assert.doesNotMatch(r.headers.get("content-security-policy")!, /script-src/);
    assert.equal(r.headers.get("x-frame-options"), "DENY");
    assert.match(r.headers.get("set-cookie")!, /__Host-ep_approve=[^;]+; Path=\/; Max-Age=600; HttpOnly; Secure; SameSite=Lax/);

    const c = await post("/approve/review", r.cookie, { csrf: r.csrf!, action: "approve" });
    const html = await c.text();
    assert.equal(c.status, 200);
    assert.match(html, /Approve this memory\?/);
    const visit = openVisit(pepper, c.headers.getSetCookie()[0].split(";")[0].split("=")[1]);
    assert.equal(visit?.step, "confirm");
    const secret = visit?.step === "confirm" ? visit.secret : "";
    assert.match(secret, /^[0-9a-f]{64}$/);
    assert.ok(!html.includes(secret), "the challenge secret never reaches the page");
    assert.equal(await stateOf(id), "none", "nothing is decided before the confirmation");

    const done = await post("/approve/confirm", cookieOf(c), { csrf: csrfOf(html)!, choice: "confirm" });
    assert.equal(done.status, 200);
    assert.match(await done.text(), /Approved/);
    assert.equal(await stateOf(id), "approved");
    const rec = (await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM memory.approvals a JOIN memory.approval_challenges c ON c.id = a.challenge_id
       WHERE a.memory_id = $1 AND c.action = 'approve' AND a.sign_in_hash = c.sign_in_hash`, [id])).rows[0].n;
    assert.equal(rec, 1);
    assert.match(done.headers.get("set-cookie")!, /__Host-ep_approve=; Path=\/; Max-Age=0/);
    assert.ok(signedOut.length > 0, "the Supabase session is ended");
  });

  test("rejecting works the same way", async () => {
    const id = await remember("delete the archive every night");
    const c = await toConfirm(id, "reject");
    assert.match(c.html, /Reject this memory\?/);
    const done = await post("/approve/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" });
    assert.match(await done.text(), /Rejected/);
    assert.equal(await stateOf(id), "rejected");
  });

  test("replaying the confirmation decides nothing more", async () => {
    const id = await remember("replay check");
    const c = await toConfirm(id, "approve");
    const first = await post("/approve/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" });
    assert.equal(first.status, 200);
    const again = await post("/approve/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" });
    assert.equal(again.status, 409);
    assert.match(await again.text(), /already used/);
    const n = (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM memory.approvals WHERE memory_id = $1", [id]))
      .rows[0].n;
    assert.equal(n, 1);
  });

  test("a memory that changes after the challenge cannot be confirmed", async () => {
    const id = await remember("changes underneath");
    const c = await toConfirm(id, "approve");
    await admin.query("UPDATE memory.memories SET status = 'superseded' WHERE id = $1", [id]);
    const done = await post("/approve/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" });
    assert.equal(done.status, 409);
    assert.match(await done.text(), /no longer active/);
    assert.equal(await stateOf(id), "none");
  });

  test("going back without deciding leaves the memory as it was", async () => {
    const id = await remember("not now");
    const r = await toReview(id);
    const later = await post("/approve/review", r.cookie, { csrf: r.csrf!, action: "cancel" });
    assert.match(await later.text(), /Nothing was decided/);
    const c = await toConfirm(id, "approve");
    const back = await post("/approve/confirm", c.cookie, { csrf: c.csrf!, choice: "cancel" });
    assert.match(await back.text(), /Nothing was decided/);
    assert.equal(await stateOf(id), "none");
  });

  test("someone without authority sees the same page as for a memory that doesn't exist", async () => {
    const id = await remember("only the owner decides");
    const theirs = await toReview(id, nobodyEmail);
    const missing = await toReview("00000000-0000-7000-8000-00000000dead");
    assert.equal(theirs.status, 403);
    assert.equal(missing.status, 403);
    const body = (html: string) => /<body>(.*)<\/body>/s.exec(html)?.[1];
    assert.equal(body(theirs.html), body(missing.html));
    assert.ok(!theirs.html.includes("only the owner decides"));
    assert.equal(theirs.csrf, undefined, "no form to decide with");
  });

  test("without the visit's own cookie and token nothing can be posted", async () => {
    const id = await remember("forged posts");
    const r = await toReview(id);
    assert.equal((await post("/approve/review", undefined, { csrf: r.csrf!, action: "approve" })).status, 400);
    assert.equal((await post("/approve/review", r.cookie, { csrf: "wrong", action: "approve" })).status, 400);
    assert.equal((await post("/approve/review", r.cookie, { action: "approve" })).status, 400);
    // The review step's cookie is not a confirmation.
    assert.equal((await post("/approve/confirm", r.cookie, { csrf: r.csrf!, choice: "confirm" })).status, 400);
    // An agent's key is no way in.
    const withKey = await fetch(`${base}/approve/confirm`, {
      method: "POST", redirect: "manual",
      headers: { Authorization: `Bearer ${agentKey}`, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ choice: "confirm" }),
    });
    assert.equal(withKey.status, 400);
    assert.equal(await stateOf(id), "none");
  });

  test("a bad link starts no sign-in, and a callback with no visit is refused", async () => {
    const bad = await fetch(`${base}/approve/not-a-memory`, { redirect: "manual" });
    assert.equal(bad.status, 404);
    assert.equal(bad.headers.getSetCookie().length, 0);
    const lost = await fetch(`${base}/approve/callback?code=abc`, { redirect: "manual" });
    assert.equal(lost.status, 400);
  });
});
