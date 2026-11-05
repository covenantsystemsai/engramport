/**
 * The restore page over HTTP, the way a person uses it: open the link, sign in
 * with Google (stood in for), review the retracted memory, choose to restore
 * it, confirm. Same database rules as store.pg.test.ts: needs
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
import { createApprovalRouter } from "../src/approve.ts";
import { createErasureRouter } from "../src/erase.ts";
import { createRestoreRouter, openRestoreVisit } from "../src/restore.ts";
import type { IdentityProvider } from "../src/oauth.ts";
import { hashKey, mintKey } from "../src/keys.ts";
import { createAuthStub, signInWithGoogle } from "./support/auth-stub.ts";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const ISSUER = "https://mcp.test";
const s256 = (v: string) => createHash("sha256").update(v).digest("base64url");

describe("restore page over http", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const pepper = randomBytes(32);
  const ownerEmail = `rs-owner-${run}@example.com`;
  const nobodyEmail = `rs-nobody-${run}@example.com`;
  let admin: pg.Pool;
  let appPool: pg.Pool;
  let server: HttpServer;
  let base: string;
  let cellId: string;
  let cellPath: string;
  let agentKey: string;

  const pending = new Map<string, { challenge: string; email: string; returnTo: string }>();
  const signedOut: string[] = [];
  let nextEmail = ownerEmail;
  const identity: IdentityProvider = {
    signInUrl(challenge, returnTo) {
      const code = randomBytes(8).toString("hex");
      pending.set(code, { challenge, email: nextEmail, returnTo });
      return `https://idp.test/authorize?code=${code}&return=${encodeURIComponent(returnTo)}`;
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

  /** As the agent's key: run one call in the cell and return its value. */
  async function asAgent<T>(sql: string, params: unknown[]): Promise<T> {
    const c = await appPool.connect();
    try {
      await c.query("BEGIN");
      const key = (await admin.query<{ id: string }>("SELECT id FROM memory.api_keys WHERE key_hash = $1",
        [hashKey(agentKey, pepper)]));
      await c.query("SELECT set_config('app.api_key_id', $1, true), set_config('app.namespace_id', $2, true)",
        [key.rows[0]?.id ?? "", cellId]);
      const v = (await c.query<{ v: T }>(sql, params)).rows[0].v;
      await c.query("COMMIT");
      return v;
    } catch (err) {
      await c.query("ROLLBACK");
      throw err;
    } finally {
      c.release();
    }
  }
  const remember = (content: string) =>
    asAgent<string>("SELECT memory.remember('fact', $1, 'remember', 'rest') AS v", [content]);
  const retract = (id: string) =>
    asAgent<number>("WITH r AS (UPDATE memory.memories SET status = 'retracted' WHERE id = $1 RETURNING 1) SELECT count(*)::int AS v FROM r", [id]);

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await createAuthStub(admin);
    await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    const ns = async (slug: string, level: string, parent: string | null) =>
      (await admin.query<{ id: string; path: string }>(
        "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, $2, $3) RETURNING id, path", [parent, level, slug],
      )).rows[0];
    const city = await ns(`rs-${run}`, "city", null);
    const tower = await ns("tower", "tower", city.id);
    const cell = await ns("cell", "cell", tower.id);
    cellId = cell.id;
    cellPath = cell.path;
    const actor = async (kind: string, slug: string) => (await admin.query<{ id: string }>(
      "INSERT INTO memory.actors (kind, slug, display_name) VALUES ($1, $2, $2) RETURNING id", [kind, slug],
    )).rows[0].id;
    const owner = await actor("human", `rs-owner-${run}`);
    const nobody = await actor("human", `rs-nobody-${run}`);
    const agent = await actor("agent", `rs-agent-${run}`);
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
      erase: createErasureRouter({ publicUrl: ISSUER, pepper, db: appPool, identity, perMinute: 1000 }),
      restore: createRestoreRouter({ publicUrl: ISSUER, pepper, db: appPool, identity, perMinute: 1000 }),
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
    const a = await fetch(`${base}/restore/${memoryId}`, { redirect: "manual" });
    assert.equal(a.status, 302);
    const idp = new URL(a.headers.get("location")!);
    assert.equal(idp.host, "idp.test");
    assert.equal(idp.searchParams.get("return"), `${ISSUER}/restore/callback`);
    const c = await fetch(`${base}/restore/callback?code=${idp.searchParams.get("code")}`, {
      redirect: "manual", headers: { Cookie: cookieOf(a)! },
    });
    const html = await c.text();
    return { status: c.status, html, cookie: cookieOf(c), csrf: csrfOf(html), headers: c.headers };
  }

  /** Review, choose to restore: the confirmation page, its cookie and token. */
  async function toConfirm(memoryId: string) {
    const r = await toReview(memoryId);
    assert.equal(r.status, 200, r.html);
    const c = await post("/restore/review", r.cookie, { csrf: r.csrf!, action: "restore" });
    const html = await c.text();
    return { status: c.status, html, cookie: cookieOf(c), csrf: csrfOf(html), res: c };
  }

  const statusOf = async (id: string) =>
    (await admin.query<{ status: string }>("SELECT status::text FROM memory.memories WHERE id = $1", [id])).rows[0].status;

  test("the owner reviews a retracted memory, confirms, and it is current again", async () => {
    const id = await remember("the gate code changed to <b>4411</b>");
    assert.equal(await retract(id), 1);
    const r = await toReview(id);
    assert.equal(r.status, 200, r.html);
    assert.match(r.html, /Restore this memory\?/);
    assert.match(r.html, /the gate code changed to &lt;b&gt;4411&lt;\/b&gt;/, "the text is shown, escaped");
    assert.ok(r.html.includes(cellPath));
    assert.match(r.html, /Can be restored until/);
    assert.match(r.html, /current again/);
    assert.match(r.headers.get("content-security-policy")!, /default-src 'none'/);
    assert.equal(r.headers.get("x-frame-options"), "DENY");
    assert.match(r.headers.get("set-cookie")!, /__Host-ep_restore=[^;]+; Path=\/; Max-Age=600; HttpOnly; Secure; SameSite=Lax/);

    const c = await post("/restore/review", r.cookie, { csrf: r.csrf!, action: "restore" });
    const html = await c.text();
    assert.equal(c.status, 200, html);
    assert.match(html, /Restore it\?/);
    const visit = openRestoreVisit(pepper, c.headers.getSetCookie()[0].split(";")[0].split("=")[1]);
    assert.equal(visit?.step, "confirm");
    const secret = visit?.step === "confirm" ? visit.secret : "";
    assert.match(secret, /^[0-9a-f]{64}$/);
    assert.ok(!html.includes(secret), "the challenge secret never reaches the page");
    assert.equal(await statusOf(id), "retracted", "nothing is restored before the confirmation");

    const done = await post("/restore/confirm", cookieOf(c), { csrf: csrfOf(html)!, choice: "confirm" });
    const doneHtml = await done.text();
    assert.equal(done.status, 200, doneHtml);
    assert.match(doneHtml, /Restored/);
    assert.match(doneHtml, /current again/);
    assert.equal(await statusOf(id), "active");
    const rec = (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM memory.restorations WHERE memory_id = $1", [id]))
      .rows[0].n;
    assert.equal(rec, 1);
    assert.match(done.headers.get("set-cookie")!, /__Host-ep_restore=; Path=\/; Max-Age=0/);
    assert.ok(signedOut.length > 0, "the Supabase session is ended");

    const again = await toReview(id);
    assert.match(again.html, /can(&#39;|')t be restored/);
    assert.match(again.html, /not retracted/);
    assert.equal(again.csrf, undefined, "nothing left to confirm");
  });

  test("replaying the confirmation restores nothing more", async () => {
    const id = await remember("restore replay check");
    await retract(id);
    const c = await toConfirm(id);
    const first = await post("/restore/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" });
    assert.equal(first.status, 200);
    const again = await post("/restore/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" });
    assert.equal(again.status, 409);
    assert.match(await again.text(), /already used/);
    const n = (await admin.query<{ n: number }>("SELECT count(*)::int AS n FROM memory.restorations WHERE memory_id = $1", [id]))
      .rows[0].n;
    assert.equal(n, 1);
  });

  test("a retraction older than 30 days is final, and the page says so with nothing to press", async () => {
    const id = await remember("retracted long ago");
    await retract(id);
    await admin.query("ALTER TABLE memory.memories DISABLE TRIGGER memories_retraction_stamp");
    try {
      await admin.query("UPDATE memory.memories SET retracted_at = now() - interval '31 days' WHERE id = $1", [id]);
    } finally {
      await admin.query("ALTER TABLE memory.memories ENABLE TRIGGER memories_retraction_stamp");
    }
    const r = await toReview(id);
    assert.equal(r.status, 200, r.html);
    assert.match(r.html, /can(&#39;|')t be restored/);
    assert.match(r.html, /30 days to restore it have passed/);
    assert.equal(r.csrf, undefined);
    assert.equal(await statusOf(id), "retracted");
  });

  test("leaving it retracted, at either step, restores nothing", async () => {
    const id = await remember("left retracted");
    await retract(id);
    const r = await toReview(id);
    const later = await post("/restore/review", r.cookie, { csrf: r.csrf!, action: "cancel" });
    assert.match(await later.text(), /Nothing was restored/);
    const c = await toConfirm(id);
    const back = await post("/restore/confirm", c.cookie, { csrf: c.csrf!, choice: "cancel" });
    assert.match(await back.text(), /Nothing was restored/);
    assert.equal(await statusOf(id), "retracted");
  });

  test("someone without authority sees the same page as for a memory that doesn't exist", async () => {
    const id = await remember("only the owner restores");
    await retract(id);
    const theirs = await toReview(id, nobodyEmail);
    const missing = await toReview("00000000-0000-7000-8000-00000000dead");
    assert.equal(theirs.status, 403);
    assert.equal(missing.status, 403);
    const body = (html: string) => /<body>(.*)<\/body>/s.exec(html)?.[1];
    assert.equal(body(theirs.html), body(missing.html));
    assert.ok(!theirs.html.includes("only the owner restores"));
    assert.equal(theirs.csrf, undefined, "no form to restore with");
  });

  test("without the visit's own cookie and token nothing can be posted, and an erasure visit is no way in", async () => {
    const id = await remember("forged restore posts");
    await retract(id);
    const r = await toReview(id);
    assert.equal((await post("/restore/review", undefined, { csrf: r.csrf!, action: "restore" })).status, 400);
    assert.equal((await post("/restore/review", r.cookie, { csrf: "wrong", action: "restore" })).status, 400);
    assert.equal((await post("/restore/review", r.cookie, { action: "restore" })).status, 400);
    assert.equal((await post("/restore/confirm", r.cookie, { csrf: r.csrf!, choice: "confirm" })).status, 400);
    // The restore visit's cookie, renamed to the erasure page's, opens nothing there.
    const value = r.cookie!.split("=").slice(1).join("=");
    assert.equal((await post("/erase/review", `__Host-ep_erase=${value}`, { csrf: r.csrf!, action: "erase" })).status, 400);
    const withKey = await fetch(`${base}/restore/confirm`, {
      method: "POST", redirect: "manual",
      headers: { Authorization: `Bearer ${agentKey}`, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ choice: "confirm" }),
    });
    assert.equal(withKey.status, 400);
    assert.equal(await statusOf(id), "retracted");
  });

  test("a bad link starts no sign-in, and a callback with no visit is refused", async () => {
    const bad = await fetch(`${base}/restore/not-a-memory`, { redirect: "manual" });
    assert.equal(bad.status, 404);
    assert.equal(bad.headers.getSetCookie().length, 0);
    const lost = await fetch(`${base}/restore/callback?code=abc`, { redirect: "manual" });
    assert.equal(lost.status, 400);
  });
});
