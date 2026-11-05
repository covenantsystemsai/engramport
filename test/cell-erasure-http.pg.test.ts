/**
 * The whole-cell erasure pages over HTTP, the way two people use them: the
 * cell's owner opens the start link, signs in with Google (stood in for),
 * reviews what the cell holds and starts it, which freezes the cell; a
 * different person holding the cell-erasure-confirmer role opens the request's
 * link, signs in, reviews counts only, and confirms. Same database rules as
 * store.pg.test.ts: needs ENGRAMPORT_TEST_DATABASE_URL pointing at a THROWAWAY
 * database, as a superuser.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server as HttpServer } from "node:http";
import pg from "pg";

import { createHttpApp } from "../src/http.ts";
import { createCellErasureRouter, openCellErasureVisit } from "../src/cell-erase.ts";
import { createRestoreRouter } from "../src/restore.ts";
import type { IdentityProvider } from "../src/oauth.ts";
import { hashKey, mintKey } from "../src/keys.ts";
import { createAuthStub, signInWithGoogle } from "./support/auth-stub.ts";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const ISSUER = "https://mcp.test";
const s256 = (v: string) => createHash("sha256").update(v).digest("base64url");

describe("whole-cell erasure pages over http", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const pepper = randomBytes(32);
  const ownerEmail = `ce-owner-${run}@example.com`;
  const confirmerEmail = `ce-confirmer-${run}@an2b.test`;
  const nobodyEmail = `ce-nobody-${run}@example.com`;
  let admin: pg.Pool;
  let appPool: pg.Pool;
  let server: HttpServer;
  let base: string;
  let cityId: string;
  let owner: string;
  let confirmer: string;
  let agent: string;

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

  interface Cell { id: string; path: string; key: string }
  let cells = 0;

  /** A fresh client cell with an agent key, owned by `who` with an authority they accepted themselves. */
  async function makeCell(who = owner, email = ownerEmail): Promise<Cell> {
    const tower = (await admin.query<{ id: string }>(
      "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, 'tower', $2) RETURNING id",
      [cityId, `t${++cells}`])).rows[0];
    const cell = (await admin.query<{ id: string; path: string }>(
      "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, 'cell', 'cell') RETURNING id, path",
      [tower.id])).rows[0];
    await admin.query("INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ($1, $2, $3), ($4, $2, $5)",
      [email, cell.id, who, nobodyEmail, nobody]);
    const k = mintKey();
    await admin.query(
      "INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes) VALUES ($1, $2, $3, $4, '{read,write}')",
      [cell.id, agent, k.prefix, hashKey(k.key, pepper)]);
    const grant = (await admin.query<{ id: string }>(
      "INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope) VALUES ($1, $2, 'cell_knowledge') RETURNING id",
      [who, cell.id])).rows[0].id;
    const s = await signInWithGoogle(admin, email);
    const offered = (await appPool.query<{ grant_sha256: string }>(
      "SELECT grant_sha256 FROM memory.pending_authority_grants($1, $2) WHERE authority_id = $3",
      [s.userId, s.sessionId, grant])).rows[0];
    await appPool.query("SELECT memory.decide_approval_authority($1, $2, $3, 'accept', $4)",
      [s.userId, s.sessionId, grant, offered.grant_sha256]);
    return { id: cell.id, path: cell.path, key: k.key };
  }
  let nobody: string;

  /** As the cell's agent key: run one call in the cell and return its value. */
  async function asAgent<T>(cell: Cell, sql: string, params: unknown[]): Promise<T> {
    const c = await appPool.connect();
    try {
      await c.query("BEGIN");
      const key = await admin.query<{ id: string }>("SELECT id FROM memory.api_keys WHERE key_hash = $1",
        [hashKey(cell.key, pepper)]);
      await c.query("SELECT set_config('app.api_key_id', $1, true), set_config('app.namespace_id', $2, true)",
        [key.rows[0].id, cell.id]);
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
  const remember = (cell: Cell, content: string) =>
    asAgent<string>(cell, "SELECT memory.remember('fact', $1, 'remember', 'rest') AS v", [content]);

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await createAuthStub(admin);
    await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    cityId = (await admin.query<{ id: string }>(
      "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES (NULL, 'city', $1) RETURNING id", [`ce-${run}`])).rows[0].id;
    // One company city per database: use the one a rerun or another test left behind, if any.
    let company = (await admin.query<{ id: string }>(
      "SELECT id FROM memory.namespaces WHERE purpose = 'company' AND parent_id IS NULL")).rows[0]?.id;
    if (!company) {
      company = (await admin.query<{ id: string }>(
        "INSERT INTO memory.namespaces (parent_id, level, slug, purpose) VALUES (NULL, 'city', $1, 'company') RETURNING id",
        [`an2b-${run}`])).rows[0].id;
    }
    const actor = async (kind: string, slug: string) => (await admin.query<{ id: string }>(
      "INSERT INTO memory.actors (kind, slug, display_name) VALUES ($1, $2, $2) RETURNING id", [kind, slug],
    )).rows[0].id;
    owner = await actor("human", `ce-owner-${run}`);
    confirmer = await actor("human", `ce-confirmer-${run}`);
    nobody = await actor("human", `ce-nobody-${run}`);
    agent = await actor("agent", `ce-agent-${run}`);
    await admin.query("INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ($1, $2, $3)",
      [confirmerEmail, company, confirmer]);

    const appUrl = new URL(ADMIN_URL!);
    appUrl.username = "engramport_app";
    appUrl.password = "engramport-test-only";
    appPool = new pg.Pool({ connectionString: appUrl.toString() });

    // The confirmer's role over this test's city, accepted with their own sign-in.
    const role = (await admin.query<{ id: string }>(
      "INSERT INTO memory.cell_erasure_confirmers (actor_id, scope_namespace_id, expires_at) VALUES ($1, $2, now() + interval '30 days') RETURNING id",
      [confirmer, cityId])).rows[0].id;
    let s = await signInWithGoogle(admin, confirmerEmail);
    const terms = (await appPool.query<{ terms_sha256: string }>(
      "SELECT terms_sha256 FROM memory.pending_confirmer_roles($1, $2) WHERE role_id = $3", [s.userId, s.sessionId, role])).rows[0];
    s = await signInWithGoogle(admin, confirmerEmail);
    await appPool.query("SELECT memory.decide_confirmer_role($1, $2, $3, 'accept', $4)",
      [s.userId, s.sessionId, role, terms.terms_sha256]);

    const app = createHttpApp({
      apiUrl: "http://stub",
      namespace: "test",
      authenticate: async () => false,
      cellErasure: createCellErasureRouter({ publicUrl: ISSUER, pepper, db: appPool, identity, perMinute: 1000 }),
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
  const body = (html: string) => /<body>(.*)<\/body>/s.exec(html)?.[1];

  /** Open a link and sign in as `email`: the page it lands on, its cookie and token. */
  async function signInAt(path: string, email: string) {
    nextEmail = email;
    const a = await fetch(`${base}${path}`, { redirect: "manual" });
    assert.equal(a.status, 302);
    const idp = new URL(a.headers.get("location")!);
    assert.equal(idp.host, "idp.test");
    assert.equal(idp.searchParams.get("return"), `${ISSUER}/cell-erasure/callback`);
    const c = await fetch(`${base}/cell-erasure/callback?code=${idp.searchParams.get("code")}`, {
      redirect: "manual", headers: { Cookie: cookieOf(a)! },
    });
    const html = await c.text();
    return { status: c.status, html, cookie: cookieOf(c), csrf: csrfOf(html), headers: c.headers };
  }

  /** The owner starts a whole-cell erasure of `cell` through the pages: its request id. */
  async function start(cell: Cell, email = ownerEmail, reason = "owner_request"): Promise<string> {
    const r = await signInAt(`/cell-erasure/start/${cell.id}`, email);
    assert.equal(r.status, 200, r.html);
    const c = await post("/cell-erasure/start/review", r.cookie, { csrf: r.csrf!, action: "start", reason });
    const html = await c.text();
    assert.equal(c.status, 200, html);
    const done = await post("/cell-erasure/start/confirm", cookieOf(c), { csrf: csrfOf(html)!, choice: "confirm" });
    const doneHtml = await done.text();
    assert.equal(done.status, 200, doneHtml);
    const id = new RegExp(`${ISSUER}/cell-erasure/([0-9a-f-]{36})`).exec(doneHtml)?.[1];
    assert.ok(id, doneHtml);
    return id;
  }

  /** The confirmer reviews a request and chooses to erase: the confirmation page, its cookie and token. */
  async function toConfirm(requestId: string) {
    const r = await signInAt(`/cell-erasure/${requestId}`, confirmerEmail);
    assert.equal(r.status, 200, r.html);
    const c = await post("/cell-erasure/review", r.cookie, { csrf: r.csrf!, action: "erase" });
    const html = await c.text();
    return { status: c.status, html, cookie: cookieOf(c), csrf: csrfOf(html), res: c };
  }

  const requestOf = async (id: string) =>
    (await admin.query<{ state: string; reason: string; confirmed_by_actor_id: string | null }>(
      "SELECT state::text, reason::text, confirmed_by_actor_id FROM memory.cell_erasure_requests WHERE id = $1", [id])).rows[0];
  const liveIn = async (cell: Cell) =>
    (await admin.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM memory.memories WHERE namespace_id = $1 AND status <> 'erased'", [cell.id])).rows[0].n;

  test("the owner starts it, the cell freezes, and a confirmer who sees only counts erases it", async () => {
    const cell = await makeCell();
    await remember(cell, "the vault code is <b>9921</b>");
    await remember(cell, "the board meets on thursdays");

    const r = await signInAt(`/cell-erasure/start/${cell.id}`, ownerEmail);
    assert.equal(r.status, 200, r.html);
    assert.match(r.html, /Erase this whole cell\?/);
    assert.ok(r.html.includes(cell.path));
    assert.match(r.html, /<dt>Memories, every version<\/dt><dd>2<\/dd>/);
    assert.ok(!r.html.includes("vault code") && !r.html.includes("thursdays"), "the owner's preview is counts only");
    assert.match(r.headers.get("content-security-policy")!, /default-src 'none'/);
    assert.equal(r.headers.get("x-frame-options"), "DENY");
    assert.match(r.headers.get("set-cookie")!, /__Host-ep_cell=[^;]+; Path=\/; Max-Age=600; HttpOnly; Secure; SameSite=Lax/);

    const c = await post("/cell-erasure/start/review", r.cookie, { csrf: r.csrf!, action: "start", reason: "legal" });
    const html = await c.text();
    assert.equal(c.status, 200, html);
    assert.match(html, /Freeze the cell and send it for confirmation\?/);
    assert.match(html, /A legal requirement/);
    assert.equal((await admin.query("SELECT 1 FROM memory.cell_erasure_requests WHERE namespace_id = $1", [cell.id])).rows.length,
      0, "nothing is started before the owner confirms");
    const done = await post("/cell-erasure/start/confirm", cookieOf(c), { csrf: csrfOf(html)!, choice: "confirm" });
    const doneHtml = await done.text();
    assert.equal(done.status, 200, doneHtml);
    assert.match(doneHtml, /Waiting for confirmation/);
    const id = new RegExp(`${ISSUER}/cell-erasure/([0-9a-f-]{36})`).exec(doneHtml)![1];
    assert.deepEqual(await requestOf(id), { state: "proposed", reason: "legal", confirmed_by_actor_id: null });
    assert.match(done.headers.get("set-cookie")!, /__Host-ep_cell=; Path=\/; Max-Age=0/);
    await assert.rejects(remember(cell, "written while frozen"), /frozen|waiting/i, "the cell is frozen");

    // Starting again while it waits shows that, with nothing to press.
    const again = await signInAt(`/cell-erasure/start/${cell.id}`, ownerEmail);
    assert.match(again.html, /Already waiting for confirmation/);
    assert.equal(again.csrf, undefined);

    const v = await signInAt(`/cell-erasure/${id}`, confirmerEmail);
    assert.equal(v.status, 200, v.html);
    assert.match(v.html, /Confirm this whole-cell erasure\?/);
    assert.match(v.html, /A legal requirement/);
    assert.ok(v.html.includes(`ce-owner-${run}`), "the confirmer sees who started it");
    assert.ok(!v.html.includes("vault code") && !v.html.includes("thursdays"), "the confirmer sees no content");
    const k = await post("/cell-erasure/review", v.cookie, { csrf: v.csrf!, action: "erase" });
    const kHtml = await k.text();
    assert.equal(k.status, 200, kHtml);
    assert.match(kHtml, /Erase it\?/);
    const visit = openCellErasureVisit(pepper, k.headers.getSetCookie()[0].split(";")[0].split("=")[1]);
    assert.equal(visit?.step, "confirmer-confirm");
    const secret = visit?.step === "confirmer-confirm" ? visit.secret : "";
    assert.match(secret, /^[0-9a-f]{64}$/);
    assert.ok(!kHtml.includes(secret), "the challenge secret never reaches the page");
    assert.equal(await liveIn(cell), 2, "nothing is erased before the confirmation");

    const fin = await post("/cell-erasure/confirm", cookieOf(k), { csrf: csrfOf(kHtml)!, choice: "confirm" });
    const finHtml = await fin.text();
    assert.equal(fin.status, 200, finHtml);
    assert.match(finHtml, /Cell erased/);
    assert.match(finHtml, /<dt>Memory versions erased<\/dt><dd>2<\/dd>/);
    assert.equal(await liveIn(cell), 0);
    const req = await requestOf(id);
    assert.equal(req.state, "completed");
    assert.equal(req.confirmed_by_actor_id, confirmer);
    assert.ok(signedOut.length >= 3, "each Supabase session is ended");

    // The link, opened again, has nothing left to confirm.
    const later = await signInAt(`/cell-erasure/${id}`, confirmerEmail);
    assert.match(later.html, /not waiting for confirmation/);
    assert.equal(later.csrf, undefined);
  });

  test("replaying the confirmation erases nothing more", async () => {
    const cell = await makeCell();
    await remember(cell, "replay check");
    const id = await start(cell);
    const c = await toConfirm(id);
    assert.equal((await post("/cell-erasure/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" })).status, 200);
    const again = await post("/cell-erasure/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" });
    assert.equal(again.status, 409);
    assert.match(await again.text(), /already used|no longer open/);
  });

  test("whoever started it can't confirm it, even holding the role", async () => {
    // The confirmer owns this cell too, and starts its erasure.
    const cell = await makeCell(confirmer, confirmerEmail);
    await remember(cell, "self confirm check");
    const id = await start(cell, confirmerEmail);
    const v = await signInAt(`/cell-erasure/${id}`, confirmerEmail);
    assert.equal(v.status, 403);
    assert.match(v.html, /different person must confirm/);
    assert.equal(v.csrf, undefined);
    assert.equal((await requestOf(id)).state, "proposed");
  });

  test("someone without the role sees the same page as for a request that doesn't exist, and can't start one", async () => {
    const cell = await makeCell();
    await remember(cell, "only the confirmer confirms");
    const id = await start(cell);
    const theirs = await signInAt(`/cell-erasure/${id}`, nobodyEmail);
    const missing = await signInAt("/cell-erasure/00000000-0000-7000-8000-00000000dead", nobodyEmail);
    assert.equal(theirs.status, 403);
    assert.equal(missing.status, 403);
    assert.equal(body(theirs.html), body(missing.html));
    assert.equal(theirs.csrf, undefined);

    const other = await makeCell();
    const notOwner = await signInAt(`/cell-erasure/start/${other.id}`, nobodyEmail);
    assert.equal(notOwner.status, 403);
    assert.match(notOwner.html, /not its owner/);
    assert.equal(notOwner.csrf, undefined);
  });

  test("leaving at any step changes nothing", async () => {
    const cell = await makeCell();
    await remember(cell, "left alone");
    const r = await signInAt(`/cell-erasure/start/${cell.id}`, ownerEmail);
    assert.match(await (await post("/cell-erasure/start/review", r.cookie, { csrf: r.csrf!, action: "cancel", reason: "legal" })).text(),
      /Nothing was changed/);
    const r2 = await signInAt(`/cell-erasure/start/${cell.id}`, ownerEmail);
    assert.match(await (await post("/cell-erasure/start/review", r2.cookie, { csrf: r2.csrf!, action: "start", reason: "toString" })).text(),
      /Nothing was changed/, "a reason not on the list starts nothing");
    const r3 = await signInAt(`/cell-erasure/start/${cell.id}`, ownerEmail);
    const c3 = await post("/cell-erasure/start/review", r3.cookie, { csrf: r3.csrf!, action: "start", reason: "legal" });
    const h3 = await c3.text();
    assert.match(await (await post("/cell-erasure/start/confirm", cookieOf(c3), { csrf: csrfOf(h3)!, choice: "cancel" })).text(),
      /Nothing was changed/);
    assert.equal((await admin.query("SELECT 1 FROM memory.cell_erasure_requests WHERE namespace_id = $1", [cell.id])).rows.length, 0);

    const id = await start(cell);
    const v = await signInAt(`/cell-erasure/${id}`, confirmerEmail);
    assert.match(await (await post("/cell-erasure/review", v.cookie, { csrf: v.csrf!, action: "cancel" })).text(), /Nothing was erased/);
    const c = await toConfirm(id);
    assert.match(await (await post("/cell-erasure/confirm", c.cookie, { csrf: c.csrf!, choice: "cancel" })).text(), /Nothing was erased/);
    assert.equal((await requestOf(id)).state, "proposed");
    assert.equal(await liveIn(cell), 1);
  });

  test("without the visit's own cookie and token nothing can be posted, and another page's visit is no way in", async () => {
    const cell = await makeCell();
    await remember(cell, "forged cell posts");
    const r = await signInAt(`/cell-erasure/start/${cell.id}`, ownerEmail);
    const fields = { csrf: r.csrf!, action: "start", reason: "legal" };
    assert.equal((await post("/cell-erasure/start/review", undefined, fields)).status, 400);
    assert.equal((await post("/cell-erasure/start/review", r.cookie, { ...fields, csrf: "wrong" })).status, 400);
    assert.equal((await post("/cell-erasure/start/confirm", r.cookie, { csrf: r.csrf!, choice: "confirm" })).status, 400,
      "the owner's review step can't skip its confirmation");
    assert.equal((await post("/cell-erasure/review", r.cookie, { csrf: r.csrf!, action: "erase" })).status, 400,
      "an owner's visit can't take a confirmer's step");
    // A restore visit's cookie, renamed to this page's, opens nothing here.
    const restore = await fetch(`${base}/restore/00000000-0000-7000-8000-00000000beef`, { redirect: "manual" });
    const value = restore.headers.getSetCookie()[0].split(";")[0].split("=").slice(1).join("=");
    assert.equal((await fetch(`${base}/cell-erasure/callback?code=x`, { headers: { Cookie: `__Host-ep_cell=${value}` } })).status, 400);
    assert.equal((await admin.query("SELECT 1 FROM memory.cell_erasure_requests WHERE namespace_id = $1", [cell.id])).rows.length, 0);
  });

  test("a bad link starts no sign-in, and a callback with no visit is refused", async () => {
    for (const path of ["/cell-erasure/not-a-request", "/cell-erasure/start/not-a-cell"]) {
      const bad = await fetch(`${base}${path}`, { redirect: "manual" });
      assert.equal(bad.status, 404);
      assert.equal(bad.headers.getSetCookie().length, 0);
    }
    assert.equal((await fetch(`${base}/cell-erasure/callback?code=abc`, { redirect: "manual" })).status, 400);
  });
});
