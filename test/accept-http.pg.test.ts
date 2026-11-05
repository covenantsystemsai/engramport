/**
 * The acceptance page over HTTP, the way a person uses it: open it, sign in
 * with Google (stood in for), see what was offered to them, pick one to accept
 * or decline, confirm. Same database rules as store.pg.test.ts: needs
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
import { createAcceptRouter, openAcceptVisit } from "../src/accept.ts";
import { createRestoreRouter } from "../src/restore.ts";
import type { IdentityProvider } from "../src/oauth.ts";
import { createAuthStub, signInWithGoogle } from "./support/auth-stub.ts";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const ISSUER = "https://mcp.test";
const s256 = (v: string) => createHash("sha256").update(v).digest("base64url");

describe("acceptance page over http", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const pepper = randomBytes(32);
  const ownerEmail = `ac-owner-${run}@example.com`;
  let admin: pg.Pool;
  let appPool: pg.Pool;
  let server: HttpServer;
  let base: string;
  let cityId: string;
  let companyId: string;
  let owner: string;
  let people = 0;

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

  const actor = async (kind: string, slug: string) => (await admin.query<{ id: string }>(
    "INSERT INTO memory.actors (kind, slug, display_name) VALUES ($1, $2, $2) RETURNING id", [kind, slug],
  )).rows[0].id;
  const member = (email: string, ns: string, who: string) =>
    admin.query("INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ($1, $2, $3)", [email, ns, who]);

  interface Person { id: string; email: string; cellId: string; cellPath: string; authority: string; grant: string; role: string }

  /**
   * A person in a fresh cell, belonging to AN2B, with one of each offer waiting
   * for them: approval authority from the admin, an export grant from the
   * cell's owner, and the confirmer role.
   */
  async function person(): Promise<Person> {
    const n = ++people;
    const email = `ac-holder${n}-${run}@an2b.test`;
    const id = await actor("human", `ac-holder${n}-${run}`);
    const tower = (await admin.query<{ id: string }>(
      "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, 'tower', $2) RETURNING id", [cityId, `t${n}`])).rows[0];
    const cell = (await admin.query<{ id: string; path: string }>(
      "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, 'cell', 'cell') RETURNING id, path", [tower.id])).rows[0];
    await member(email, cell.id, id);
    await member(email, companyId, id);
    await member(ownerEmail, cell.id, owner);

    // The owner's own authority over the cell, which may be passed on, accepted with their own sign-in.
    const ownerAuth = (await admin.query<{ id: string }>(
      "INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, can_delegate) VALUES ($1, $2, 'cell_knowledge', true) RETURNING id",
      [owner, cell.id])).rows[0].id;
    let s = await signInWithGoogle(admin, ownerEmail);
    const offered = (await appPool.query<{ grant_sha256: string }>(
      "SELECT grant_sha256 FROM memory.pending_authority_grants($1, $2) WHERE authority_id = $3",
      [s.userId, s.sessionId, ownerAuth])).rows[0];
    await appPool.query("SELECT memory.decide_approval_authority($1, $2, $3, 'accept', $4)",
      [s.userId, s.sessionId, ownerAuth, offered.grant_sha256]);
    s = await signInWithGoogle(admin, ownerEmail);
    const grant = (await appPool.query<{ id: string }>(
      "SELECT memory.grant_data_power($1, $2, $3, $4, 'export', now() + interval '30 days') AS id",
      [s.userId, s.sessionId, cell.id, id])).rows[0].id;

    const authority = (await admin.query<{ id: string }>(
      "INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope) VALUES ($1, $2, 'cell_knowledge') RETURNING id",
      [id, cell.id])).rows[0].id;
    const role = (await admin.query<{ id: string }>(
      "INSERT INTO memory.cell_erasure_confirmers (actor_id, scope_namespace_id, expires_at) VALUES ($1, $2, now() + interval '30 days') RETURNING id",
      [id, cityId])).rows[0].id;
    return { id, email, cellId: cell.id, cellPath: cell.path, authority, grant, role };
  }

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await createAuthStub(admin);
    await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    cityId = (await admin.query<{ id: string }>(
      "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES (NULL, 'city', $1) RETURNING id", [`ac-${run}`])).rows[0].id;
    // One company city per database: use the one a rerun or another test left behind, if any.
    companyId = (await admin.query<{ id: string }>(
      "SELECT id FROM memory.namespaces WHERE purpose = 'company' AND parent_id IS NULL")).rows[0]?.id;
    if (!companyId) {
      companyId = (await admin.query<{ id: string }>(
        "INSERT INTO memory.namespaces (parent_id, level, slug, purpose) VALUES (NULL, 'city', $1, 'company') RETURNING id",
        [`an2b-${run}`])).rows[0].id;
    }
    owner = await actor("human", `ac-owner-${run}`);

    const appUrl = new URL(ADMIN_URL!);
    appUrl.username = "engramport_app";
    appUrl.password = "engramport-test-only";
    appPool = new pg.Pool({ connectionString: appUrl.toString() });

    const app = createHttpApp({
      apiUrl: "http://stub",
      namespace: "test",
      authenticate: async () => false,
      accept: createAcceptRouter({ publicUrl: ISSUER, pepper, db: appPool, identity, perMinute: 1000 }),
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
  /** The hidden fields of the offer whose id is `id`, as the list page gave them. */
  const offerOf = (html: string, id: string) => {
    const m = new RegExp(`name="kind" value="([a-z]+)"><input type="hidden" name="id" value="${id}">` +
      `<input type="hidden" name="sha" value="([0-9a-f]{64})">`).exec(html);
    return m ? { kind: m[1], id, sha: m[2] } : undefined;
  };

  /** Open the page and sign in: the list page, its cookie and token. */
  async function toList(email: string) {
    nextEmail = email;
    const a = await fetch(`${base}/accept`, { redirect: "manual" });
    assert.equal(a.status, 302);
    const idp = new URL(a.headers.get("location")!);
    assert.equal(idp.host, "idp.test");
    assert.equal(idp.searchParams.get("return"), `${ISSUER}/accept/callback`);
    const c = await fetch(`${base}/accept/callback?code=${idp.searchParams.get("code")}`, {
      redirect: "manual", headers: { Cookie: cookieOf(a)! },
    });
    const html = await c.text();
    return { status: c.status, html, cookie: cookieOf(c), csrf: csrfOf(html), headers: c.headers };
  }

  /** Pick one offer and a decision: the confirmation page, its cookie and token. */
  async function toConfirm(email: string, id: string, decision: "accept" | "reject") {
    const l = await toList(email);
    assert.equal(l.status, 200, l.html);
    const o = offerOf(l.html, id);
    assert.ok(o, `offer ${id} is listed`);
    const c = await post("/accept/review", l.cookie, { csrf: l.csrf!, ...o, decision });
    const html = await c.text();
    return { status: c.status, html, cookie: cookieOf(c), csrf: csrfOf(html), res: c };
  }

  const decide = async (email: string, id: string, decision: "accept" | "reject") => {
    const c = await toConfirm(email, id, decision);
    assert.equal(c.status, 200, c.html);
    return post("/accept/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" });
  };

  test("a person sees each offer's terms, and accepts the confirmer role with a second confirmation", async () => {
    const p = await person();
    const l = await toList(p.email);
    assert.equal(l.status, 200, l.html);
    assert.match(l.html, /Waiting for your decision/);
    assert.ok(l.html.includes(`Approve memories in ${p.cellPath}`));
    assert.ok(l.html.includes(`Export everything in ${p.cellPath}`));
    assert.match(l.html, /Confirm whole-cell erasures under ac-/);
    assert.match(l.html, /doesn&#39;t let you read any memory|doesn't let you read any memory/);
    assert.ok(l.html.includes(`ac-owner-${run}`), "the export grant names who gave it");
    for (const id of [p.authority, p.grant, p.role]) assert.ok(offerOf(l.html, id), `offer ${id} is listed`);
    assert.match(l.headers.get("content-security-policy")!, /default-src 'none'/);
    assert.equal(l.headers.get("x-frame-options"), "DENY");
    assert.match(l.headers.get("set-cookie")!, /__Host-ep_accept=[^;]+; Path=\/; Max-Age=600; HttpOnly; Secure; SameSite=Lax/);

    const c = await post("/accept/review", l.cookie, { csrf: l.csrf!, ...offerOf(l.html, p.role)!, decision: "accept" });
    const html = await c.text();
    assert.equal(c.status, 200, html);
    assert.match(html, /Accept this\?/);
    assert.equal(openAcceptVisit(pepper, c.headers.getSetCookie()[0].split(";")[0].split("=")[1])?.step, "confirm");
    const undecided = (await admin.query<{ accepted_at: Date | null }>(
      "SELECT accepted_at FROM memory.cell_erasure_confirmers WHERE id = $1", [p.role])).rows[0];
    assert.equal(undecided.accepted_at, null, "nothing is decided before the confirmation");

    const done = await post("/accept/confirm", cookieOf(c), { csrf: csrfOf(html)!, choice: "confirm" });
    const doneHtml = await done.text();
    assert.equal(done.status, 200, doneHtml);
    assert.match(doneHtml, /Accepted/);
    assert.ok((await admin.query("SELECT 1 FROM memory.cell_erasure_confirmers WHERE id = $1 AND accepted_at IS NOT NULL",
      [p.role])).rows.length === 1);
    assert.match(done.headers.get("set-cookie")!, /__Host-ep_accept=; Path=\/; Max-Age=0/);
    assert.ok(signedOut.length > 0, "the Supabase session is ended");

    const again = await toList(p.email);
    assert.equal(offerOf(again.html, p.role), undefined, "a decided offer is no longer listed");
    assert.ok(offerOf(again.html, p.authority) && offerOf(again.html, p.grant));
  });

  test("approval authority is accepted and an export grant declined, one per sign-in", async () => {
    const p = await person();
    assert.equal((await decide(p.email, p.authority, "accept")).status, 200);
    const d = (await admin.query<{ decision: string }>(
      "SELECT decision FROM memory.approval_authority_decisions WHERE authority_id = $1", [p.authority])).rows[0];
    assert.equal(d.decision, "accept");
    const no = await decide(p.email, p.grant, "reject");
    assert.equal(no.status, 200);
    assert.match(await no.text(), /Declined/);
    const g = (await admin.query<{ accepted_at: Date | null; rejected_at: Date | null }>(
      "SELECT accepted_at, rejected_at FROM memory.data_grants WHERE id = $1", [p.grant])).rows[0];
    assert.equal(g.accepted_at, null);
    assert.ok(g.rejected_at);
  });

  test("replaying the confirmation decides nothing more", async () => {
    const p = await person();
    const c = await toConfirm(p.email, p.grant, "accept");
    assert.equal((await post("/accept/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" })).status, 200);
    const again = await post("/accept/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" });
    assert.equal(again.status, 409);
    assert.match(await again.text(), /already (used|decided)/);
  });

  test("terms other than the ones shown, or an offer made to someone else, are refused with nothing decided", async () => {
    const p = await person();
    const q = await person();
    const l = await toList(p.email);
    const o = offerOf(l.html, p.authority)!;
    const changed = await post("/accept/review", l.cookie, { csrf: l.csrf!, ...o, sha: "a".repeat(64), decision: "accept" });
    assert.equal(changed.status, 409);
    assert.match(await changed.text(), /no longer waiting for you, or its terms changed/);
    // q's offer, posted from p's visit with p's token.
    const l2 = await toList(p.email);
    const theirs = await post("/accept/review", l2.cookie, { csrf: l2.csrf!, kind: "authority", id: q.authority,
      sha: (await toList(q.email).then((x) => offerOf(x.html, q.authority)!)).sha, decision: "accept" });
    assert.equal(theirs.status, 409);
    assert.equal((await admin.query("SELECT 1 FROM memory.approval_authority_decisions WHERE authority_id IN ($1, $2)",
      [p.authority, q.authority])).rows.length, 0);
  });

  test("nothing waiting shows that with nothing to press, and going back decides nothing", async () => {
    // A member with nothing offered to them.
    await member(`ac-nobody-${run}@example.com`, cityId, await actor("human", `ac-nobody-${run}`));
    const empty = await toList(`ac-nobody-${run}@example.com`);
    assert.equal(empty.status, 200, empty.html);
    assert.match(empty.html, /Nothing waiting for you/);
    assert.equal(empty.csrf, undefined);

    const p = await person();
    const c = await toConfirm(p.email, p.role, "reject");
    assert.match(c.html, /Decline this\?/);
    const back = await post("/accept/confirm", c.cookie, { csrf: c.csrf!, choice: "cancel" });
    assert.match(await back.text(), /Nothing was decided/);
    assert.ok((await admin.query(
      "SELECT 1 FROM memory.cell_erasure_confirmers WHERE id = $1 AND accepted_at IS NULL AND rejected_at IS NULL", [p.role])).rows.length);
  });

  test("without the visit's own cookie and token nothing can be posted, and another page's visit is no way in", async () => {
    const p = await person();
    const l = await toList(p.email);
    const o = offerOf(l.html, p.role)!;
    const fields = { csrf: l.csrf!, ...o, decision: "accept" };
    assert.equal((await post("/accept/review", undefined, fields)).status, 400);
    assert.equal((await post("/accept/review", l.cookie, { ...fields, csrf: "wrong" })).status, 400);
    assert.equal((await post("/accept/review", l.cookie, { ...fields, kind: "everything" })).status, 400);
    const l2 = await toList(p.email);
    assert.equal((await post("/accept/confirm", l2.cookie, { csrf: l2.csrf!, choice: "confirm" })).status, 400,
      "the list step can't skip its confirmation");
    const restore = await fetch(`${base}/restore/00000000-0000-7000-8000-00000000beef`, { redirect: "manual" });
    const value = restore.headers.getSetCookie()[0].split(";")[0].split("=").slice(1).join("=");
    assert.equal((await fetch(`${base}/accept/callback?code=x`, { headers: { Cookie: `__Host-ep_accept=${value}` } })).status, 400);
    assert.equal((await fetch(`${base}/accept/callback?code=abc`, { redirect: "manual" })).status, 400);
    assert.ok((await admin.query(
      "SELECT 1 FROM memory.cell_erasure_confirmers WHERE id = $1 AND accepted_at IS NULL AND rejected_at IS NULL", [p.role])).rows.length);
  });
});
