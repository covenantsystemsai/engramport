/**
 * The grant page over HTTP, the way an owner uses it: open the link, sign in
 * with Google (stood in for), type the recipient's email, pick the power and how
 * long, confirm. Same database rules as store.pg.test.ts: needs
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
import { createGrantRouter, openGrantVisit } from "../src/grant.ts";
import { createAcceptRouter } from "../src/accept.ts";
import type { IdentityProvider } from "../src/oauth.ts";
import { createAuthStub, signInWithGoogle } from "./support/auth-stub.ts";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const ISSUER = "https://mcp.test";
const s256 = (v: string) => createHash("sha256").update(v).digest("base64url");

describe("grant page over http", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const pepper = randomBytes(32);
  const ownerEmail = `gp-owner-${run}@example.com`;
  const memberEmail = `gp-member-${run}@example.com`;
  const limitedEmail = `gp-limited-${run}@example.com`;
  const outsiderEmail = `gp-outsider-${run}@example.com`;
  let admin: pg.Pool;
  let appPool: pg.Pool;
  let server: HttpServer;
  let base: string;
  let cellId: string;
  let cellPath: string;
  let owner: string;
  let member: string;
  let outsider: string;

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

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await createAuthStub(admin);
    await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    const ns = async (slug: string, level: string, parent: string | null) =>
      (await admin.query<{ id: string; path: string }>(
        "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, $2, $3) RETURNING id, path", [parent, level, slug],
      )).rows[0];
    const city = await ns(`gp-${run}`, "city", null);
    const tower = await ns("tower", "tower", city.id);
    const cell = await ns("cell", "cell", tower.id);
    const other = await ns("other", "cell", tower.id);
    cellId = cell.id;
    cellPath = cell.path;
    const actor = async (slug: string) => (await admin.query<{ id: string }>(
      "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', $1, $1) RETURNING id", [slug])).rows[0].id;
    owner = await actor(`gp-owner-${run}`);
    member = await actor(`gp-member-${run}`);
    const limited = await actor(`gp-limited-${run}`);
    outsider = await actor(`gp-outsider-${run}`);
    await admin.query(
      "INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ($1, $4, $5), ($2, $4, $6), ($3, $4, $7), ($8, $9, $10)",
      [ownerEmail, memberEmail, limitedEmail, cell.id, owner, member, limited, outsiderEmail, other.id, outsider]);

    const appUrl = new URL(ADMIN_URL!);
    appUrl.username = "engramport_app";
    appUrl.password = "engramport-test-only";
    appPool = new pg.Pool({ connectionString: appUrl.toString() });

    // The owner's authority, which may be passed on, and a limited one that may not, each accepted the real way.
    for (const [who, email, canDelegate] of [[owner, ownerEmail, true], [limited, limitedEmail, false]] as const) {
      const id = (await admin.query<{ id: string }>(
        "INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, can_delegate) VALUES ($1, $2, 'cell_knowledge', $3) RETURNING id",
        [who, cell.id, canDelegate])).rows[0].id;
      const s = await signInWithGoogle(admin, email);
      const sha = (await appPool.query<{ grant_sha256: string }>(
        "SELECT grant_sha256 FROM memory.pending_authority_grants($1, $2) WHERE authority_id = $3", [s.userId, s.sessionId, id])).rows[0];
      await appPool.query("SELECT memory.decide_approval_authority($1, $2, $3, 'accept', $4)", [s.userId, s.sessionId, id, sha.grant_sha256]);
    }

    const app = createHttpApp({
      apiUrl: "http://stub",
      namespace: "test",
      authenticate: async () => false,
      grant: createGrantRouter({ publicUrl: ISSUER, pepper, db: appPool, identity, perMinute: 1000 }),
      accept: createAcceptRouter({ publicUrl: ISSUER, pepper, db: appPool, identity, perMinute: 1000 }),
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
  async function signInAt(path: string, email = ownerEmail) {
    nextEmail = email;
    const a = await fetch(`${base}${path}`, { redirect: "manual" });
    assert.equal(a.status, 302);
    const idp = new URL(a.headers.get("location")!);
    const back = new URL(idp.searchParams.get("return")!).pathname;
    const c = await fetch(`${base}${back}?code=${idp.searchParams.get("code")}`, {
      redirect: "manual", headers: { Cookie: cookieOf(a)! },
    });
    const html = await c.text();
    return { status: c.status, html, cookie: cookieOf(c), csrf: csrfOf(html), headers: c.headers, returnTo: idp.searchParams.get("return") };
  }

  /** The owner fills the form: the confirmation page, its cookie and token. */
  async function toConfirm(email: string, power = "export", days = "30") {
    const f = await signInAt(`/grant/${cellId}`);
    assert.equal(f.status, 200, f.html);
    const c = await post("/grant/review", f.cookie, { csrf: f.csrf!, action: "review", email, power, days });
    const html = await c.text();
    return { status: c.status, html, cookie: cookieOf(c), csrf: csrfOf(html), res: c };
  }
  /** The owner makes the offer: the last page. */
  async function offer(email: string, power = "export", days = "30") {
    const c = await toConfirm(email, power, days);
    assert.equal(c.status, 200, c.html);
    const done = await post("/grant/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" });
    return { status: done.status, html: await done.text(), res: done };
  }
  const grantsTo = async (who: string) =>
    (await admin.query<{ power: string; days: number; granted_by_actor_id: string; accepted_at: Date | null }>(
      `SELECT power::text, round(extract(epoch FROM expires_at - created_at) / 86400)::int AS days, granted_by_actor_id, accepted_at
       FROM memory.data_grants WHERE actor_id = $1 ORDER BY created_at`, [who])).rows;

  test("the owner types a member's email, confirms, and the member finds the offer waiting", async () => {
    const f = await signInAt(`/grant/${cellId}`);
    assert.equal(f.status, 200, f.html);
    assert.equal(f.returnTo, `${ISSUER}/grant/callback`);
    assert.match(f.html, /Offer a grant/);
    assert.ok(f.html.includes(cellPath));
    assert.ok(!f.html.includes(memberEmail) && !f.html.includes(`gp-member-${run}`), "the page lists no members");
    assert.match(f.headers.get("content-security-policy")!, /default-src 'none'/);
    assert.equal(f.headers.get("x-frame-options"), "DENY");
    assert.match(f.headers.get("set-cookie")!, /__Host-ep_grant=[^;]+; Path=\/; Max-Age=600; HttpOnly; Secure; SameSite=Lax/);

    const c = await post("/grant/review", f.cookie, { csrf: f.csrf!, action: "review", email: `  ${memberEmail.toUpperCase()} `,
                                                     power: "export", days: "30" });
    const html = await c.text();
    assert.equal(c.status, 200, html);
    assert.match(html, /Make this offer\?/);
    assert.ok(html.includes(memberEmail), "the owner's own typing is shown back, tidied");
    assert.equal(openGrantVisit(pepper, c.headers.getSetCookie()[0].split(";")[0].split("=")[1])?.step, "confirm");
    assert.equal((await grantsTo(member)).length, 0, "nothing is offered before the confirmation");

    const done = await post("/grant/confirm", cookieOf(c), { csrf: csrfOf(html)!, choice: "confirm" });
    const doneHtml = await done.text();
    assert.equal(done.status, 200, doneHtml);
    assert.match(doneHtml, /Offer recorded/);
    assert.ok(doneHtml.includes(`${ISSUER}/accept`));
    assert.deepEqual(await grantsTo(member), [{ power: "export", days: 30, granted_by_actor_id: owner, accepted_at: null }]);
    assert.match(done.headers.get("set-cookie")!, /__Host-ep_grant=; Path=\/; Max-Age=0/);
    assert.ok(signedOut.length > 0, "the Supabase session is ended");

    const waiting = await signInAt("/accept", memberEmail);
    assert.ok(waiting.html.includes(`Export everything in ${cellPath}`), "the member sees it on the acceptance page");
  });

  test("an address that is not another member's gets the same page and no grant", async () => {
    const memberPage = await offer(memberEmail, "erase", "7");
    const same = (html: string, email: string) => body(html)!.replaceAll(email, "EMAIL");
    for (const email of [outsiderEmail, `nobody-${run}@nowhere.test`, ownerEmail]) {
      const r = await offer(email, "erase", "7");
      assert.equal(r.status, memberPage.status);
      assert.equal(same(r.html, email), same(memberPage.html, memberEmail), `${email} reads the same as a member`);
    }
    assert.equal((await grantsTo(outsider)).length, 0);
    assert.equal((await grantsTo(owner)).length, 0);
    assert.equal((await grantsTo(member)).filter((g) => g.power === "erase").length, 1);
  });

  test("only an owner who may pass authority on gets the form", async () => {
    const r = await signInAt(`/grant/${cellId}`, limitedEmail);
    assert.equal(r.status, 403);
    assert.match(r.html, /may delegate/);
    assert.equal(r.csrf, undefined);
    const missing = await signInAt("/grant/00000000-0000-7000-8000-00000000dead", limitedEmail);
    assert.equal(body(missing.html), body(r.html), "a namespace that doesn't exist reads the same");
  });

  test("an address or choice the page didn't offer is refused with nothing offered", async () => {
    const before = (await grantsTo(member)).length;
    for (const [email, power, days] of [["not-an-address", "export", "30"], [memberEmail, "toString", "30"],
                                       [memberEmail, "delete", "30"], [memberEmail, "export", "45"]]) {
      const c = await toConfirm(email, power, days);
      assert.equal(c.status, 400, `${email} ${power} ${days}`);
      assert.match(c.html, /Nothing was offered/);
    }
    assert.equal((await grantsTo(member)).length, before);
  });

  test("replaying the confirmation offers nothing more, and going back offers nothing", async () => {
    const before = (await grantsTo(member)).length;
    const c = await toConfirm(memberEmail);
    assert.equal((await post("/grant/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" })).status, 200);
    const again = await post("/grant/confirm", c.cookie, { csrf: c.csrf!, choice: "confirm" });
    assert.equal(again.status, 409);
    assert.match(await again.text(), /already used/);
    assert.equal((await grantsTo(member)).length, before + 1);

    const f = await signInAt(`/grant/${cellId}`);
    assert.match(await (await post("/grant/review", f.cookie, { csrf: f.csrf!, action: "cancel" })).text(), /Nothing was offered/);
    const c2 = await toConfirm(memberEmail);
    assert.match(await (await post("/grant/confirm", c2.cookie, { csrf: c2.csrf!, choice: "cancel" })).text(), /Nothing was offered/);
    assert.equal((await grantsTo(member)).length, before + 1);
  });

  test("without the visit's own cookie and token nothing can be posted, and another page's visit is no way in", async () => {
    const before = (await grantsTo(member)).length;
    const f = await signInAt(`/grant/${cellId}`);
    const fields = { csrf: f.csrf!, action: "review", email: memberEmail, power: "export", days: "30" };
    assert.equal((await post("/grant/review", undefined, fields)).status, 400);
    assert.equal((await post("/grant/review", f.cookie, { ...fields, csrf: "wrong" })).status, 400);
    assert.equal((await post("/grant/confirm", f.cookie, { csrf: f.csrf!, choice: "confirm" })).status, 400,
      "the form step can't skip its confirmation");
    const acc = await fetch(`${base}/accept`, { redirect: "manual" });
    const value = acc.headers.getSetCookie()[0].split(";")[0].split("=").slice(1).join("=");
    assert.equal((await fetch(`${base}/grant/callback?code=x`, { headers: { Cookie: `__Host-ep_grant=${value}` } })).status, 400);
    assert.equal((await fetch(`${base}/grant/callback?code=abc`, { redirect: "manual" })).status, 400);
    const bad = await fetch(`${base}/grant/not-a-namespace`, { redirect: "manual" });
    assert.equal(bad.status, 404);
    assert.equal(bad.headers.getSetCookie().length, 0);
    assert.equal((await grantsTo(member)).length, before);
  });
});
