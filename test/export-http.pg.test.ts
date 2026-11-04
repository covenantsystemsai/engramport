/**
 * The export page over HTTP, the way a person uses it: open the link, sign in
 * with Google (stood in for), pick a namespace, confirm, download. Same
 * database rules as store.pg.test.ts: needs ENGRAMPORT_TEST_DATABASE_URL
 * pointing at a THROWAWAY database, as a superuser.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { Server as HttpServer } from "node:http";
import pg from "pg";

import { createHttpApp } from "../src/http.ts";
import { createApprovalRouter } from "../src/approve.ts";
import { createExportRouter, exportFileName } from "../src/export.ts";
import type { IdentityProvider } from "../src/oauth.ts";
import { hashKey, mintKey } from "../src/keys.ts";
import { createAuthStub, signInWithGoogle } from "./support/auth-stub.ts";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const ISSUER = "https://mcp.test";
const s256 = (v: string) => createHash("sha256").update(v).digest("base64url");

test("an export file name is made only of safe characters", () => {
  assert.equal(exportFileName("acme/tower/cell", new Date("2026-11-04T10:00:00Z")),
    "engramport-export-acme-tower-cell-2026-11-04.jsonl");
  assert.equal(exportFileName('a"b; c/../x', new Date("2026-11-04T10:00:00Z")), "engramport-export-a-b-c-x-2026-11-04.jsonl");
  assert.equal(exportFileName("///", new Date("2026-11-04T10:00:00Z")), "engramport-export-namespace-2026-11-04.jsonl");
});

describe("export page over http", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const pepper = randomBytes(32);
  const ownerEmail = `xp-owner-${run}@example.com`;
  const nobodyEmail = `xp-nobody-${run}@example.com`;
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

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await createAuthStub(admin);
    await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    const ns = async (slug: string, level: string, parent: string | null) =>
      (await admin.query<{ id: string; path: string }>(
        "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, $2, $3) RETURNING id, path", [parent, level, slug],
      )).rows[0];
    const city = await ns(`xp-${run}`, "city", null);
    const tower = await ns("tower", "tower", city.id);
    const cell = await ns("cell", "cell", tower.id);
    cellId = cell.id;
    cellPath = cell.path;
    const actor = async (kind: string, slug: string) => (await admin.query<{ id: string }>(
      "INSERT INTO memory.actors (kind, slug, display_name) VALUES ($1, $2, $2) RETURNING id", [kind, slug],
    )).rows[0].id;
    const owner = await actor("human", `xp-owner-${run}`);
    const nobody = await actor("human", `xp-nobody-${run}`);
    const agent = await actor("agent", `xp-agent-${run}`);
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
      exportPage: createExportRouter({ publicUrl: ISSUER, pepper, db: appPool, identity, perMinute: 1000, batch: 2 }),
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
  const post = (path: string, cookie: string | undefined, fields: Record<string, string>, signal?: AbortSignal) =>
    fetch(`${base}${path}`, {
      method: "POST", redirect: "manual", signal,
      headers: { ...(cookie ? { Cookie: cookie } : {}), "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields),
    });

  /** Open the link and sign in: the list of namespaces, its cookie and token. */
  async function toPick(email = ownerEmail) {
    nextEmail = email;
    const a = await fetch(`${base}/export`, { redirect: "manual" });
    assert.equal(a.status, 302);
    const idp = new URL(a.headers.get("location")!);
    assert.equal(idp.searchParams.get("return"), `${ISSUER}/export/callback`);
    const c = await fetch(`${base}/export/callback?code=${idp.searchParams.get("code")}`, {
      redirect: "manual", headers: { Cookie: cookieOf(a)! },
    });
    const html = await c.text();
    return { status: c.status, html, cookie: cookieOf(c), csrf: csrfOf(html), headers: c.headers };
  }

  /** Pick the cell: the confirmation page, its cookie and token. */
  async function toConfirm() {
    const p = await toPick();
    assert.equal(p.status, 200, p.html);
    const c = await post("/export/review", p.cookie, { csrf: p.csrf!, action: "pick", namespace: cellId });
    const html = await c.text();
    return { status: c.status, html, cookie: cookieOf(c), csrf: csrfOf(html) };
  }

  const exportsOf = async () =>
    (await admin.query<{ started: boolean; completed: boolean; counts: Record<string, number> | null }>(
      `SELECT started_at IS NOT NULL AS started, completed_at IS NOT NULL AS completed, counts
       FROM memory.exports WHERE namespace_id = $1 ORDER BY issued_at`, [cellId])).rows;

  test("the owner picks the cell, confirms, and downloads everything in it as JSON lines", async () => {
    const a = await remember("export check: the vendor is <Acme>");
    const b = await remember("export check: a second memory");
    const p = await toPick();
    assert.equal(p.status, 200, p.html);
    assert.match(p.html, /Export a namespace/);
    assert.ok(p.html.includes(cellPath));
    assert.match(p.headers.get("set-cookie")!, /__Host-ep_export=[^;]+; Path=\/; Max-Age=600; HttpOnly; Secure; SameSite=Lax/);
    const c = await post("/export/review", p.cookie, { csrf: p.csrf!, action: "pick", namespace: cellId });
    const html = await c.text();
    assert.equal(c.status, 200, html);
    assert.match(html, /isn&#39;t kept anywhere|isn't kept anywhere/);
    assert.equal((await exportsOf()).at(-1)?.started, false, "nothing starts before the confirmation");

    const d = await post("/export/download", cookieOf(c), { csrf: csrfOf(html)!, choice: "confirm" });
    assert.equal(d.status, 200);
    assert.match(d.headers.get("content-type")!, /application\/jsonl/);
    assert.match(d.headers.get("content-disposition")!, /^attachment; filename="engramport-export-xp-[0-9a-f]+-tower-cell-\d{4}-\d{2}-\d{2}\.jsonl"$/);
    assert.equal(d.headers.get("cache-control"), "no-store");
    const lines = (await d.text()).trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    assert.equal(lines[0].type, "export");
    assert.equal(lines[0].namespace, cellPath);
    const memories = lines.filter((l) => l.type === "memory");
    assert.deepEqual(memories.map((m) => m.id).sort(), [a, b].sort());
    assert.equal(memories.find((m) => m.id === a)!.content, "export check: the vendor is <Acme>");
    assert.equal((memories[0].provenance as { written_by: string }).written_by, `xp-agent-${run}`);
    const rec = (await exportsOf()).at(-1)!;
    assert.deepEqual([rec.started, rec.completed, rec.counts?.memories], [true, true, 2]);
    assert.ok(signedOut.length > 0, "the Supabase session is ended");

    const again = await post("/export/download", cookieOf(c), { csrf: csrfOf(html)!, choice: "confirm" });
    assert.equal(again.status, 409);
    assert.match(await again.text(), /already used/);
  });

  test("a download that breaks off is not recorded as delivered, and lets go of its connection", async () => {
    // Enough rows that the stream fills the socket and has to wait for the browser.
    for (let i = 0; i < 800; i++) await remember(`export check: filler ${i} ${"x".repeat(30000)}`);
    const c = await toConfirm();
    const appSessions = async (state: string) => (await admin.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM pg_stat_activity
       WHERE usename = 'engramport_app' AND state = $1 AND query LIKE 'FETCH%'`, [state])).rows[0].n;
    // A browser that starts the download and then stops reading.
    const body = new URLSearchParams({ csrf: c.csrf!, choice: "confirm" }).toString();
    const req = http.request(`${base}/export/download`, {
      method: "POST",
      headers: { Cookie: c.cookie!, "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(body) },
    });
    const response = await new Promise<http.IncomingMessage>((resolve, reject) => {
      req.on("response", resolve);
      req.on("error", reject);
      req.end(body);
    });
    assert.equal(response.statusCode, 200);
    response.pause();
    // Wait until the stream is held up on the browser, between fetches, inside its transaction.
    let waiting = 0;
    for (let i = 0; i < 50 && !waiting; i++) {
      await new Promise((r) => setTimeout(r, 100));
      waiting = await appSessions("idle in transaction");
    }
    assert.equal(waiting, 1, "the stream is waiting on the browser");
    req.destroy();
    response.destroy();
    let stuck = 1;
    for (let i = 0; i < 50 && stuck; i++) {
      await new Promise((r) => setTimeout(r, 100));
      stuck = await appSessions("idle in transaction");
    }
    assert.equal(stuck, 0, "the transaction is rolled back and the connection let go");
    const rec = (await exportsOf()).at(-1)!;
    assert.deepEqual([rec.started, rec.completed], [true, false], "started, but not delivered");
  });

  test("a revoked grant exports nothing, even after the confirmation page", async () => {
    const email = `xp-owner2-${run}@example.com`;
    const owner2 = (await admin.query<{ id: string }>(
      "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', $1, $1) RETURNING id", [`xp-owner2-${run}`])).rows[0].id;
    await admin.query("INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ($1, $2, $3)", [email, cellId, owner2]);
    const grant = (await admin.query<{ id: string }>(
      "INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope) VALUES ($1, $2, 'cell_knowledge') RETURNING id",
      [owner2, cellId])).rows[0].id;
    const s = await signInWithGoogle(admin, email);
    const offered = (await appPool.query<{ grant_sha256: string }>(
      "SELECT grant_sha256 FROM memory.pending_authority_grants($1, $2) WHERE authority_id = $3",
      [s.userId, s.sessionId, grant])).rows[0];
    await appPool.query("SELECT memory.decide_approval_authority($1, $2, $3, 'accept', $4)",
      [s.userId, s.sessionId, grant, offered.grant_sha256]);
    const p = await toPick(email);
    const c = await post("/export/review", p.cookie, { csrf: p.csrf!, action: "pick", namespace: cellId });
    const html = await c.text();
    await admin.query("UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'owner_left' WHERE id = $1", [grant]);
    const d = await post("/export/download", cookieOf(c), { csrf: csrfOf(html)!, choice: "confirm" });
    assert.equal(d.status, 409);
    const text = await d.text();
    assert.match(text, /no longer valid/);
    assert.ok(!text.includes("export check"), "no stored text on the refusal page");
  });

  test("someone without an owner's grant is offered nothing, and can't name a namespace", async () => {
    const p = await toPick(nobodyEmail);
    assert.equal(p.status, 403);
    assert.match(p.html, /nothing you can export/);
    assert.equal(p.csrf, undefined);
  });

  test("going back exports nothing, and forged posts are refused", async () => {
    const p = await toPick();
    assert.equal((await post("/export/review", p.cookie, { csrf: "wrong", action: "pick", namespace: cellId })).status, 400);
    assert.equal((await post("/export/download", p.cookie, { csrf: p.csrf!, choice: "confirm" })).status, 400);
    const later = await post("/export/review", p.cookie, { csrf: p.csrf!, action: "cancel" });
    assert.match(await later.text(), /Nothing was exported/);
    const c = await toConfirm();
    const back = await post("/export/download", c.cookie, { csrf: c.csrf!, choice: "cancel" });
    assert.match(await back.text(), /Nothing was exported/);
    const withKey = await fetch(`${base}/export/download`, {
      method: "POST", redirect: "manual",
      headers: { Authorization: `Bearer ${agentKey}`, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ choice: "confirm" }),
    });
    assert.equal(withKey.status, 400);
    const lost = await fetch(`${base}/export/callback?code=abc`, { redirect: "manual" });
    assert.equal(lost.status, 400);
  });
});
