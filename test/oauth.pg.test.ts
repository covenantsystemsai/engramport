/**
 * OAuth races that one SQL script can't show: a membership revoked while a
 * code or refresh token is being traded on another connection must never
 * leave a working access token behind. Same database rules as
 * store.pg.test.ts: needs ENGRAMPORT_TEST_DATABASE_URL pointing at a THROWAWAY
 * database, as a superuser, and stands in for Supabase Auth's tables.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import pg from "pg";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const sha = (s: string) => createHash("sha256").update(s).digest();
const s256 = (v: string) => createHash("sha256").update(v).digest("base64url");

describe("oauth races", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const clientId = `epc_${randomBytes(18).toString("base64url").replace(/[^A-Za-z0-9]/g, "x").slice(0, 24)}`;
  const cb = "https://claude.ai/api/mcp/auth_callback";
  const resource = "https://mcp.example/mcp";
  const verifier = randomBytes(32).toString("base64url");
  const userId = randomUUID();
  const sessionId = randomUUID();
  let admin: pg.Pool;
  let app: pg.Pool;
  let cell: string;
  let actor: string;
  let n = 0;

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await admin.query(`
      CREATE SCHEMA IF NOT EXISTS auth;
      CREATE TABLE IF NOT EXISTS auth.users (
        id uuid PRIMARY KEY, email text, email_confirmed_at timestamptz, banned_until timestamptz,
        deleted_at timestamptz, is_anonymous boolean NOT NULL DEFAULT false);
      CREATE TABLE IF NOT EXISTS auth.identities (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL, provider text NOT NULL,
        provider_id text, identity_data jsonb NOT NULL, last_sign_in_at timestamptz);
      CREATE TABLE IF NOT EXISTS auth.sessions (
        id uuid PRIMARY KEY, user_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
        not_after timestamptz);
      CREATE TABLE IF NOT EXISTS auth.mfa_amr_claims (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), session_id uuid NOT NULL,
        authentication_method text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());`);
    await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    const email = `race-${run}@example.com`;
    await admin.query("INSERT INTO auth.users (id, email) VALUES ($1, $2)", [userId, email]);
    await admin.query(
      `INSERT INTO auth.identities (user_id, provider, identity_data, last_sign_in_at)
       VALUES ($1, 'google', jsonb_build_object('email', $2::text, 'email_verified', true), now())`,
      [userId, email],
    );
    await admin.query("INSERT INTO auth.sessions (id, user_id) VALUES ($1, $2)", [sessionId, userId]);
    await admin.query("INSERT INTO auth.mfa_amr_claims (session_id, authentication_method) VALUES ($1, 'oauth')", [sessionId]);
    const ns = async (slug: string, level: string, parent: string | null) =>
      (await admin.query<{ id: string }>(
        "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, $2, $3) RETURNING id", [parent, level, slug],
      )).rows[0].id;
    const city = await ns(`oa-${run}`, "city", null);
    cell = await ns("cell", "cell", await ns("tower", "tower", city));
    actor = (await admin.query<{ id: string }>(
      "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', $1, 'Claude') RETURNING id", [`oa-${run}`],
    )).rows[0].id;

    const appUrl = new URL(ADMIN_URL!);
    appUrl.username = "engramport_app";
    appUrl.password = "engramport-test-only";
    app = new pg.Pool({ connectionString: appUrl.toString() });
    await app.query("SELECT memory.oauth_register_client($1, 'Claude', $2)", [clientId, [cb]]);
  });

  after(async () => {
    await app?.end();
    await admin?.end();
  });

  async function member(): Promise<string> {
    return (await admin.query<{ id: string }>(
      `INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ($1, $2, $3) RETURNING id`,
      [`race-${run}@example.com`, cell, actor],
    )).rows[0].id;
  }

  async function code(memberId: string): Promise<Buffer> {
    const h = sha(`code-${run}-${++n}`);
    const r = await app.query<{ ok: boolean }>(
      "SELECT memory.oauth_issue_code($1, $2, $3, $4, $5, $6, $7, '{read,write}', $8) AS ok",
      [userId, sessionId, clientId, memberId, cb, s256(verifier), resource, h],
    );
    assert.equal(r.rows[0].ok, true);
    return h;
  }

  function token() {
    const i = ++n;
    return { prefix: `ep_live_race${run}${String(i).padStart(2, "0")}`.slice(0, 32), hash: sha(`access-${run}-${i}`) };
  }

  /** Revokes the member as the admin role while `trade` holds its transaction open, then commits it. */
  async function revokeDuring(memberId: string, trade: (c: pg.PoolClient) => Promise<string>) {
    const a = await app.connect();
    const b = await admin.connect();
    try {
      await a.query("BEGIN");
      assert.equal(await trade(a), "ok");
      await b.query("SET ROLE engramport_admin");
      let done = false;
      const revoke = b.query("UPDATE memory.oauth_members SET revoked_at = now() WHERE id = $1", [memberId]).then(() => {
        done = true;
      });
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(done, false, "the revocation waits for the trade in flight");
      await a.query("COMMIT");
      await revoke;
    } finally {
      await b.query("RESET ROLE").catch(() => {});
      a.release();
      b.release();
    }
  }

  async function works(t: { prefix: string; hash: Buffer }): Promise<boolean> {
    const r = await app.query("SELECT 1 FROM memory.authenticate($1, $2)", [t.prefix, t.hash]);
    return r.rowCount === 1;
  }

  test("a membership revoked during a code trade leaves no working token", async () => {
    const m = await member();
    const c = await code(m);
    const access = token();
    await revokeDuring(m, async (conn) =>
      (await conn.query<{ status: string }>(
        "SELECT status FROM memory.oauth_exchange_code($1, $2, $3, $4, $5, $6, $7, $8)",
        [clientId, c, verifier, cb, resource, access.prefix, access.hash, sha(`refresh-${run}-a`)],
      )).rows[0].status,
    );
    assert.equal(await works(access), false);
  });

  test("a membership revoked during a refresh leaves no working token", async () => {
    const m = await member();
    const c = await code(m);
    const first = token();
    const refresh = sha(`refresh-${run}-b`);
    const ex = await app.query<{ status: string }>(
      "SELECT status FROM memory.oauth_exchange_code($1, $2, $3, $4, $5, $6, $7, $8)",
      [clientId, c, verifier, cb, resource, first.prefix, first.hash, refresh],
    );
    assert.equal(ex.rows[0].status, "ok");
    const next = token();
    await revokeDuring(m, async (conn) =>
      (await conn.query<{ status: string }>(
        "SELECT status FROM memory.oauth_refresh($1, $2, NULL, $3, $4, $5)",
        [clientId, refresh, next.prefix, next.hash, sha(`refresh-${run}-c`)],
      )).rows[0].status,
    );
    assert.equal(await works(first), false);
    assert.equal(await works(next), false);
  });
});
