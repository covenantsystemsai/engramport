/**
 * The pilot setup against a real database, through the admin CLI: dry run
 * changes nothing, apply does all of it in one transaction or none of it,
 * and keys go only to a new owner-only file. Same database rules as
 * store.pg.test.ts: needs ENGRAMPORT_TEST_DATABASE_URL pointing at a
 * THROWAWAY database, as a superuser.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";

import { AdminClient, AdminError, runAdmin } from "../src/admin.ts";
import { hashKey } from "../src/keys.ts";

const SUPER_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const pepper = randomBytes(32);

function urlAs(user: string, password: string): string {
  const u = new URL(SUPER_URL!);
  u.username = user;
  u.password = password;
  return u.toString();
}

describe("pilot setup", { skip: SUPER_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const opsRole = `pilot_ops_${run}`;
  let superPool: pg.Pool;
  let admin: AdminClient;
  let dir: string;

  before(async () => {
    superPool = new pg.Pool({ connectionString: SUPER_URL });
    await superPool.query(`CREATE ROLE ${opsRole} LOGIN PASSWORD 'ops-test-only'`);
    await superPool.query(`GRANT engramport_admin TO ${opsRole} WITH INHERIT FALSE, SET TRUE`);
    admin = new AdminClient(new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") }), pepper);
    dir = mkdtempSync(join(tmpdir(), "ep-pilot-"));
  });

  after(async () => {
    await admin?.close();
    await superPool?.query(`DROP OWNED BY ${opsRole}`).catch(() => undefined);
    await superPool?.query(`DROP ROLE IF EXISTS ${opsRole}`).catch(() => undefined);
    await superPool?.end();
    rmSync(dir, { recursive: true, force: true });
  });

  let n = 0;
  /** A config for a new cell, written to a file: its path and contents. */
  function config(over: Record<string, unknown> = {}) {
    const k = `${run}-${++n}`;
    const cfg = {
      namespace: `pl-${k}/realty/max`,
      embedding_model: "gte-small",
      owner: {
        actor: `pl-owner-${k}`,
        display: "Pilot owner",
        email: `owner-${k}@example.com`,
        authority: { scope: "cell_knowledge", can_delegate: true, expires_in: "365d" },
      },
      agents: [
        { actor: `pl-claude-${k}`, display: "Claude", read_only: false, expires_in: "90d" },
        { actor: `pl-grok-${k}`, display: "Grok", read_only: true, expires_in: "30d" },
      ],
      ...over,
    };
    const file = join(dir, `pilot-${k}.json`);
    writeFileSync(file, JSON.stringify(cfg));
    return { file, cfg };
  }

  /** The CLI, with its own client each time, as a real run has; it closes it when done. */
  const opsClient = (withPepper = true) =>
    new AdminClient(new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") }), withPepper ? pepper : undefined);
  async function cli(args: string[], withPepper = true) {
    const out: string[] = [];
    const err: string[] = [];
    const code = await runAdmin(["pilot", "setup", ...args], () => opsClient(withPepper), { out: (l) => out.push(l), err: (l) => err.push(l) });
    return { code, out: out.join("\n"), err: err.join("\n") };
  }
  const counts = async () => (await superPool.query<{ ns: number; actors: number; keys: number; members: number; auth: number }>(
    `SELECT (SELECT count(*) FROM memory.namespaces)::int AS ns, (SELECT count(*) FROM memory.actors)::int AS actors,
            (SELECT count(*) FROM memory.api_keys)::int AS keys, (SELECT count(*) FROM memory.oauth_members)::int AS members,
            (SELECT count(*) FROM memory.approval_authorities)::int AS auth`)).rows[0];

  test("a dry run lists every step and changes nothing", async () => {
    const { file, cfg } = config();
    const before = await counts();
    const r = await cli(["--config", file, "--namespace", cfg.namespace]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /Dry run for .*: nothing was changed/);
    assert.match(r.out, /create cell .*max, embeddings gte-small/);
    assert.match(r.out, /mint one read-only key/);
    assert.match(r.out, /To apply: add --apply --confirm/);
    assert.ok(!r.out.includes(cfg.owner.email), "the full email is not printed");
    assert.deepEqual(await counts(), before);
  });

  test("the namespace must be named the same on the command line, and typed again to apply", async () => {
    const { file, cfg } = config();
    const before = await counts();
    const other = await cli(["--config", file, "--namespace", "pl-other/realty/max"]);
    assert.equal(other.code, 1);
    assert.match(other.err, /not the config's namespace/);
    const noConfirm = await cli(["--config", file, "--namespace", cfg.namespace, "--apply", "--keys-out", join(dir, `k-${n}a`)]);
    assert.equal(noConfirm.code, 2);
    const wrongConfirm = await cli(["--config", file, "--namespace", cfg.namespace, "--apply", "--confirm", "pl-x/realty/max",
                                     "--keys-out", join(dir, `k-${n}b`)]);
    assert.equal(wrongConfirm.code, 2);
    const noKeysOut = await cli(["--config", file, "--namespace", cfg.namespace, "--apply", "--confirm", cfg.namespace]);
    assert.equal(noKeysOut.code, 2);
    const strayConfirm = await cli(["--config", file, "--namespace", cfg.namespace, "--confirm", cfg.namespace]);
    assert.equal(strayConfirm.code, 2, "--confirm without --apply is refused, not ignored");
    assert.deepEqual(await counts(), before);
    assert.ok(!existsSync(join(dir, `k-${n}a`)) && !existsSync(join(dir, `k-${n}b`)));
  });

  test("apply sets up the cell, the owner (offered, not yet accepted) and the agents, with keys only in the new file", async () => {
    const { file, cfg } = config();
    const keysOut = join(dir, `keys-${n}.jsonl`);
    const r = await cli(["--config", file, "--namespace", cfg.namespace, "--apply", "--confirm", cfg.namespace, "--keys-out", keysOut]);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /Set up /);
    const lines = readFileSync(keysOut, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(lines.length, 2);
    assert.equal(statSync(keysOut).mode & 0o777, 0o600);
    for (const l of lines) assert.ok(!r.out.includes(l.key) && !r.err.includes(l.key), "keys never reach the screen");

    const ns = (await superPool.query<{ embedding_model: string; purpose: string }>(
      "SELECT embedding_model, purpose::text FROM memory.namespaces WHERE path = $1", [cfg.namespace])).rows[0];
    assert.deepEqual(ns, { embedding_model: "gte-small", purpose: "client" });
    for (const l of lines) {
      const k = (await superPool.query<{ scopes: string[]; slug: string; ns: string }>(
        `SELECT k.scopes, a.slug, n.path AS ns FROM memory.api_keys k JOIN memory.actors a ON a.id = k.actor_id
         JOIN memory.namespaces n ON n.id = k.namespace_id WHERE k.key_hash = $1`, [hashKey(l.key, pepper)])).rows[0];
      assert.ok(k, "the key in the file is the one stored, as its peppered hash");
      assert.equal(k.ns, cfg.namespace);
      assert.deepEqual(k.scopes, l.actor === cfg.agents[1].actor ? ["read"] : ["read", "write"]);
    }
    const auth = (await superPool.query<{ can_delegate: boolean; decided: boolean }>(
      `SELECT a.can_delegate, EXISTS (SELECT 1 FROM memory.approval_authority_decisions d WHERE d.authority_id = a.id) AS decided
       FROM memory.approval_authorities a JOIN memory.actors x ON x.id = a.actor_id WHERE x.slug = $1`, [cfg.owner.actor])).rows[0];
    assert.deepEqual(auth, { can_delegate: true, decided: false }, "offered, counts only once the owner accepts");
    const member = (await superPool.query("SELECT 1 FROM memory.oauth_members WHERE email = $1", [cfg.owner.email])).rows;
    assert.equal(member.length, 1);

    // Running it again is refused, and changes nothing.
    const before = await counts();
    const again = await cli(["--config", file, "--namespace", cfg.namespace, "--apply", "--confirm", cfg.namespace,
                             "--keys-out", join(dir, `keys-${n}-again.jsonl`)]);
    assert.equal(again.code, 1);
    assert.match(again.err, /already exists/);
    assert.deepEqual(await counts(), before);
    assert.ok(!existsSync(join(dir, `keys-${n}-again.jsonl`)), "a refused run leaves no keys file");
  });

  test("an existing keys file is refused before anything happens", async () => {
    const { file, cfg } = config();
    const keysOut = join(dir, `taken-${n}`);
    writeFileSync(keysOut, "do not overwrite");
    const before = await counts();
    const r = await cli(["--config", file, "--namespace", cfg.namespace, "--apply", "--confirm", cfg.namespace, "--keys-out", keysOut]);
    assert.equal(r.code, 1);
    assert.match(r.err, /already exists/);
    assert.equal(readFileSync(keysOut, "utf8"), "do not overwrite");
    assert.deepEqual(await counts(), before);
  });

  test("a taken actor name or a company city refuses the whole setup", async () => {
    const { file, cfg } = config();
    await superPool.query("INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', $1, 'squatter')", [cfg.agents[1].actor]);
    const before = await counts();
    const r = await cli(["--config", file, "--namespace", cfg.namespace, "--apply", "--confirm", cfg.namespace,
                         "--keys-out", join(dir, `keys-${n}.jsonl`)]);
    assert.equal(r.code, 1);
    assert.match(r.err, /already taken/);
    assert.deepEqual(await counts(), before, "not even the city or the first agent was created");

    const company = (await superPool.query<{ path: string }>(
      "SELECT path FROM memory.namespaces WHERE purpose = 'company' AND parent_id IS NULL")).rows[0]?.path
      ?? (await admin.createNamespace(`pl-co-${run}`, { company: true })).path;
    const co = config({ namespace: `${company}/realty/max-${run}` });
    const dry = await cli(["--config", co.file, "--namespace", co.cfg.namespace]);
    assert.equal(dry.code, 1);
    assert.match(dry.err, /company namespace/);
  });

  test("a failure part way through leaves nothing behind", async () => {
    const before = await counts();
    await assert.rejects(admin.transaction(async (tx) => {
      await tx.createNamespace(`pl-half-${run}`);
      await tx.createNamespace(`pl-half-${run}/tower`);
      throw new AdminError("stop here");
    }), /stop here/);
    assert.deepEqual(await counts(), before);
    // And the dry run's transaction refuses writes outright.
    await assert.rejects(admin.transaction((tx) => tx.createNamespace(`pl-ro-${run}`), { readOnly: true }),
      (e: { code?: string }) => e.code === "25006");
    assert.deepEqual(await counts(), before);
  });

  test("without the pepper nothing is applied", async () => {
    const { file, cfg } = config();
    const before = await counts();
    const r = await cli(["--config", file, "--namespace", cfg.namespace, "--apply", "--confirm", cfg.namespace,
                         "--keys-out", join(dir, `keys-${n}.jsonl`)], false);
    assert.equal(r.code, 1);
    assert.match(r.err, /KEY_PEPPER/);
    assert.deepEqual(await counts(), before);
    assert.ok(!existsSync(join(dir, `keys-${n}.jsonl`)));
  });
});
