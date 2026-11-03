/**
 * `engramport admin` against a real database with the memory schema applied.
 *
 * Needs ENGRAMPORT_TEST_DATABASE_URL: a superuser URL to a THROWAWAY database
 * (CI uses a pgvector container). The test makes its own login roles, one
 * granted SET on engramport_admin and one not, and runs the admin tool as the
 * first, then proves each key it mints, rotates or revokes through the store
 * running as engramport_app. Skipped when the variable is unset.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import pg from "pg";

import { AdminClient, AdminError, runAdmin } from "../src/admin.ts";
import { parseKey } from "../src/keys.ts";
import { PostgresStore, StoreError } from "../src/store/postgres.ts";

const SUPER_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const pepper = randomBytes(32);

function urlAs(user: string, password: string): string {
  const u = new URL(SUPER_URL!);
  u.username = user;
  u.password = password;
  return u.toString();
}

describe("engramport admin", { skip: SUPER_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const opsRole = `ops_${run}`;
  const strangerRole = `stranger_${run}`;
  const city = `adm-${run}`;
  const cell = `${city}/tower/cell`;
  let superPool: pg.Pool;
  let appPool: pg.Pool;
  let admin: AdminClient;
  let store: PostgresStore;

  before(async () => {
    superPool = new pg.Pool({ connectionString: SUPER_URL });
    await superPool.query(`CREATE ROLE ${opsRole} LOGIN PASSWORD 'ops-test-only'`);
    await superPool.query(`GRANT engramport_admin TO ${opsRole} WITH INHERIT FALSE, SET TRUE`);
    await superPool.query(`CREATE ROLE ${strangerRole} LOGIN PASSWORD 'stranger-test-only'`);
    await superPool.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    admin = new AdminClient(new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") }), pepper);
    appPool = new pg.Pool({ connectionString: urlAs("engramport_app", "engramport-test-only") });
    store = new PostgresStore(appPool, { pepper, transport: "stdio" });
  });

  after(async () => {
    await admin?.close();
    await appPool?.end();
    await superPool?.query(`DROP OWNED BY ${opsRole}`).catch(() => undefined);
    await superPool?.query(`DROP ROLE IF EXISTS ${opsRole}`).catch(() => undefined);
    await superPool?.query(`DROP ROLE IF EXISTS ${strangerRole}`).catch(() => undefined);
    await superPool?.end();
  });

  const refused = (p: Promise<unknown>, pattern: RegExp) =>
    assert.rejects(p, (err: unknown) => err instanceof AdminError && pattern.test(err.message));
  const storeFails = (p: Promise<unknown>, code: string) =>
    assert.rejects(p, (err: unknown) => err instanceof StoreError && err.code === code);

  test("the ops login has no direct rights; only the admin role does", async () => {
    const ops = new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") });
    try {
      await assert.rejects(ops.query("SELECT 1 FROM memory.namespaces"), (e: { code?: string }) => e.code === "42501");
    } finally {
      await ops.end();
    }
  });

  test("a login without SET on the admin role is refused with the grant to run", async () => {
    const stranger = new AdminClient(new pg.Pool({ connectionString: urlAs(strangerRole, "stranger-test-only") }));
    try {
      await refused(stranger.listNamespaces(), /cannot switch to engramport_admin/);
    } finally {
      await stranger.close();
    }
  });

  test("namespaces are created top down with their level taken from the path", async () => {
    assert.equal((await admin.createNamespace(city)).level, "city");
    assert.equal((await admin.createNamespace(`${city}/tower`)).level, "tower");
    const c = await admin.createNamespace(cell);
    assert.deepEqual([c.level, c.path], ["cell", cell]);
    await admin.createNamespace(`${city}/tower/cell-2`);
    await refused(admin.createNamespace(cell), /already exists/);
    await refused(admin.createNamespace(`${city}/missing/cell`), /create it first/);
    assert.ok((await admin.listNamespaces()).some((n) => n.path === cell));
  });

  test("actors are created once and must be enabled to get a key", async () => {
    await admin.createActor(`claude-${run}`, "agent", "Claude");
    await admin.createActor(`grok-${run}`, "agent", "Grok Bot");
    await refused(admin.createActor(`claude-${run}`, "agent", "Claude"), /already exists/);
    await admin.setActorDisabled(`grok-${run}`, true);
    await refused(admin.mintKey({ namespace: cell, actor: `grok-${run}` }), /disabled/);
    await admin.setActorDisabled(`grok-${run}`, false);
    await refused(admin.mintKey({ namespace: `${city}/nope`, actor: `grok-${run}` }), /no namespace/);
    await refused(admin.mintKey({ namespace: cell, actor: "nobody-here" }), /no actor/);
  });

  test("a minted key works in its namespace only, and a read-only key cannot write", async () => {
    const rw = await admin.mintKey({ namespace: cell, actor: `claude-${run}` });
    assert.deepEqual(parseKey(rw.key)?.prefix, rw.prefix);
    assert.ok(rw.key.startsWith(`${rw.prefix}.`));
    const saved = await store.remember(rw.key, { content: "minted key writes here" });
    assert.ok(saved);
    await storeFails(store.remember(rw.key, { content: "x", namespace: `${city}/tower/cell-2` }), "forbidden");

    const ro = await admin.mintKey({ namespace: cell, actor: `grok-${run}`, readOnly: true });
    assert.deepEqual(ro.scopes, ["read"]);
    await storeFails(store.remember(ro.key, { content: "should not land" }), "forbidden");
    const found = await store.recall(ro.key, { query: "minted key writes", mode: "keyword" });
    assert.ok(JSON.stringify(found).includes("minted key writes here"));
  });

  test("key listings never carry a hash or the secret half of a key", async () => {
    const k = await admin.mintKey({ namespace: cell, actor: `claude-${run}`, expiresInMs: 3_600_000 });
    const listed = await admin.listKeys({ namespace: cell });
    const row = listed.find((r) => r.prefix === k.prefix);
    assert.ok(row);
    assert.ok(row.expires_at && row.expires_at.getTime() > Date.now());
    const text = JSON.stringify(listed);
    assert.ok(!text.includes(k.key.split(".")[1]));
    assert.ok(!/key_hash/.test(text));
  });

  test("rotation keeps the old key alive for the grace period, or ends it at once", async () => {
    const first = await admin.mintKey({ namespace: cell, actor: `claude-${run}` });
    const { minted: second, old } = await admin.rotateKey(first.prefix, 3_600_000);
    assert.ok(old.expires_at && old.expires_at.getTime() <= Date.now() + 3_600_000 + 5_000);
    assert.equal(old.revoked_at, null);
    assert.ok(await store.remember(first.key, { content: "old key still works during grace" }));
    assert.ok(await store.remember(second.key, { content: "new key works" }));
    assert.equal(second.namespace, cell);

    const { minted: third, old: ended } = await admin.rotateKey(second.prefix, 0);
    assert.ok(ended.revoked_at);
    await storeFails(store.remember(second.key, { content: "x" }), "unauthorized");
    assert.ok(await store.remember(third.key, { content: "third key works" }));
    await refused(admin.rotateKey(second.prefix, 0), /revoked/);
  });

  test("rotating a key that expires soon renews its lifetime", async () => {
    const k = await admin.mintKey({ namespace: cell, actor: `claude-${run}`, expiresInMs: 7 * 86_400_000 });
    const { minted } = await admin.rotateKey(k.prefix, 0);
    const life = minted.expires_at!.getTime() - Date.now();
    assert.ok(life > 6.9 * 86_400_000 && life <= 7 * 86_400_000 + 5_000);
  });

  test("revoking stops the key on its next request and cannot be undone", async () => {
    const k = await admin.mintKey({ namespace: cell, actor: `claude-${run}` });
    assert.ok(await store.remember(k.key, { content: "before revoke" }));
    const revoked = await admin.revokeKey(k.prefix);
    assert.ok(revoked.revoked_at);
    await storeFails(store.remember(k.key, { content: "after revoke" }), "unauthorized");
    await refused(admin.revokeKey(k.prefix), /already revoked/);
    await refused(admin.revokeKey("ep_live_000000000000"), /no key/);
    const listed = await admin.listKeys({ namespace: cell });
    assert.ok(!listed.some((r) => r.prefix === k.prefix), "revoked keys are hidden by default");
    assert.ok((await admin.listKeys({ namespace: cell, includeInactive: true })).some((r) => r.prefix === k.prefix));
  });

  test("disabling an actor stops all of its keys, and enabling brings them back", async () => {
    const k = await admin.mintKey({ namespace: cell, actor: `grok-${run}` });
    await admin.setActorDisabled(`grok-${run}`, true);
    await storeFails(store.recall(k.key, { query: "anything", mode: "keyword" }), "unauthorized");
    await admin.setActorDisabled(`grok-${run}`, false);
    assert.ok(await store.recall(k.key, { query: "anything", mode: "keyword" }));
  });

  test("the company city is marked once, and its towers and cells inherit it", async () => {
    // One company city per database: use the one a rerun left behind, if any.
    const existing = await superPool.query<{ path: string }>(
      "SELECT path FROM memory.namespaces WHERE purpose = 'company' AND parent_id IS NULL",
    );
    const coCity = existing.rows[0]?.path ?? `co-${run}`;
    if (!existing.rows[0]) {
      const made = await admin.createNamespace(coCity, { company: true });
      assert.deepEqual([made.level, made.purpose], ["city", "company"]);
    }
    const tower = await admin.createNamespace(`${coCity}/t-${run}`);
    const coCell = await admin.createNamespace(`${coCity}/t-${run}/hq`);
    assert.deepEqual([tower.purpose, coCell.purpose], ["company", "company"]);
    assert.equal((await admin.createNamespace(`adm2-${run}`)).purpose, "client");
    await refused(admin.createNamespace(`another-${run}`, { company: true }), /already .*only one/);
    await refused(admin.createNamespace(`${city}/co-${run}`, { company: true }), /only a city/);
    const listed = await admin.listNamespaces();
    assert.equal(listed.find((n) => n.path === coCell.path)?.purpose, "company");
    assert.equal(listed.find((n) => n.path === cell)?.purpose, "client");

    // The company cell and a client cell cannot read each other.
    const coKey = await admin.mintKey({ namespace: coCell.path, actor: `claude-${run}` });
    const clientKey = await admin.mintKey({ namespace: cell, actor: `claude-${run}` });
    await store.remember(coKey.key, { content: `company only pricing rule ${run}` });
    await store.remember(clientKey.key, { content: `client only launch note ${run}` });
    const fromCompany = JSON.stringify(await store.recall(coKey.key, { query: run, mode: "keyword" }));
    const fromClient = JSON.stringify(await store.recall(clientKey.key, { query: run, mode: "keyword" }));
    assert.ok(fromCompany.includes("company only pricing rule"));
    assert.ok(!fromCompany.includes("client only launch note"), "the company cell never sees a client memory");
    assert.ok(fromClient.includes("client only launch note"));
    assert.ok(!fromClient.includes("company only pricing rule"), "a client cell never sees a company memory");
    await storeFails(store.remember(clientKey.key, { content: "x", namespace: coCell.path }), "forbidden");
    await storeFails(store.remember(coKey.key, { content: "x", namespace: cell }), "forbidden");
  });

  test("the command line marks a city as the company's and shows purposes", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const io = { out: (l: string) => out.push(l), err: (l: string) => err.push(l) };
    const open = () => new AdminClient(new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") }), pepper);
    assert.equal(await runAdmin(["namespace", "create", `nope-${run}`, "--company"], open, io), 1);
    assert.match(err.join("\n"), /only one/);
    out.length = 0;
    assert.equal(await runAdmin(["namespace", "list"], open, io), 0);
    assert.ok(out.some((l) => /^cell\s+company\s/.test(l) && l.endsWith(`/t-${run}/hq`)), out.join("\n"));
    assert.ok(out.some((l) => l.includes("client") && l.endsWith(cell)));
  });

  test("the audit shows who wrote what, where and when, and never the content", async () => {
    const k = await admin.mintKey({ namespace: cell, actor: `grok-${run}` });
    const secret = `audit secret text ${run}`;
    await store.remember(k.key, { content: secret });
    const rows = await admin.audit({ namespace: city });
    const write = rows.find((r) => r.event === "write" && r.key_prefix === k.prefix);
    assert.ok(write, "the write is in the trail");
    assert.deepEqual([write.namespace, write.actor, write.tool, write.transport], [cell, `grok-${run}`, "remember", "stdio"]);
    assert.ok(rows.some((r) => r.event === "key minted" && r.key_prefix === k.prefix));
    const text = JSON.stringify(rows);
    assert.ok(!text.includes(secret), "no memory text");
    const hash = createHash("sha256").update(secret).digest("hex");
    assert.ok(!text.includes(hash), "no content hash");

    // Filters: a namespace includes everything under it; actor, time and writes only narrow it.
    assert.ok((await admin.audit({ namespace: cell })).some((r) => r.key_prefix === k.prefix));
    assert.ok(!(await admin.audit({ namespace: `${city}/tower/cell-2` })).some((r) => r.key_prefix === k.prefix));
    const mine = await admin.audit({ namespace: city, actor: `grok-${run}`, writesOnly: true });
    assert.ok(mine.length > 0 && mine.every((r) => r.actor === `grok-${run}` && r.event === "write"));
    assert.ok((await admin.audit({ namespace: city, sinceMs: 3_600_000 })).some((r) => r.key_prefix === k.prefix));
    assert.equal((await admin.audit({ namespace: city, limit: 1 })).length, 1);
    const newest = await admin.audit({ namespace: city });
    for (let i = 1; i < newest.length; i++) assert.ok(newest[i - 1].at >= newest[i].at, "newest first");

    await admin.revokeKey(k.prefix);
    assert.ok((await admin.audit({ namespace: cell })).some((r) => r.event === "key revoked" && r.key_prefix === k.prefix));
    await refused(admin.audit({ namespace: `${city}/nope` }), /no namespace/);
    await refused(admin.audit({ actor: "nobody-here" }), /no actor/);
    await refused(admin.audit({ limit: 5000 }), /limit/);
  });

  test("the audit command prints one line per event and no content", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const io = { out: (l: string) => out.push(l), err: (l: string) => err.push(l) };
    const open = () => new AdminClient(new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") }), pepper);
    const k = await admin.mintKey({ namespace: cell, actor: `claude-${run}` });
    await store.remember(k.key, { content: `cli audit secret ${run}` });
    assert.equal(await runAdmin(["audit", "--namespace", cell, "--since", "1h", "--limit", "50"], open, io), 0, err.join("\n"));
    assert.ok(out.some((l) => l.includes(" write ") && l.includes(k.prefix) && l.includes("remember via stdio")), out.join("\n"));
    assert.ok(out.some((l) => l.includes("key minted") && l.includes(k.prefix)));
    assert.ok(out.every((l) => !l.includes("cli audit secret")));
  });

  test("the command line prints a minted key alone on stdout", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const io = { out: (l: string) => out.push(l), err: (l: string) => err.push(l) };
    const opsUrl = urlAs(opsRole, "ops-test-only");
    const open = () => new AdminClient(new pg.Pool({ connectionString: opsUrl }), pepper);
    const code = await runAdmin(["key", "mint", "--namespace", cell, "--actor", `claude-${run}`, "--expires-in", "30d"], open, io);
    assert.equal(code, 0, err.join("\n"));
    assert.equal(out.length, 1);
    assert.ok(parseKey(out[0]), "stdout is exactly one key");
    const cliKey = out[0];
    assert.match(err.join("\n"), /shown once/);
    assert.ok(await store.remember(out[0], { content: "cli key works" }));

    out.length = 0;
    assert.equal(await runAdmin(["key", "list", "--namespace", cell], open, io), 0);
    assert.ok(out.some((l) => l.startsWith(parseKey(cliKey)!.prefix)));
    assert.ok(out.every((l) => !l.includes(cliKey.split(".")[1])), "listings never show the secret half");

    assert.equal(await runAdmin(["key", "mint", "--namespace", cell, "--actor", "nobody-here"], open, io), 1);
  });
});
