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
import { hashKey, mintKey, parseKey } from "../src/keys.ts";
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

  test("a namespace's embedding model defaults to Supabase's, passes down, and can be changed", async () => {
    const top = `em-${run}`;
    assert.equal((await admin.createNamespace(top)).embedding_model, "gte-small");
    assert.equal((await admin.createNamespace(`${top}/oa`, { embeddingModel: "text-embedding-3-small" })).embedding_model,
      "text-embedding-3-small");
    assert.equal((await admin.createNamespace(`${top}/oa/inherits`)).embedding_model, "text-embedding-3-small");
    assert.equal((await admin.createNamespace(`${top}/oa/pilot`, { embeddingModel: "gte-small" })).embedding_model, "gte-small");
    assert.equal((await admin.createNamespace(`${top}/oa/off`, { embeddingModel: "none" })).embedding_model, null);
    await refused(admin.createNamespace(`${top}/oa/bad`, { embeddingModel: "made-up" }), /must be one of/);
    assert.equal((await admin.setEmbeddingModel(`${top}/oa/inherits`, "gte-small")).embedding_model, "gte-small");
    assert.equal((await admin.setEmbeddingModel(`${top}/oa/inherits`, "none")).embedding_model, null);
    await refused(admin.setEmbeddingModel(`${top}/missing`, "gte-small"), /no namespace/);
    const models = (await admin.listEmbeddingModels()).map((m) => [m.model, m.dimension, m.stays_in_supabase]);
    assert.deepEqual(models.filter(([m]) => m === "gte-small" || m === "text-embedding-3-small"),
      [["gte-small", 384, true], ["text-embedding-3-small", 1536, false]]);
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

  test("the command line sets and shows each namespace's embedding model", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const io = { out: (l: string) => out.push(l), err: (l: string) => err.push(l) };
    const open = () => new AdminClient(new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") }), pepper);
    const top = `emcli-${run}`;
    assert.equal(await runAdmin(["namespace", "create", top], open, io), 0, err.join("\n"));
    assert.equal(await runAdmin(["namespace", "create", `${top}/t`, "--embedding-model", "none"], open, io), 0, err.join("\n"));
    assert.ok(out.some((l) => l.endsWith(`${top}, embeddings gte-small`)), out.join("\n"));
    assert.ok(out.some((l) => l.endsWith(`${top}/t, embeddings none`)), out.join("\n"));
    assert.equal(await runAdmin(["namespace", "embedding", `${top}/t`, "gte-small"], open, io), 0, err.join("\n"));
    assert.ok(out.some((l) => l === `${top}/t now embeds with gte-small`), out.join("\n"));
    out.length = 0;
    assert.equal(await runAdmin(["namespace", "list"], open, io), 0);
    assert.ok(out.some((l) => /\sgte-small\s/.test(l) && l.endsWith(`${top}/t`)), out.join("\n"));
    out.length = 0;
    assert.equal(await runAdmin(["embedding", "models"], open, io), 0);
    assert.ok(out.some((l) => l.startsWith("gte-small") && l.includes("stays in Supabase")), out.join("\n"));
    assert.ok(out.some((l) => l.startsWith("text-embedding-3-small") && l.includes("sent outside Supabase")), out.join("\n"));
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

  /** As the superuser, a client and a connection for a member, and an access token on it, the way 0009's functions make them. */
  async function connect(email: string, namespace: string, actor: string, clientName = "Claude") {
    const clientId = `epc_${randomBytes(18).toString("hex").slice(0, 24)}`;
    const cl = await superPool.query<{ id: string }>(
      "INSERT INTO memory.oauth_clients (client_id, client_name, redirect_uris) VALUES ($1, $2, $3) RETURNING id",
      [clientId, clientName, ["https://claude.ai/api/mcp/auth_callback"]],
    );
    const m = await superPool.query<{ id: string; namespace_id: string; actor_id: string }>(
      `SELECT m.id, m.namespace_id, m.actor_id FROM memory.oauth_members m
       JOIN memory.namespaces n ON n.id = m.namespace_id JOIN memory.actors a ON a.id = m.actor_id
       WHERE m.email = $1 AND n.path = $2 AND a.slug = $3 AND m.revoked_at IS NULL`,
      [email, namespace, actor],
    );
    const g = await superPool.query<{ id: string }>(
      "INSERT INTO memory.oauth_grants (client_id, member_id, scopes, resource) VALUES ($1, $2, '{read,write}', 'https://mcp.example/mcp') RETURNING id",
      [cl.rows[0].id, m.rows[0].id],
    );
    const token = mintKey();
    await superPool.query(
      `INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes, expires_at, oauth_grant_id)
       VALUES ($1, $2, $3, $4, '{read,write}', now() + interval '1 hour', $5)`,
      [m.rows[0].namespace_id, m.rows[0].actor_id, token.prefix, hashKey(token.key, pepper), g.rows[0].id],
    );
    return { grantId: g.rows[0].id, token: token.key };
  }

  test("members are added once per namespace and actor, and only to what exists", async () => {
    const email = `Pilot-${run}@Example.com`;
    const m = await admin.addMember({ email, namespace: cell, actor: `claude-${run}` });
    assert.deepEqual([m.email, m.namespace, m.actor, m.scopes, m.connections], [email.toLowerCase(), cell, `claude-${run}`, ["read", "write"], 0]);
    await refused(admin.addMember({ email: email.toLowerCase(), namespace: cell, actor: `claude-${run}` }), /already a member/);
    const ro = await admin.addMember({ email, namespace: cell, actor: `grok-${run}`, readOnly: true });
    assert.deepEqual(ro.scopes, ["read"]);
    await refused(admin.addMember({ email, namespace: `${city}/nope`, actor: `claude-${run}` }), /no namespace/);
    await refused(admin.addMember({ email, namespace: cell, actor: "nobody-here" }), /no actor/);
    await refused(admin.addMember({ email: "not-an-email", namespace: cell, actor: `claude-${run}` }), /not an email/);
    await admin.setActorDisabled(`grok-${run}`, true);
    try {
      await refused(admin.addMember({ email: `other-${run}@example.com`, namespace: cell, actor: `grok-${run}` }), /disabled/);
    } finally {
      await admin.setActorDisabled(`grok-${run}`, false);
    }
    const listed = await admin.listMembers({ namespace: city, email });
    assert.deepEqual(listed.map((r) => r.actor).sort(), [`claude-${run}`, `grok-${run}`].sort());
  });

  test("revoking a member ends its connections and their tokens, and cannot be undone", async () => {
    const email = `revoke-${run}@example.com`;
    await admin.addMember({ email, namespace: cell, actor: `claude-${run}` });
    const { grantId, token } = await connect(email, cell, `claude-${run}`);
    assert.ok(await store.remember(token, { content: "connected before revoke" }));
    const [before] = await admin.listMembers({ email });
    assert.equal(before.connections, 1);
    assert.ok((await admin.listConnections({ email })).some((g) => g.id === grantId));

    await refused(admin.revokeMember({ email, namespace: `${city}/tower/cell-2` }), /no active membership/);
    const [gone] = await admin.revokeMember({ email, namespace: cell });
    assert.ok(gone.revoked_at);
    assert.equal(gone.connections, 0);
    await storeFails(store.remember(token, { content: "should not land" }), "unauthorized");
    const [conn] = await admin.listConnections({ email, includeRevoked: true });
    assert.deepEqual([conn.id, conn.revoke_reason], [grantId, "member_revoked"]);
    assert.equal((await admin.listMembers({ email })).length, 0);
    assert.equal((await admin.listMembers({ email, includeRevoked: true })).length, 1);
    await refused(admin.revokeMember({ email, namespace: cell }), /no active membership/);
  });

  test("revoking one connection keeps the membership, so the person can connect again", async () => {
    const email = `conn-${run}@example.com`;
    await admin.addMember({ email, namespace: cell, actor: `claude-${run}` });
    const a = await connect(email, cell, `claude-${run}`);
    const b = await connect(email, cell, `claude-${run}`, "Desktop");
    const g = await admin.revokeConnection(a.grantId);
    assert.deepEqual([g.revoke_reason, g.client], ["admin_revoked", "Claude"]);
    await storeFails(store.remember(a.token, { content: "should not land" }), "unauthorized");
    assert.ok(await store.remember(b.token, { content: "the other connection still works" }));
    assert.equal((await admin.listMembers({ email }))[0].connections, 1);
    await refused(admin.revokeConnection(a.grantId), /already revoked/);
    await refused(admin.revokeConnection("00000000-0000-0000-0000-000000000000"), /no connection/);
    await refused(admin.revokeConnection("not-a-uuid"), /not a connection id/);
  });

  test("the member and connection commands print metadata and spell out odd client names", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const io = { out: (l: string) => out.push(l), err: (l: string) => err.push(l) };
    const open = () => new AdminClient(new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") }), pepper);
    const email = `cli-${run}@example.com`;
    assert.equal(await runAdmin(["member", "add", email, "--namespace", cell, "--actor", `claude-${run}`, "--read-only"], open, io), 0, err.join("\n"));
    assert.match(out.at(-1)!, new RegExp(`^${email} may connect to ${cell} as claude-${run} \\(read\\)$`));
    const { grantId } = await connect(email, cell, `claude-${run}`, "Claude\u202Egnp.exe");
    out.length = 0;
    assert.equal(await runAdmin(["connection", "list", "--email", email], open, io), 0, err.join("\n"));
    assert.equal(out.length, 1);
    assert.ok(out[0].startsWith(grantId) && out[0].includes('"Claude\\u202egnp.exe"'), out[0]);
    assert.ok(!out[0].includes("\u202E"));
    out.length = 0;
    assert.equal(await runAdmin(["member", "list", "--namespace", cell, "--email", email], open, io), 0);
    assert.match(out[0], /active, 1 connection$/);
    assert.equal(await runAdmin(["member", "revoke", email, "--namespace", cell, "--actor", `claude-${run}`], open, io), 0);
    assert.match(out.at(-1)!, /can no longer connect/);
    assert.equal(await runAdmin(["member", "revoke", email, "--namespace", cell], open, io), 1);
  });

  // Stands in for the holder accepting through their own Google sign-in, which
  // the database tests cover; here only the admin's view of it matters.
  async function acceptAsHolder(authorityId: string): Promise<void> {
    const sess = randomBytes(32);
    await superPool.query(
      `WITH a AS (SELECT actor_id FROM memory.approval_authorities WHERE id = $1),
            s AS (INSERT INTO memory.human_sign_ins_used (session_hash, actor_id, purpose)
                  SELECT $2, actor_id, 'accept' FROM a RETURNING session_hash, actor_id)
       INSERT INTO memory.approval_authority_decisions (authority_id, actor_id, decision, grant_sha256, sign_in_hash)
       SELECT $1, s.actor_id, 'accept', memory.approval_authority_grant_sha256($1), s.session_hash FROM s`,
      [authorityId, sess]);
  }

  test("approval authority goes to humans only, in the scope its namespace allows", async () => {
    const owner = `owner-${run}`;
    await admin.createActor(owner, "human", "Pilot owner");
    await admin.createActor(`bot-${run}`, "agent", "An agent");
    const a = await admin.grantAuthority({ actor: owner, namespace: cell, scope: "cell_knowledge", canDelegate: true });
    // A grant is only an offer until its holder accepts it (0017).
    assert.deepEqual([a.actor, a.namespace, a.scope, a.claim_types, a.can_delegate, a.parent_id, a.acceptance, a.valid],
      [owner, cell, "cell_knowledge", null, true, null, "pending", false]);
    const narrow = await admin.grantAuthority({
      actor: owner, namespace: cell, scope: "cell_knowledge", claimTypes: ["decision", "fact", "fact"], expiresInMs: 86_400_000,
    });
    assert.deepEqual(narrow.claim_types, ["decision", "fact"]);
    assert.ok(narrow.expires_at && narrow.expires_at.getTime() > Date.now());

    await refused(admin.grantAuthority({ actor: `bot-${run}`, namespace: cell, scope: "cell_knowledge" }), /not a human actor/);
    await refused(admin.grantAuthority({ actor: owner, namespace: `${city}/tower`, scope: "cell_knowledge" }), /client cell/);
    await refused(admin.grantAuthority({ actor: owner, namespace: cell, scope: "company_governance" }), /company namespace/);
    await refused(admin.grantAuthority({ actor: owner, namespace: cell, scope: "promotion" }), /tower or a city/);
    await refused(admin.grantAuthority({ actor: owner, namespace: cell, scope: "deploy" }), /not an approval scope/);
    await refused(admin.grantAuthority({ actor: owner, namespace: cell, scope: "cell_knowledge", claimTypes: ["approved"] }), /not a claim type/);
    await refused(admin.grantAuthority({ actor: owner, namespace: cell, scope: "cell_knowledge", claimTypes: [] }), /at least one/);
    await refused(admin.grantAuthority({ actor: owner, namespace: cell, scope: "cell_knowledge", expiresInMs: 0 }), /future/);
    await refused(admin.grantAuthority({ actor: "nobody-here", namespace: cell, scope: "cell_knowledge" }), /no actor/);
    const promo = await admin.grantAuthority({ actor: owner, namespace: `${city}/tower`, scope: "promotion" });
    assert.equal(promo.scope, "promotion");

    const listed = await admin.listAuthorities({ namespace: city, actor: owner });
    assert.deepEqual(listed.map((r) => r.id).sort(), [a.id, narrow.id, promo.id].sort());

    await refused(admin.revokeAuthority(a.id, "  "), /reason/);
    await refused(admin.revokeAuthority(a.id, "Paused by the owner"), /short code/);
    await refused(admin.revokeAuthority("not-a-uuid", "gone_now"), /not an authority id/);
    await refused(admin.revokeAuthority("00000000-0000-0000-0000-000000000000", "gone_now"), /no authority/);
    const gone = await admin.revokeAuthority(a.id, "pilot_paused");
    assert.deepEqual([gone.revoke_reason, gone.valid], ["pilot_paused", false]);
    await refused(admin.revokeAuthority(a.id, "again_now"), /already revoked/);
    assert.ok(!(await admin.listAuthorities({ actor: owner })).some((r) => r.id === a.id));
    assert.ok((await admin.listAuthorities({ actor: owner, includeRevoked: true })).some((r) => r.id === a.id));

    // The holder's acceptance, as memory.decide_approval_authority records it.
    await acceptAsHolder(narrow.id);
    const [taken] = (await admin.listAuthorities({ actor: owner })).filter((r) => r.id === narrow.id);
    assert.deepEqual([taken.acceptance, taken.valid], ["accepted", true]);
    assert.ok(taken.decided_at instanceof Date);

    // Disabling the holder makes the authority invalid without revoking it.
    await admin.setActorDisabled(owner, true);
    try {
      const [still] = (await admin.listAuthorities({ actor: owner })).filter((r) => r.id === narrow.id);
      assert.deepEqual([still.revoked_at, still.valid], [null, false]);
    } finally {
      await admin.setActorDisabled(owner, false);
    }
  });

  test("the authority commands grant, list and revoke, and print no memory content", async () => {
    const out: string[] = [];
    const err: string[] = [];
    const io = { out: (l: string) => out.push(l), err: (l: string) => err.push(l) };
    const open = () => new AdminClient(new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") }), pepper);
    const holder = `holder-${run}`;
    await admin.createActor(holder, "human", "Another owner");
    assert.equal(await runAdmin(["authority", "grant", holder, "--namespace", cell, "--scope", "cell_knowledge",
      "--claim-types", "decision,fact", "--can-delegate", "--expires-in", "30d"], open, io), 0, err.join("\n"));
    assert.deepEqual(out.slice(-1), ["It counts only once they accept it with their own Google sign-in."]);
    const line = out.at(-2)!;
    assert.match(line, new RegExp(`^[0-9a-f-]{36}  ${holder} may approve decision, fact in ${cell} \\(cell_knowledge\\), and may delegate, until `));
    const id = line.slice(0, 36);
    out.length = 0;
    assert.equal(await runAdmin(["authority", "list", "--actor", holder], open, io), 0);
    assert.equal(out.length, 1);
    assert.match(out[0], /granted by admin  waiting for the holder to accept$/);
    await acceptAsHolder(id);
    out.length = 0;
    assert.equal(await runAdmin(["authority", "list", "--actor", holder], open, io), 0);
    assert.match(out[0], /granted by admin  valid, accepted /);
    assert.equal(await runAdmin(["authority", "grant", holder, "--namespace", cell], open, io), 2);
    assert.equal(await runAdmin(["authority", "revoke", id], open, io), 2);
    out.length = 0;
    assert.equal(await runAdmin(["authority", "revoke", id, "--reason", "owner_left"], open, io), 0);
    assert.match(out[0], /can no longer approve/);
    out.length = 0;
    assert.equal(await runAdmin(["authority", "list", "--actor", holder, "--all"], open, io), 0);
    assert.match(out[0], /revoked .* \(owner_left\)$/);
  });

  test("the erasure ledger shows who asked and who decided, never the text, and the admin can't erase", async () => {
    const k = await admin.mintKey({ namespace: cell, actor: `claude-${run}` });
    const text = `Erasure ledger check ${run}: a phone number`;
    const m = await store.remember(k.key, { content: text });
    const asked = await store.requestErasure(k.key, { memoryIds: [m.id], reason: "owner_request" });
    const rows = await admin.listErasures({ namespace: city, sinceMs: 3_600_000 });
    const mine = rows.find((r) => r.id === asked.request_id)!;
    assert.deepEqual([mine.namespace, mine.reason, mine.state, mine.requested_by, mine.memories, mine.tombstones],
      [cell, "owner_request", "proposed", `claude-${run}`, 1, 0]);
    assert.ok(!JSON.stringify(rows).includes("phone number"), "no text in the ledger");
    await refused(admin.listErasures({ limit: 1001 }), /limit/);

    const out: string[] = [];
    const io = { out: (l: string) => out.push(l), err: () => undefined };
    const open = () => new AdminClient(new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") }), pepper);
    assert.equal(await runAdmin(["erasure", "list", "--namespace", cell], open, io), 0);
    assert.ok(out.some((l) => l.includes(asked.request_id) && l.includes("waiting for a person to decide")));
    assert.ok(!out.join("\n").includes("phone number"));

    const ops = new pg.Client({ connectionString: urlAs(opsRole, "ops-test-only") });
    await ops.connect();
    try {
      await ops.query("SET ROLE engramport_admin");
      await assert.rejects(ops.query("SELECT memory.erase_chain($1, NULL, 'restore')", [m.id]), /permission denied/);
      await assert.rejects(ops.query("SELECT memory.reapply_erasures($1::uuid[])", [[m.id]]), /permission denied/);
    } finally {
      await ops.end();
    }
    assert.equal((await store.fetch(k.key, m.id)).memory.content, text, "the admin erased nothing");
  });

  test("the export ledger shows who exported what and how much, never content", async () => {
    const ns = (await superPool.query<{ id: string }>("SELECT id FROM memory.namespaces WHERE path = $1", [cell])).rows[0].id;
    const person = (await superPool.query<{ id: string }>(
      "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', $1, $1) RETURNING id", [`exporter-${run}`])).rows[0].id;
    const grant = (await superPool.query<{ id: string }>(
      "INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope) VALUES ($1, $2, 'cell_knowledge') RETURNING id",
      [person, ns])).rows[0].id;
    const id = (await superPool.query<{ id: string }>(
      `INSERT INTO memory.exports (namespace_id, actor_id, authority_id, secret_sha256, sign_in_hash, expires_at,
         started_at, completed_at, counts)
       VALUES ($1, $2, $3, $4, $5, now() + interval '10 minutes', now(), now(), '{"memories": 3, "links": 1}')
       RETURNING id`, [ns, person, grant, randomBytes(32), randomBytes(32)])).rows[0].id;
    const rows = await admin.listExports({ namespace: city, sinceMs: 3_600_000 });
    const mine = rows.find((r) => r.id === id)!;
    assert.deepEqual([mine.namespace, mine.actor, mine.authority_id, mine.counts], [cell, `exporter-${run}`, grant, { memories: 3, links: 1 }]);
    assert.ok(!("secret_sha256" in mine) && !("sign_in_hash" in mine));
    await refused(admin.listExports({ limit: 0 }), /limit/);
    const out: string[] = [];
    const io = { out: (l: string) => out.push(l), err: () => undefined };
    const open = () => new AdminClient(new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") }), pepper);
    assert.equal(await runAdmin(["export", "list", "--namespace", cell], open, io), 0);
    assert.ok(out.some((l) => l.includes(id) && l.includes("3 memories") && l.includes("1 links")));
  });

  test("the restoration ledger shows who restored which memory, never the text, and the admin can't restore", async () => {
    const k = await admin.mintKey({ namespace: cell, actor: `claude-${run}` });
    const m = await store.remember(k.key, { content: `Restoration ledger check ${run}: a private note` });
    await store.retract(k.key, m.id);
    const ns = (await superPool.query<{ id: string }>("SELECT id FROM memory.namespaces WHERE path = $1", [cell])).rows[0].id;
    const person = (await superPool.query<{ id: string }>(
      "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', $1, $1) RETURNING id", [`restorer-${run}`])).rows[0].id;
    const authority = (await superPool.query<{ id: string }>(
      "INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope) VALUES ($1, $2, 'cell_knowledge') RETURNING id",
      [person, ns])).rows[0].id;
    const at = (await superPool.query<{ retracted_at: Date }>(
      "SELECT retracted_at FROM memory.memories WHERE id = $1", [m.id])).rows[0].retracted_at;
    const challenge = (await superPool.query<{ id: string }>(
      `INSERT INTO memory.restore_challenges (memory_id, namespace_id, actor_id, authority_id, retracted_at, secret_sha256,
         sign_in_hash, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, now() + interval '10 minutes') RETURNING id`,
      [m.id, ns, person, authority, at, randomBytes(32), randomBytes(32)])).rows[0].id;
    const id = (await superPool.query<{ id: string }>(
      `INSERT INTO memory.restorations (memory_id, namespace_id, restored_by_actor_id, authority_id, challenge_id,
         retracted_at, restored_to)
       VALUES ($1, $2, $3, $4, $5, $6, 'active') RETURNING id`, [m.id, ns, person, authority, challenge, at])).rows[0].id;
    const rows = await admin.listRestorations({ namespace: city, sinceMs: 3_600_000 });
    const mine = rows.find((r) => r.id === id)!;
    assert.deepEqual([mine.namespace, mine.memory_id, mine.restored_by, mine.authority_id, mine.restored_to],
      [cell, m.id, `restorer-${run}`, authority, "active"]);
    assert.ok(!JSON.stringify(rows).includes("private note"), "no text in the ledger");
    await refused(admin.listRestorations({ limit: 0 }), /limit/);
    const out: string[] = [];
    const io = { out: (l: string) => out.push(l), err: () => undefined };
    const open = () => new AdminClient(new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") }), pepper);
    assert.equal(await runAdmin(["restore", "list", "--namespace", cell], open, io), 0);
    assert.ok(out.some((l) => l.includes(id) && l.includes("back to active") && l.includes(`restorer-${run}`)));
    const ops = new pg.Client({ connectionString: urlAs(opsRole, "ops-test-only") });
    await ops.connect();
    try {
      await ops.query("SET ROLE engramport_admin");
      await assert.rejects(ops.query("SELECT secret_sha256 FROM memory.restore_challenges"), /permission denied/);
      await assert.rejects(ops.query(
        "SELECT memory.decide_restore_challenge(gen_random_uuid(), gen_random_uuid(), $1, $2)",
        [challenge, "0".repeat(64)]), /permission denied/);
    } finally {
      await ops.end();
    }
  });

  test("the admin sees delegated grants and can revoke one, and nothing more", async () => {
    const ns = (await superPool.query<{ id: string }>("SELECT id FROM memory.namespaces WHERE path = $1", [cell])).rows[0].id;
    const human = async (slug: string) => (await superPool.query<{ id: string }>(
      "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', $1, $1) RETURNING id", [slug])).rows[0].id;
    const owner = await human(`grantor-${run}`);
    const helper = await human(`helper-${run}`);
    const parent = (await superPool.query<{ id: string }>(
      "INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, can_delegate) VALUES ($1, $2, 'cell_knowledge', true) RETURNING id",
      [owner, ns])).rows[0].id;
    const id = (await superPool.query<{ id: string }>(
      `INSERT INTO memory.data_grants (namespace_id, power, actor_id, granted_by_actor_id, parent_authority_id, expires_at)
       VALUES ($1, 'export', $2, $3, $4, now() + interval '7 days') RETURNING id`, [ns, helper, owner, parent])).rows[0].id;
    const listed = (await admin.listDataGrants({ namespace: city })).find((g) => g.id === id)!;
    assert.deepEqual([listed.power, listed.holder, listed.granted_by, listed.state, listed.valid],
      ["export", `helper-${run}`, `grantor-${run}`, "waiting", false]);
    await refused(admin.revokeDataGrant(id, "Not A Code"), /short code/);
    const out: string[] = [];
    const io = { out: (l: string) => out.push(l), err: () => undefined };
    const open = () => new AdminClient(new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") }), pepper);
    assert.equal(await runAdmin(["grant", "list", "--namespace", cell], open, io), 0);
    assert.ok(out.some((l) => l.includes(id) && l.includes("waiting")));
    assert.equal(await runAdmin(["grant", "revoke", id, "--reason", "audit_finding"], open, io), 0);
    assert.match(out.at(-1)!, /can no longer export/);
    await refused(admin.revokeDataGrant(id, "again"), /already revoked/);
    assert.equal((await admin.listDataGrants({ namespace: city })).some((g) => g.id === id), false, "ended grants are hidden");
    const ended = (await admin.listDataGrants({ namespace: city, includeEnded: true })).find((g) => g.id === id)!;
    assert.deepEqual([ended.state, ended.revoke_reason], ["revoked", "audit_finding"]);
    const ops = new pg.Client({ connectionString: urlAs(opsRole, "ops-test-only") });
    await ops.connect();
    try {
      await ops.query("SET ROLE engramport_admin");
      await assert.rejects(ops.query("UPDATE memory.data_grants SET accepted_at = now() WHERE id = $1", [id]));
      await assert.rejects(ops.query(
        "SELECT memory.grant_data_power(gen_random_uuid(), gen_random_uuid(), $1, $2, 'erase', now() + interval '1 day')",
        [ns, helper]), /permission denied/);
    } finally {
      await ops.end();
    }
  });

  test("the approval trail shows who asked, where and when, and never the text", async () => {
    const k = await admin.mintKey({ namespace: cell, actor: `claude-${run}` });
    const text = `Secret pricing rule for approval ${run}`;
    const m = await store.remember(k.key, { content: text, kind: "decision", claimType: "decision" });
    await store.requestApproval(k.key, m.id);
    const rows = await admin.listApprovals({ namespace: city, sinceMs: 3_600_000 });
    const mine = rows.filter((r) => r.memory_id === m.id);
    assert.deepEqual(mine.map((r) => [r.event, r.namespace, r.actor]), [["requested", cell, `claude-${run}`]]);
    await refused(admin.listApprovals({ limit: 0 }), /limit/);

    const out: string[] = [];
    const io = { out: (l: string) => out.push(l), err: () => undefined };
    const open = () => new AdminClient(new pg.Pool({ connectionString: urlAs(opsRole, "ops-test-only") }), pepper);
    assert.equal(await runAdmin(["approval", "list", "--namespace", cell], open, io), 0);
    const line = out.find((l) => l.includes(m.id))!;
    assert.match(line, new RegExp(`  requested  ${cell}  memory ${m.id}  by claude-${run}$`));
    assert.ok(!out.join("\n").includes("Secret pricing"), "no memory text in the trail");
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
