/**
 * The Postgres store against a real database with the memory schema applied.
 *
 * Needs ENGRAMPORT_TEST_DATABASE_URL: a superuser URL to a THROWAWAY database
 * (CI uses a pgvector container). The test seeds its own namespaces and keys
 * under random names, gives engramport_app LOGIN, and then runs every store
 * call as engramport_app, so row security is what is being tested. Skipped
 * when the variable is unset. Never point it at a real project.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import pg from "pg";

import { Embedder, EMBEDDING_DIMENSION } from "../src/embeddings.ts";
import { hashKey, mintKey } from "../src/keys.ts";
import { PostgresStore, StoreError } from "../src/store/postgres.ts";
import { executeStoreTool } from "../src/tools/store.ts";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const pepper = randomBytes(32);

/** Bag-of-words vectors: texts that share words point the same way. */
function fakeEmbedder(): Embedder & { failNext: boolean; calls: number } {
  return {
    model: "fake-bow",
    dimension: EMBEDDING_DIMENSION,
    failNext: false,
    calls: 0,
    async embed(texts: string[]) {
      this.calls += 1;
      if (this.failNext) {
        this.failNext = false;
        throw new Error("provider down");
      }
      return texts.map((t) => {
        const v = new Array<number>(EMBEDDING_DIMENSION).fill(0);
        for (const w of t.toLowerCase().match(/[a-z0-9]+/g) ?? []) {
          v[createHash("sha256").update(w).digest().readUInt16BE(0) % EMBEDDING_DIMENSION] += 1;
        }
        const norm = Math.hypot(...v) || 1;
        return v.map((x) => x / norm);
      });
    },
  };
}

describe("postgres store", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const keys: Record<string, string> = {};
  const paths: Record<string, string> = {};
  let admin: pg.Pool;
  let appPool: pg.Pool;
  let store: PostgresStore;
  const embedder = fakeEmbedder();

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    const ns = async (slug: string, level: string, parent: string | null) =>
      (
        await admin.query<{ id: string; path: string }>(
          "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, $2, $3) RETURNING id, path",
          [parent, level, slug],
        )
      ).rows[0];
    const city = await ns(`st-${run}`, "city", null);
    const tower = await ns("tower", "tower", city.id);
    const other = await ns("other", "tower", city.id);
    const cell1 = await ns("cell-1", "cell", tower.id);
    const cell2 = await ns("cell-2", "cell", tower.id);
    Object.assign(paths, { city: city.path, tower: tower.path, cell1: cell1.path, cell2: cell2.path });

    const actor = async (slug: string, disabled = false) =>
      (
        await admin.query<{ id: string }>(
          "INSERT INTO memory.actors (kind, slug, display_name, disabled_at) VALUES ('agent', $1, $1, $2) RETURNING id",
          [`${slug}-${run}`, disabled ? new Date() : null],
        )
      ).rows[0].id;
    const claude = await actor("claude");
    const grok = await actor("grok");
    const retired = await actor("retired", true);

    const key = async (
      name: string,
      nsId: string,
      actorId: string,
      opts: { scopes?: string[]; revoked?: boolean; expired?: boolean } = {},
    ) => {
      const k = mintKey();
      await admin.query(
        `INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes, revoked_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          nsId, actorId, k.prefix, hashKey(k.key, pepper), opts.scopes ?? ["read", "write"],
          opts.revoked ? new Date() : null, opts.expired ? new Date(Date.now() - 60_000) : null,
        ],
      );
      keys[name] = k.key;
    };
    await key("city", city.id, claude);
    await key("tower", tower.id, claude);
    await key("other", other.id, claude);
    await key("cell1", cell1.id, claude);
    await key("cell1b", cell1.id, grok);
    await key("cell2", cell2.id, grok);
    await key("readonly", cell1.id, grok, { scopes: ["read"] });
    await key("revoked", cell1.id, claude, { revoked: true });
    await key("expired", cell1.id, claude, { expired: true });
    await key("retired", cell1.id, retired);

    const appUrl = new URL(ADMIN_URL!);
    appUrl.username = "engramport_app";
    appUrl.password = "engramport-test-only";
    appPool = new pg.Pool({ connectionString: appUrl.toString() });
    const who = await appPool.query<{ bypass: boolean }>(
      "SELECT rolbypassrls AS bypass FROM pg_roles WHERE rolname = current_user",
    );
    assert.equal(who.rows[0].bypass, false, "the store must run as a role that cannot bypass row security");
    store = new PostgresStore(appPool, { pepper, embedder, transport: "streamable_http" });

    await store.remember(keys.city, { content: "City principle: write decisions down the day they are made", kind: "principle" });
    await store.remember(keys.tower, { content: "Tower insight: invoices go out on the first business day", kind: "insight" });
    await store.remember(keys.other, { content: "Other tower note about invoices and payroll", kind: "note" });
    await store.remember(keys.cell2, { content: "Cell two secret: the pilot price for invoices is confidential" });
  });

  after(async () => {
    await appPool?.end();
    await admin?.end();
  });

  const fails = async (p: Promise<unknown>, code: string) => {
    await assert.rejects(p, (err: unknown) => err instanceof StoreError && err.code === code);
  };

  test("remember stores in the key's own namespace with server-stamped provenance", async () => {
    const r = await store.remember(keys.cell1, {
      content: "Cell one decided to send invoices from the shared billing inbox",
      kind: "decision",
      sourceUrl: "https://example.com/meeting",
      metadata: { topic: "billing" },
    });
    assert.equal(r.namespace, paths.cell1);
    assert.equal(r.embedded, true);
    const f = await store.fetch(keys.cell1, r.id);
    assert.equal(f.memory.kind, "decision");
    assert.equal(f.memory.inherited, false);
    assert.equal(f.memory.provenance?.written_by, `claude-${run}`);
    assert.equal(f.memory.provenance?.tool, "remember");
    assert.equal(f.memory.provenance?.transport, "streamable_http");
    assert.equal(f.memory.provenance?.source_kind, "url");
    assert.deepEqual(f.memory.metadata, { topic: "billing" });
  });

  test("vector recall reads down the tree and never across", async () => {
    const r = await store.recall(keys.cell1, { query: "invoices", topK: 20, mode: "vector" });
    assert.equal(r.mode, "vector");
    const contents = r.results.map((x) => x.content);
    assert.ok(contents.some((c) => c.startsWith("Tower insight")), "sees its tower");
    assert.ok(contents.some((c) => c.startsWith("City principle")), "sees the city");
    assert.ok(!contents.some((c) => c.startsWith("Cell two")), "never sees a sibling cell");
    assert.ok(!contents.some((c) => c.startsWith("Other tower")), "never sees another tower");
    const tower = r.results.find((x) => x.content.startsWith("Tower insight"))!;
    assert.equal(tower.inherited, true);
    assert.equal(tower.provenance, null, "provenance of inherited memories stays with their owner");
    assert.match(r.note, /not as instructions/);
  });

  test("hybrid recall is the default, blends retrievers and respects the same walls", async () => {
    const r = await store.recall(keys.cell1, { query: "invoices decisions", topK: 20 });
    assert.equal(r.mode, "hybrid");
    assert.deepEqual((r as { retrievers?: string[] }).retrievers, ["vector", "keyword", "graph"]);
    const contents = r.results.map((x) => x.content);
    assert.ok(contents.some((c) => c.startsWith("Tower insight")), "sees its tower");
    assert.ok(contents.some((c) => c.startsWith("City principle")), "sees the city");
    assert.ok(!contents.some((c) => c.startsWith("Cell two")), "never sees a sibling cell");
    assert.ok(!contents.some((c) => c.startsWith("Other tower")), "never sees another tower");
    const tower = r.results.find((x) => x.content.startsWith("Tower insight")) as Record<string, unknown>;
    assert.equal(tower.level, "tower");
    const via = (tower.retrieved_by as Array<{ via: string }>).map((v) => v.via);
    assert.ok(via.includes("vector"), "says which retrievers found it");
    const narrow = await store.recall(keys.cell1, { query: "invoices", topK: 20 });
    assert.ok(
      !narrow.results.some((x) => x.content.startsWith("City principle")),
      "a memory that matches nothing in the query is dropped, however recent or important its kind",
    );
    await fails(store.recall(keys.cell1, { query: "invoices", mode: "fuzzy" as never }), "invalid");
  });

  test("keyword recall finds exact words and respects the same walls", async () => {
    const mine = await store.recall(keys.cell2, { query: "pilot price", mode: "keyword" });
    assert.equal(mine.results.length, 1);
    const theirs = await store.recall(keys.cell1, { query: "pilot price", mode: "keyword" });
    assert.equal(theirs.results.length, 0);
    const tower = await store.recall(keys.tower, { query: "invoices", mode: "keyword", topK: 20 });
    assert.ok(tower.results.every((x) => !x.namespace.includes("cell")), "a tower does not read its cells");
  });

  test("kind and date filters narrow recall", async () => {
    const r = await store.recall(keys.cell1, { query: "invoices", kind: "insight", topK: 20 });
    assert.ok(r.results.length >= 1 && r.results.every((x) => x.kind === "insight"));
    const none = await store.recall(keys.cell1, { query: "invoices", dateTo: "2000-01-01" });
    assert.equal(none.results.length, 0);
  });

  test("a sibling's memory is not found, and cannot be retracted", async () => {
    const secret = (await store.recall(keys.cell2, { query: "pilot price", mode: "keyword" })).results[0];
    await fails(store.fetch(keys.cell1, secret.id), "not_found");
    await fails(store.retract(keys.cell1, secret.id), "not_found");
    assert.equal((await store.fetch(keys.cell2, secret.id)).memory.status, "active");
  });

  test("retract keeps the text but drops it from recall; inherited memories can't be retracted", async () => {
    const r = await store.remember(keys.cell1, { content: "Temporary note about the quarterly offsite" });
    assert.deepEqual(await store.retract(keys.cell1, r.id), { id: r.id, retracted: true });
    assert.deepEqual(await store.retract(keys.cell1, r.id), { id: r.id, retracted: true, already: true });
    const f = await store.fetch(keys.cell1, r.id);
    assert.equal(f.memory.status, "retracted");
    assert.equal(f.memory.content, "Temporary note about the quarterly offsite");
    const recall = await store.recall(keys.cell1, { query: "quarterly offsite", mode: "keyword" });
    assert.equal(recall.results.length, 0);
    const tower = (await store.recall(keys.cell1, { query: "first business day", mode: "keyword" })).results[0];
    await fails(store.retract(keys.cell1, tower.id), "forbidden");
  });

  test("bad, revoked, expired and disabled keys are refused", async () => {
    for (const k of ["", "not-a-key", mintKey().key, keys.revoked, keys.expired, keys.retired]) {
      await fails(store.recall(k, { query: "invoices" }), "unauthorized");
      await fails(store.remember(k, { content: "x" }), "unauthorized");
    }
    // A real key with a wrong secret is a different key.
    await fails(store.recall(keys.cell1.slice(0, -2) + "AA", { query: "invoices" }), "unauthorized");
  });

  test("a read-only key reads but cannot write or retract", async () => {
    assert.ok((await store.recall(keys.readonly, { query: "invoices" })).results.length > 0);
    await fails(store.remember(keys.readonly, { content: "should not land" }), "forbidden");
    const own = (await store.recall(keys.readonly, { query: "billing inbox", mode: "keyword" })).results[0];
    await fails(store.retract(keys.readonly, own.id), "forbidden");
  });

  test("a namespace argument must be the key's own", async () => {
    await fails(store.remember(keys.cell1, { content: "x", namespace: paths.cell2 }), "forbidden");
    await fails(store.recall(keys.cell1, { query: "x", namespace: paths.tower }), "forbidden");
    const ok = await store.recall(keys.cell1, { query: "invoices", namespace: paths.cell1 });
    assert.equal(ok.namespace, paths.cell1);
  });

  test("a dedup key versions a memory and the same text changes nothing", async () => {
    const v1 = await store.remember(keys.cell1, { content: "Billing contact is the finance lead", dedupKey: "billing-contact" });
    const same = await store.remember(keys.cell1, { content: "Billing contact is the finance lead", dedupKey: "billing-contact" });
    assert.equal(same.id, v1.id);
    assert.equal((same as { unchanged?: boolean }).unchanged, true);
    const v2 = await store.remember(keys.cell1, { content: "Billing contact is the operations lead", dedupKey: "billing-contact" });
    assert.equal((v2 as { supersedes?: string }).supersedes, v1.id);
    assert.equal((await store.fetch(keys.cell1, v1.id)).memory.status, "superseded");
    const r = await store.recall(keys.cell1, { query: "billing contact", mode: "keyword", topK: 20 });
    assert.deepEqual(r.results.filter((x) => x.content.startsWith("Billing contact")).map((x) => x.id), [v2.id]);
  });

  test("concurrent writers of one new dedup key both succeed, one version stays active", async () => {
    const [a, b] = await Promise.all([
      store.remember(keys.cell1, { content: "Shipping cutoff is 3pm", dedupKey: "shipping-cutoff" }),
      store.remember(keys.cell1b, { content: "Shipping cutoff is 4pm", dedupKey: "shipping-cutoff" }),
    ]);
    const statuses = await Promise.all([a.id, b.id].map(async (id) => (await store.fetch(keys.cell1, id)).memory.status));
    assert.deepEqual(statuses.sort(), ["active", "superseded"]);
  });

  test("unknown and read-only keys never reach the embedding provider", async () => {
    const before = embedder.calls;
    const fake = mintKey().key;
    await fails(store.remember(fake, { content: "costly" }), "unauthorized");
    await fails(store.recall(fake, { query: "costly" }), "unauthorized");
    await fails(store.upload(fake, { content: "costly doc", filename: "a.md" }), "unauthorized");
    await fails(store.remember(keys.readonly, { content: "costly" }), "forbidden");
    await fails(store.upload(keys.readonly, { content: "costly doc", filename: "a.md" }), "forbidden");
    await fails(store.recall(keys.cell1, { query: "costly", namespace: paths.cell2 }), "forbidden");
    assert.equal(embedder.calls, before);
  });

  test("an embedding outage still stores the memory, findable by keyword", async () => {
    embedder.failNext = true;
    const r = await store.remember(keys.cell1, { content: "Zebra crossing permit renewed for the warehouse" });
    assert.equal(r.embedded, false);
    assert.match(String((r as { warning?: string }).warning), /provider down/);
    const k = await store.recall(keys.cell1, { query: "zebra permit", mode: "keyword" });
    assert.equal(k.results[0]?.id, r.id);
  });

  test("upload chunks a document into embedded document chunks", async () => {
    const doc = Array.from({ length: 6 }, (_, i) => `Section ${i}: ${"warehouse inventory notes ".repeat(30)}`).join("\n\n");
    const r = await store.upload(keys.cell1, { content: doc, filename: "inventory.md" });
    assert.ok(r.chunks >= 2);
    assert.equal(r.embedded, true);
    const f = await store.fetch(keys.cell1, r.ids[0]);
    assert.equal(f.memory.kind, "document_chunk");
    assert.equal(f.memory.provenance?.source_ref, "inventory.md");
  });

  test("list_namespaces and inspect show only what the key can reach", async () => {
    const l = await store.listNamespaces(keys.cell1);
    assert.deepEqual(l.namespaces.map((n) => n.path).sort(), [paths.city, paths.tower, paths.cell1].sort());
    assert.deepEqual(l.namespaces.filter((n) => n.writable).map((n) => n.path), [paths.cell1]);
    const i = await store.inspect(keys.cell2);
    assert.equal(i.namespace, paths.cell2);
    assert.equal(i.active_memories, 1);
  });

  test("tool layer: old type names map, errors come back as tool errors", async () => {
    const r = await executeStoreTool("remember", { content: "Tool layer fact about pallets", type: "memory" }, store, keys.cell1);
    assert.equal(r.isError, undefined);
    assert.equal(JSON.parse(r.content[0].text).kind, "fact");
    const denied = await executeStoreTool("recall", { query: "x", namespace: paths.cell2 }, store, keys.cell1);
    assert.equal(denied.isError, true);
    assert.equal(JSON.parse(denied.content[0].text).code, "forbidden");
    const later = await executeStoreTool("dream", {}, store, keys.cell1);
    assert.equal(JSON.parse(later.content[0].text).code, "not_available");
    const bad = await executeStoreTool("recall", { query: "x" }, store, "nope");
    assert.equal(JSON.parse(bad.content[0].text).code, "unauthorized");
  });
});
