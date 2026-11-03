/**
 * The extraction job on the Postgres store, with a stand-in extractor, against
 * a real database with the memory schema applied. Same rules as
 * store.pg.test.ts: needs ENGRAMPORT_TEST_DATABASE_URL (a superuser URL to a
 * THROWAWAY database), seeds its own namespaces and keys under random names,
 * and runs every call as engramport_app so row security is what is tested.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import pg from "pg";

import { hashKey, mintKey } from "../src/keys.ts";
import { Extractor, ExtractorError } from "../src/store/extract.ts";
import { PostgresStore, StoreError } from "../src/store/postgres.ts";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const pepper = randomBytes(32);

/** Answers from a table keyed by the memory's text, and counts what it read. */
function fakeExtractor(id: string, answers: Record<string, unknown | Error>): Extractor & { reads: string[] } {
  const reads: string[] = [];
  return {
    id,
    reads,
    async extract({ text }) {
      reads.push(text);
      const a = answers[text];
      if (a instanceof Error) throw a;
      return a ?? { entities: [], relations: [] };
    },
  };
}

describe("extraction job", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const keys: Record<string, string> = {};
  let admin: pg.Pool;
  let appPool: pg.Pool;
  let store: PostgresStore;
  let jobStore: PostgresStore;
  let cell1Id: string;
  let cell2Id: string;

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    const ns = async (slug: string, level: string, parent: string | null) =>
      (
        await admin.query<{ id: string }>(
          "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, $2, $3) RETURNING id",
          [parent, level, slug],
        )
      ).rows[0].id;
    const city = await ns(`ex-${run}`, "city", null);
    const tower = await ns("tower", "tower", city);
    cell1Id = await ns("cell-1", "cell", tower);
    const cell2 = await ns("cell-2", "cell", tower);
    cell2Id = cell2;
    const actor = (
      await admin.query<{ id: string }>(
        "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', $1, $1) RETURNING id",
        [`extract-${run}`],
      )
    ).rows[0].id;
    const key = async (name: string, nsId: string, scopes = ["read", "write"]) => {
      const k = mintKey();
      await admin.query(
        `INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes) VALUES ($1, $2, $3, $4, $5)`,
        [nsId, actor, k.prefix, hashKey(k.key, pepper), scopes],
      );
      keys[name] = k.key;
    };
    await key("tower", tower);
    await key("cell1", cell1Id);
    await key("cell2", cell2);
    await key("readonly", cell1Id, ["read"]);

    const appUrl = new URL(ADMIN_URL!);
    appUrl.username = "engramport_app";
    appUrl.password = "engramport-test-only";
    appPool = new pg.Pool({ connectionString: appUrl.toString() });
    store = new PostgresStore(appPool, { pepper, transport: "streamable_http" });
    jobStore = new PostgresStore(appPool, { pepper, transport: "job" });
  });

  after(async () => {
    await appPool?.end();
    await admin?.end();
  });

  const fails = async (p: Promise<unknown>, code: string) => {
    await assert.rejects(p, (err: unknown) => err instanceof StoreError && err.code === code);
  };

  test("only the job transport, a write key and a valid extractor id may run it", async () => {
    const x = fakeExtractor("test/v1", {});
    await fails(store.extract(keys.cell1, x), "forbidden");
    await fails(jobStore.extract(keys.readonly, x), "forbidden");
    await fails(jobStore.extract(keys.cell1, fakeExtractor("Bad Id!", {})), "invalid");
    await fails(jobStore.extract("ek_nonsense", x), "unauthorized");
    assert.equal(x.reads.length, 0, "nothing was read for a refused run");
  });

  test("new memories are read once and their graph rows are marked extracted", async () => {
    const text = "Grok Bot builds the EngramPort server for AN2B.";
    const m = await store.remember(keys.cell1, { content: text });
    const x = fakeExtractor("test/v1", {
      [text]: {
        entities: [
          { name: "Grok Bot", type: "agent", description: "builder agent" },
          { name: "grok   bot", type: "Agent" },
          { name: "", type: "agent" },
        ],
        relations: [
          { source: { name: "Grok Bot", type: "agent" }, predicate: "Works On", target: { name: "EngramPort", type: "project" },
            confidence: 0.8, evidence: "builds the EngramPort server" },
          { source: { name: "Grok Bot", type: "agent" }, predicate: "made_up", target: { name: "AN2B", type: "company" },
            evidence: "words that are not in the memory" },
          { source: { name: "Grok Bot", type: "agent" }, predicate: "is", target: { name: "grok bot", type: "agent" } },
        ],
        aliases: ["ignored"],
        memoryLinks: [{ to: m.id, kind: "related" }],
      },
    });
    const first = await jobStore.extract(keys.cell1, x);
    assert.equal(first.read, 1);
    assert.equal(first.done, 1);
    assert.equal(first.entities, 3, "Grok Bot, EngramPort and AN2B, each once");
    assert.equal(first.relations, 2, "the self-relation is dropped");

    const rows = await admin.query<{ origin: string; name: string }>(
      "SELECT origin::text, name FROM memory.entities WHERE namespace_id = $1 ORDER BY name",
      [cell1Id],
    );
    assert.deepEqual(rows.rows.map((r) => r.name), ["AN2B", "EngramPort", "Grok Bot"]);
    assert.ok(rows.rows.every((r) => r.origin === "extracted"));
    const rels = await admin.query<{ predicate: string; origin: string; evidence_span: string | null }>(
      "SELECT predicate, origin::text, evidence_span FROM memory.relations WHERE namespace_id = $1 ORDER BY predicate",
      [cell1Id],
    );
    assert.deepEqual(rels.rows, [
      { predicate: "made_up", origin: "extracted", evidence_span: null },
      { predicate: "works_on", origin: "extracted", evidence_span: "builds the EngramPort server" },
    ]);
    const mentions = await admin.query<{ origin: string }>(
      "SELECT origin::text FROM memory.entity_mentions WHERE memory_id = $1", [m.id],
    );
    assert.equal(mentions.rowCount, 3);
    assert.ok(mentions.rows.every((r) => r.origin === "extracted"));
    const extras = await admin.query(
      `SELECT 1 FROM memory.entity_aliases WHERE namespace_id = $1
       UNION ALL SELECT 1 FROM memory.memory_links WHERE namespace_id = $1`,
      [cell1Id],
    );
    assert.equal(extras.rowCount, 0, "the extractor never adds aliases or memory links");
    const prov = await admin.query<{ tool: string; transport: string; client_name: string }>(
      `SELECT p.tool, p.transport::text, p.client_name FROM memory.extraction_runs r
       JOIN memory.provenance p ON p.id = r.provenance_id WHERE r.memory_id = $1`,
      [m.id],
    );
    assert.deepEqual(prov.rows, [{ tool: "extract", transport: "job", client_name: "test/v1" }]);

    const again = await jobStore.extract(keys.cell1, x);
    assert.equal(again.read, 0, "a finished memory is not read again by the same extractor");
    assert.equal(x.reads.length, 1);
    const v2 = fakeExtractor("test/v2", {});
    const other = await jobStore.extract(keys.cell1, v2);
    assert.equal(other.read, 1, "a new extractor version reads it again");
  });

  test("a near spelling reuses an entity the cell can read, a clear miss does not", async () => {
    const tower = await store.link(keys.tower, { entities: [{ name: "Listing workflow", type: "process" }] });
    const towerEnt = tower.entities[0].id;
    const text = "The listing workflows changed and Billing runs on Fridays.";
    await store.remember(keys.cell1, { content: text });
    const x = fakeExtractor("fuzzy/v1", {
      [text]: {
        entities: [{ name: "listing workflows", type: "process" }, { name: "Billing", type: "process" }],
        relations: [{ source: { name: "Billing", type: "process" }, predicate: "follows",
          target: { name: "listing workflows", type: "process" } }],
      },
    });
    const r = await jobStore.extract(keys.cell1, x);
    assert.equal(r.failed, 0);
    assert.ok(x.reads.includes(text));
    const rel = await admin.query<{ target_entity_id: string }>(
      "SELECT target_entity_id FROM memory.relations WHERE namespace_id = $1 AND predicate = 'follows'", [cell1Id],
    );
    assert.equal(rel.rows[0].target_entity_id, towerEnt, "the tower's entity is reused, not duplicated");
    const twins = await admin.query(
      "SELECT 1 FROM memory.entities WHERE namespace_id = $1 AND norm_key = 'listing workflows'", [cell1Id],
    );
    assert.equal(twins.rowCount, 0);
  });

  test("two close candidates are never merged by guess", async () => {
    await store.link(keys.cell1, { entities: [{ name: "Project Alpha", type: "project" }, { name: "Project Alphe", type: "project" }] });
    const text = "Project Alph is late.";
    await store.remember(keys.cell1, { content: text });
    const x = fakeExtractor("fuzzy/v2", { [text]: { entities: [{ name: "Project Alph", type: "project" }] } });
    await jobStore.extract(keys.cell1, x);
    const made = await admin.query<{ origin: string }>(
      "SELECT origin::text FROM memory.entities WHERE namespace_id = $1 AND name = 'Project Alph'", [cell1Id],
    );
    assert.deepEqual(made.rows, [{ origin: "extracted" }], "a new entity, since neither candidate is clearly ahead");
  });

  test("a cell never reads another cell's memories or matches its entities", async () => {
    const secret = `cell two secret ${run}`;
    await store.remember(keys.cell2, { content: secret });
    await store.link(keys.cell2, { entities: [{ name: "Hidden Client", type: "company" }] });
    const text = "Hidden Clients came up today.";
    await store.remember(keys.cell1, { content: text });
    const x = fakeExtractor("iso/v1", { [text]: { entities: [{ name: "Hidden Clients", type: "company" }] } });
    await jobStore.extract(keys.cell1, x);
    assert.ok(!x.reads.includes(secret), "cell 2's memory was never sent to cell 1's extractor");
    const made = await admin.query<{ namespace_id: string }>(
      "SELECT namespace_id FROM memory.entities WHERE name = 'Hidden Clients' AND namespace_id = ANY($1)",
      [[cell1Id, cell2Id]],
    );
    assert.deepEqual(made.rows, [{ namespace_id: cell1Id }], "a new cell 1 entity, not cell 2's");
  });

  test("failures are recorded as a short class and retried a few times", async () => {
    const text = `this memory always fails ${run}`;
    const m = await store.remember(keys.cell1, { content: text });
    const leaky = new Error(`provider said: ${text}`);
    const x = fakeExtractor("fail/v1", { [text]: leaky });
    for (let i = 0; i < 4; i++) await jobStore.extract(keys.cell1, x, { maxAttempts: 3 });
    assert.equal(x.reads.filter((t) => t === text).length, 3, "tried three times, then left alone");
    const runs = await admin.query<{ status: string; error_class: string }>(
      "SELECT status::text, error_class FROM memory.extraction_runs WHERE memory_id = $1", [m.id],
    );
    assert.equal(runs.rowCount, 3);
    assert.ok(runs.rows.every((r) => r.status === "failed" && r.error_class === "error"),
      "an unknown error is stored as a class, never its message");

    const t2 = `bad output ${run}`;
    const m2 = await store.remember(keys.cell1, { content: t2 });
    const timeout = `times out ${run}`;
    const m3 = await store.remember(keys.cell1, { content: timeout });
    await jobStore.extract(keys.cell1, fakeExtractor("fail/v2", { [t2]: "not json", [timeout]: new ExtractorError("timeout") }));
    const classes = await admin.query<{ memory_id: string; error_class: string }>(
      "SELECT memory_id, error_class FROM memory.extraction_runs WHERE extractor = 'fail/v2' AND status = 'failed'",
    );
    const byMem = Object.fromEntries(classes.rows.map((r) => [r.memory_id, r.error_class]));
    assert.equal(byMem[m2.id], "bad_output");
    assert.equal(byMem[m3.id], "timeout");
  });

  test("retracted memories are skipped and the limit caps one pass", async () => {
    const gone = `retracted before reading ${run}`;
    const m = await store.remember(keys.cell1, { content: gone });
    await store.retract(keys.cell1, m.id);
    const x = fakeExtractor("limit/v1", {});
    const capped = await jobStore.extract(keys.cell1, x, { limit: 2 });
    assert.equal(capped.read, 2);
    const rest = await jobStore.extract(keys.cell1, x, { limit: 500 });
    assert.ok(rest.read > 0);
    assert.ok(!x.reads.includes(gone), "a retracted memory is never read");
    assert.equal(new Set(x.reads).size, x.reads.length, "nothing was read twice");
  });

  test("a memory retracted while the extractor reads it is skipped, not written", async () => {
    const text = `retracted mid-read ${run}`;
    const m = await store.remember(keys.cell1, { content: text });
    const x: Extractor = {
      id: "race/v1",
      async extract({ text: t }) {
        if (t === text) await store.retract(keys.cell1, m.id);
        return { entities: [{ name: `Race Entity ${run}`, type: "concept" }] };
      },
    };
    await jobStore.extract(keys.cell1, x, { limit: 500 });
    const runs = await admin.query("SELECT 1 FROM memory.extraction_runs WHERE memory_id = $1", [m.id]);
    assert.equal(runs.rowCount, 0);
    const made = await admin.query("SELECT 1 FROM memory.entity_mentions WHERE memory_id = $1", [m.id]);
    assert.equal(made.rowCount, 0);
  });

  test("two jobs at once never write the same memory twice", async () => {
    const text = `contended ${run}`;
    const m = await store.remember(keys.cell1, { content: text });
    const answer = { entities: [{ name: `Contended ${run}`, type: "concept" }] };
    const a = fakeExtractor("race/v2", { [text]: answer });
    const b = fakeExtractor("race/v2", { [text]: answer });
    await Promise.all([jobStore.extract(keys.cell1, a, { limit: 500 }), jobStore.extract(keys.cell1, b, { limit: 500 })]);
    const runs = await admin.query("SELECT 1 FROM memory.extraction_runs WHERE memory_id = $1 AND status = 'done'", [m.id]);
    assert.equal(runs.rowCount, 1);
  });
});
