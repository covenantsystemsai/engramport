/**
 * Each namespace's text goes only to its own embedding model (migration 0011).
 *
 * The server here holds stand-ins for both real providers, under their real
 * model names: gte-small (Supabase's built-in, 384) and text-embedding-3-small
 * (OpenAI, 1536). Each records every text it is sent, so the tests can prove
 * that a gte-small namespace's text never reaches the OpenAI stand-in, even on
 * a server that has both. Needs ENGRAMPORT_TEST_DATABASE_URL, a THROWAWAY
 * database; skipped without it.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import pg from "pg";

import { Embedder, GTE_SMALL, OPENAI_SMALL } from "../src/embeddings.ts";
import { hashKey, mintKey } from "../src/keys.ts";
import { PostgresStore } from "../src/store/postgres.ts";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const pepper = randomBytes(32);

type Spy = Embedder & { seen: string[]; beforeReturn?: () => Promise<void> };

/** Bag-of-words vectors at the model's size, recording every text sent. */
function spy(model: string, dimension: number): Spy {
  return {
    model,
    dimension,
    seen: [],
    async embed(texts: string[]) {
      this.seen.push(...texts);
      if (this.beforeReturn) await this.beforeReturn();
      return texts.map((t) => {
        const v = new Array<number>(dimension).fill(0);
        for (const w of t.toLowerCase().match(/[a-z0-9]+/g) ?? []) {
          v[createHash("sha256").update(w).digest().readUInt16BE(0) % dimension] += 1;
        }
        const norm = Math.hypot(...v) || 1;
        return v.map((x) => x / norm);
      });
    },
  };
}

describe("embedding models per namespace", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const keys: Record<string, string> = {};
  const ids: Record<string, string> = {};
  let admin: pg.Pool;
  let appPool: pg.Pool;
  const gte = spy(GTE_SMALL.model, GTE_SMALL.dimension);
  const openai = spy(OPENAI_SMALL.model, OPENAI_SMALL.dimension);
  let both: PostgresStore;
  let openaiOnly: PostgresStore;

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    const ns = async (slug: string, level: string, parent: string | null, model?: string | null) =>
      (
        await admin.query<{ id: string; embedding_model: string | null }>(
          model === undefined
            ? "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, $2, $3) RETURNING id, embedding_model"
            : "INSERT INTO memory.namespaces (parent_id, level, slug, embedding_model) VALUES ($1, $2, $3, $4) RETURNING id, embedding_model",
          model === undefined ? [parent, level, slug] : [parent, level, slug, model],
        )
      ).rows[0];
    const city = await ns(`em-${run}`, "city", null);
    assert.equal(city.embedding_model, "gte-small", "a new city defaults to Supabase's built-in model");
    const tower = await ns("tower", "tower", city.id, OPENAI_SMALL.model);
    const pilot = await ns("pilot", "cell", tower.id, GTE_SMALL.model);
    const plain = await ns("plain", "cell", tower.id, null);
    const shifting = await ns("shifting", "cell", tower.id, GTE_SMALL.model);
    Object.assign(ids, { city: city.id, tower: tower.id, pilot: pilot.id, plain: plain.id, shifting: shifting.id });

    const actor = (
      await admin.query<{ id: string }>(
        "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', $1, $1) RETURNING id",
        [`em-${run}`],
      )
    ).rows[0].id;
    for (const [name, nsId] of Object.entries(ids)) {
      const k = mintKey();
      await admin.query(
        `INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes) VALUES ($1, $2, $3, $4, '{read,write}')`,
        [nsId, actor, k.prefix, hashKey(k.key, pepper)],
      );
      keys[name] = k.key;
    }
    const appUrl = new URL(ADMIN_URL!);
    appUrl.username = "engramport_app";
    appUrl.password = "engramport-test-only";
    appPool = new pg.Pool({ connectionString: appUrl.toString() });
    both = new PostgresStore(appPool, { pepper, transport: "streamable_http", embedders: [gte, openai] });
    openaiOnly = new PostgresStore(appPool, { pepper, transport: "streamable_http", embedders: [openai] });
  });

  after(async () => {
    await appPool?.end();
    await admin?.end();
  });

  const stored = async (memoryId: string) =>
    (
      await admin.query<{ model: string; dimension: number }>(
        "SELECT model, dimension FROM memory.memory_embeddings WHERE memory_id = $1",
        [memoryId],
      )
    ).rows;

  test("a gte-small namespace's text goes to gte-small only, on a server that also has OpenAI", async () => {
    const text = `Pilot decision ${run}: invoices go out on Fridays`;
    const r = await both.remember(keys.pilot, { content: text, kind: "decision" });
    assert.equal(r.embedded, true);
    assert.ok(gte.seen.includes(text));
    assert.ok(!openai.seen.includes(text), "the pilot's text reached the OpenAI provider");
    assert.deepEqual(await stored(r.id), [{ model: "gte-small", dimension: 384 }]);

    const query = `when do pilot invoices go out ${run}`;
    const found = await both.recall(keys.pilot, { query, mode: "vector", topK: 3 });
    assert.equal(found.mode, "vector");
    assert.equal(found.results[0]?.id, r.id);
    assert.ok(gte.seen.includes(query));
    assert.ok(!openai.seen.includes(query), "the pilot's query reached the OpenAI provider");
  });

  test("an OpenAI namespace's text goes to OpenAI only, and its cells still find it by keyword", async () => {
    const text = `Tower lesson ${run}: quarterly reviews need two approvers`;
    const r = await both.remember(keys.tower, { content: text, kind: "insight" });
    assert.equal(r.embedded, true);
    assert.ok(openai.seen.includes(text));
    assert.ok(!gte.seen.includes(text));
    assert.deepEqual(await stored(r.id), [{ model: "text-embedding-3-small", dimension: 1536 }]);

    // The pilot cell reads its tower, but its query is a gte-small vector, so
    // the tower's OpenAI vector is never compared; keyword search finds it.
    const before = openai.seen.length;
    const found = await both.recall(keys.pilot, { query: `quarterly reviews approvers ${run}`, topK: 5 });
    assert.equal(openai.seen.length, before, "a pilot recall sent its query to OpenAI");
    const hit = found.results.find((x) => x.id === r.id);
    assert.ok(hit, "the tower's memory is found from the cell");
    const via = (hit.retrieved_by ?? []).map((v) => v.via);
    assert.ok(via.includes("keyword") && !via.includes("vector"), JSON.stringify(hit.retrieved_by));
  });

  test("a namespace with no model sends its text nowhere", async () => {
    const gteBefore = gte.seen.length;
    const openaiBefore = openai.seen.length;
    const r = await both.remember(keys.plain, { content: `Plain note ${run}`, kind: "note" });
    assert.equal(r.embedded, false);
    assert.match(String(r.warning), /this namespace stores no embeddings/);
    const found = await both.recall(keys.plain, { query: `plain note ${run}`, mode: "vector" });
    assert.equal(found.mode, "keyword");
    assert.match(String(found.warnings), /stores no embeddings/);
    assert.equal(gte.seen.length, gteBefore);
    assert.equal(openai.seen.length, openaiBefore);
  });

  test("a server without the namespace's provider never falls back to another", async () => {
    const before = openai.seen.length;
    const text = `Pilot note ${run} on a server with only OpenAI`;
    const r = await openaiOnly.remember(keys.pilot, { content: text });
    assert.equal(r.embedded, false);
    assert.match(String(r.warning), /no provider for this namespace's model \(gte-small\)/);
    const found = await openaiOnly.recall(keys.pilot, { query: text });
    assert.match(String(found.warnings), /blended keyword and graph only/);
    assert.equal(openai.seen.length, before, "the pilot's text reached the OpenAI provider");
  });

  test("a model change during a write drops the vector rather than store it under the old model", async () => {
    gte.beforeReturn = async () => {
      gte.beforeReturn = undefined;
      await admin.query("UPDATE memory.namespaces SET embedding_model = 'text-embedding-3-small' WHERE id = $1", [
        ids.shifting,
      ]);
    };
    const r = await both.remember(keys.shifting, { content: `Shifting note ${run}` });
    assert.equal(r.embedded, false);
    assert.match(String(r.warning), /model changed/);
    assert.deepEqual(await stored(r.id), []);
  });
});
