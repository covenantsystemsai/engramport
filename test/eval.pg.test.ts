/**
 * The retrieval eval on a made-up namespace (test/fixtures/eval-basic.json):
 * recall@k for each mode, with a stand-in embedder that knows a few synonyms,
 * so each retriever has questions only it can answer. Same database rules as
 * store.pg.test.ts: needs ENGRAMPORT_TEST_DATABASE_URL pointing at a THROWAWAY
 * database, seeds its own namespaces and keys, and runs as engramport_app.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";

import { Embedder, EMBEDDING_DIMENSION } from "../src/embeddings.ts";
import { hashKey, mintKey } from "../src/keys.ts";
import { EvalQuestion, EvalResult, reciprocalRank, recallAtK, runEval } from "../src/store/eval.ts";
import { PostgresStore, RecallMode } from "../src/store/postgres.ts";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const pepper = randomBytes(32);

interface Fixture {
  memories: Array<{ key: string; level: "cell" | "tower" | "city" | "sibling"; kind: string; content: string }>;
  graph: {
    entities: Array<{ name: string; type: string; mentionedIn: string[] }>;
    relations: Array<{ source: string; predicate: string; target: string; confidence: number }>;
  };
  synonyms: string[][];
  questions: Array<{ question: string; expect: string[] }>;
}
const fixture = JSON.parse(readFileSync(new URL("./fixtures/eval-basic.json", import.meta.url), "utf8")) as Fixture;

const STOP = new Set(["the", "a", "an", "of", "on", "in", "to", "is", "for", "with", "do", "does", "did", "what",
  "when", "who", "how", "i", "are", "and", "our", "their", "after", "each", "every", "get"]);

/** Bag of words, with the fixture's synonym groups folded together. Deterministic, no network. */
function synonymEmbedder(groups: string[][]): Embedder {
  const canon = new Map<string, string>();
  for (const g of groups) for (const w of g) canon.set(w, g[0]);
  const token = (w: string) => canon.get(w) ?? canon.get(w.replace(/s$/, "")) ?? w.replace(/s$/, "");
  return {
    model: "eval-synonyms",
    dimension: EMBEDDING_DIMENSION,
    async embed(texts) {
      return texts.map((t) => {
        const v = new Array<number>(EMBEDDING_DIMENSION).fill(0);
        for (const w of t.toLowerCase().replace(/[^a-z0-9\s]/g, " ").split(/\s+/)) {
          // Like real embeddings, it is weak at exact identifiers: numbers carry no signal.
          if (!w || STOP.has(w) || /\d/.test(w)) continue;
          v[createHash("sha256").update(token(w)).digest().readUInt32BE(0) % EMBEDDING_DIMENSION] += 1;
        }
        const norm = Math.hypot(...v) || 1;
        return v.map((x) => x / norm);
      });
    },
  };
}

describe("retrieval eval", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const keys: Record<string, string> = {};
  const ids: Record<string, string> = {};
  let admin: pg.Pool;
  let appPool: pg.Pool;
  let store: PostgresStore;
  let questions: EvalQuestion[];

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
    const city = await ns(`ev-${run}`, "city", null);
    const tower = await ns("tower", "tower", city);
    const cell = await ns("cell", "cell", tower);
    const sibling = await ns("sibling", "cell", tower);
    await admin.query(
      "INSERT INTO memory.embedding_models VALUES ('eval-synonyms', 1536, true, 'test only') ON CONFLICT DO NOTHING",
    );
    await admin.query("UPDATE memory.namespaces SET embedding_model = 'eval-synonyms' WHERE id = ANY ($1)", [
      [city, tower, cell, sibling],
    ]);
    const actor = (
      await admin.query<{ id: string }>(
        "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', $1, $1) RETURNING id",
        [`eval-${run}`],
      )
    ).rows[0].id;
    for (const [name, nsId] of Object.entries({ city, tower, cell, sibling })) {
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
    store = new PostgresStore(appPool, { pepper, transport: "streamable_http", embedder: synonymEmbedder(fixture.synonyms) });

    for (const m of fixture.memories) {
      const r = await store.remember(keys[m.level], { content: m.content, kind: m.kind as never });
      ids[m.key] = r.id;
    }
    for (const e of fixture.graph.entities) {
      for (const memKey of e.mentionedIn) {
        await store.link(keys.cell, { entities: [{ name: e.name, type: e.type }], memoryId: ids[memKey] });
      }
    }
    const typeOf = new Map(fixture.graph.entities.map((e) => [e.name, e.type]));
    await store.link(keys.cell, {
      relations: fixture.graph.relations.map((r) => ({
        source: { name: r.source, type: typeOf.get(r.source)! },
        predicate: r.predicate,
        target: { name: r.target, type: typeOf.get(r.target)! },
        confidence: r.confidence,
      })),
    });
    questions = fixture.questions.map((q) => ({ question: q.question, expect: q.expect.map((k) => ids[k]) }));
  });

  after(async () => {
    await appPool?.end();
    await admin?.end();
  });

  test("recall@k counts the share of expected memories in the top k", () => {
    assert.equal(recallAtK(["a", "b", "c"], ["a", "c"], 3), 1);
    assert.equal(recallAtK(["a", "b", "c"], ["a", "c"], 1), 0.5);
    assert.equal(recallAtK([], [], 5), 1);
    assert.equal(reciprocalRank(["a", "b", "c"], ["c"], 3), 1 / 3);
    assert.equal(reciprocalRank(["a", "b", "c"], ["c"], 2), 0);
  });

  test("hybrid ranks an answer first for every question, and beats each retriever alone", async () => {
    const res: Partial<Record<RecallMode, Record<number, EvalResult>>> = {};
    for (const mode of ["hybrid", "vector", "keyword", "graph"] as RecallMode[]) {
      res[mode] = {};
      for (const k of [3, 10]) res[mode]![k] = await runEval(store, keys.cell, questions, mode, k);
    }
    const table = Object.entries(res).map(
      ([m, r]) => `${m.padEnd(8)} recall@3 ${r![3].recall.toFixed(2)}  recall@10 ${r![10].recall.toFixed(2)}  mrr ${r![10].mrr.toFixed(2)}`,
    );
    console.log(`retrieval eval (${questions.length} questions)\n${table.join("\n")}`);
    const h = res.hybrid!;
    assert.equal(h[10].recall, 1, "hybrid finds every expected memory in its top 10");
    assert.equal(h[3].recall, 1, "and in its top 3");
    assert.equal(h[10].mrr, 1, "and ranks an expected memory first every time");
    for (const m of ["vector", "keyword", "graph"] as RecallMode[]) {
      assert.ok(h[3].recall >= res[m]![3].recall, `hybrid recalls at least as much as ${m} alone`);
      assert.ok(h[10].mrr > res[m]![10].mrr, `hybrid ranks better than ${m} alone`);
    }
  });

  test("no mode ever returns the sibling cell's memory", async () => {
    for (const mode of ["hybrid", "vector", "keyword", "graph"] as RecallMode[]) {
      for (const q of fixture.questions) {
        const r = await store.recall(keys.cell, { query: q.question, mode, topK: 20 });
        assert.ok(!r.results.some((x) => x.id === ids.sibling), `${mode}: ${q.question}`);
      }
    }
  });
});
