/**
 * Retrieval benchmark for Supabase's built-in embedding model, gte-small.
 *
 * Seeds a throwaway namespace tree with test/fixtures/eval-basic.json, then
 * asks its tuned questions, the held-out ones in test/fixtures/eval-heldout.json
 * and the fresh ones in test/fixtures/eval-fresh.json (written after hybrid was
 * tuned, never tuned on). It seeds a second, separate tree with
 * test/fixtures/eval-realty.json, a made-up brokerage's operating knowledge with
 * its own questions, also never tuned on. Every question goes through the same
 * recall an agent uses, and the report gives recall@1, recall@3, recall@5 and
 * MRR for each retriever:
 *
 *   keyword                   full-text only
 *   graph                     entities and relations only
 *   keyword + graph           hybrid recall with no embeddings (what a
 *                             namespace gets with no model)
 *   vector (gte-small)        meaning only
 *   hybrid (gte-small)        all three, the default recall
 *
 * plus how long each query took to embed and to recall.
 *
 * After the quality numbers it runs trust checks on the brokerage tree with
 * the model switched on, and the job fails if any of them fails:
 *
 *   cell walls       a sibling cell's key, and a key in another city, ask every
 *                    brokerage question through every retriever and get none
 *                    of the memories they may not read
 *   retraction       a retracted memory stops coming back from every retriever
 *   supersession     after a memory is superseded, only the new version comes
 *                    back, and the old one from no retriever
 *   never-store      hostile writes are refused with embeddings on, and no
 *                    memory or embedding row is added The model runs on this
 * machine through transformers.js, with the same gte-small weights Supabase
 * publishes, so no text goes to any outside service and no secret is needed;
 * timings are this machine's, not Supabase's Edge Functions'.
 *
 * Needs BENCH_DATABASE_URL: a superuser URL to a THROWAWAY database with the
 * migrations applied (CI uses a pgvector container). Never a real project.
 * BENCH_EMBEDDER=fake swaps the model for a bag-of-words stand-in, to check
 * the plumbing where the model can't be downloaded.
 *
 * Run: npx tsx bench/embeddings.ts
 */
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";
import pg from "pg";

import { Embedder, GTE_SMALL } from "../src/embeddings.ts";
import { hashKey, mintKey } from "../src/keys.ts";
import { recallAtK, reciprocalRank } from "../src/store/eval.ts";
import { PostgresStore, RecallMode, StoreError } from "../src/store/postgres.ts";

const ADMIN_URL = process.env.BENCH_DATABASE_URL;
if (!ADMIN_URL) {
  console.error("Set BENCH_DATABASE_URL to a throwaway database with the migrations applied.");
  process.exit(2);
}
const MODEL_REPO = "Supabase/gte-small";
const K = 5;

interface Fixture {
  memories: Array<{ key: string; level: string; kind: string; content: string }>;
  graph: {
    entities: Array<{ name: string; type: string; mentionedIn: string[] }>;
    relations: Array<{ source: string; predicate: string; target: string; confidence: number }>;
  };
  questions: Array<{ question: string; expect: string[] }>;
}
const basic = JSON.parse(readFileSync("test/fixtures/eval-basic.json", "utf8")) as Fixture;
const heldout = JSON.parse(readFileSync("test/fixtures/eval-heldout.json", "utf8")) as Pick<Fixture, "questions">;
const fresh = JSON.parse(readFileSync("test/fixtures/eval-fresh.json", "utf8")) as Pick<Fixture, "questions">;
const realty = JSON.parse(readFileSync("test/fixtures/eval-realty.json", "utf8")) as Fixture;

/** An embedder that times each call, so query latency can be reported. */
type Timed = Embedder & { lastMs: number };

async function gteSmall(): Promise<Timed> {
  if (process.env.BENCH_EMBEDDER === "fake") {
    const { dimension } = GTE_SMALL;
    return {
      ...GTE_SMALL,
      lastMs: 0,
      async embed(texts: string[]) {
        const t = performance.now();
        const out = texts.map((text) => {
          const v = new Array<number>(dimension).fill(0);
          for (const w of text.toLowerCase().match(/[a-z0-9]+/g) ?? []) {
            v[createHash("sha256").update(w).digest().readUInt16BE(0) % dimension] += 1;
          }
          const norm = Math.hypot(...v) || 1;
          return v.map((x) => x / norm);
        });
        this.lastMs = performance.now() - t;
        return out;
      },
    };
  }
  // Installed by the benchmark job only, so it is not a dependency of the package.
  const { pipeline } = (await import("@huggingface/transformers" as string)) as {
    pipeline: (task: string, model: string, opts: Record<string, unknown>) => Promise<
      (texts: string[], opts: Record<string, unknown>) => Promise<{ tolist(): number[][] }>
    >;
  };
  const extract = await pipeline("feature-extraction", MODEL_REPO, { dtype: "fp32" });
  return {
    ...GTE_SMALL,
    lastMs: 0,
    async embed(texts: string[]) {
      const t = performance.now();
      const out = (await extract(texts, { pooling: "mean", normalize: true })).tolist();
      this.lastMs = performance.now() - t;
      return out;
    },
  };
}

function percentile(xs: number[], p: number): number {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
}

async function main(): Promise<void> {
  const run = randomBytes(3).toString("hex");
  const pepper = randomBytes(32);
  const admin = new pg.Pool({ connectionString: ADMIN_URL });
  await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-bench-only'");
  const ns = async (slug: string, level: string, parent: string | null) =>
    (
      await admin.query<{ id: string }>(
        "INSERT INTO memory.namespaces (parent_id, level, slug, embedding_model) VALUES ($1, $2, $3, 'gte-small') RETURNING id",
        [parent, level, slug],
      )
    ).rows[0].id;
  const actor = (
    await admin.query<{ id: string }>(
      "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', $1, $1) RETURNING id",
      [`bench-${run}`],
    )
  ).rows[0].id;
  /** A city with a tower, a cell and a sibling cell, and a key for each. */
  const tree = async (prefix: string): Promise<Record<string, string>> => {
    const city = await ns(`${prefix}-${run}`, "city", null);
    const tower = await ns("tower", "tower", city);
    const cell = await ns("cell", "cell", tower);
    const sibling = await ns("sibling", "cell", tower);
    const keys: Record<string, string> = {};
    for (const [name, nsId] of Object.entries({ city, tower, cell, sibling })) {
      const k = mintKey();
      await admin.query(
        `INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes) VALUES ($1, $2, $3, $4, '{read,write}')`,
        [nsId, actor, k.prefix, hashKey(k.key, pepper)],
      );
      keys[name] = k.key;
    }
    return keys;
  };
  // Separate trees, so neither fixture's memories can answer the other's questions.
  const basicKeys = await tree("bench");
  const realtyKeys = await tree("bench-realty");
  const appUrl = new URL(ADMIN_URL!);
  appUrl.username = "engramport_app";
  appUrl.password = "engramport-bench-only";
  const appPool = new pg.Pool({ connectionString: appUrl.toString() });

  const loadStart = performance.now();
  const embedder = await gteSmall();
  const loadMs = performance.now() - loadStart;
  const withModel = new PostgresStore(appPool, { pepper, transport: "rest", embedders: [embedder] });
  const noModel = new PostgresStore(appPool, { pepper, transport: "rest" });

  /** Writes a fixture's memories and graph through the tools an agent uses. */
  const seed = async (fixture: Fixture, keys: Record<string, string>): Promise<Record<string, string>> => {
    const ids: Record<string, string> = {};
    for (const m of fixture.memories) {
      const r = await withModel.remember(keys[m.level], { content: m.content, kind: m.kind as never });
      if (!r.embedded) throw new Error(`memory ${m.key} was not embedded: ${r.warning}`);
      ids[m.key] = r.id;
    }
    for (const e of fixture.graph.entities) {
      for (const memKey of e.mentionedIn) {
        await withModel.link(keys.cell, { entities: [{ name: e.name, type: e.type }], memoryId: ids[memKey] });
      }
    }
    const typeOf = new Map(fixture.graph.entities.map((e) => [e.name, e.type]));
    await withModel.link(keys.cell, {
      relations: fixture.graph.relations.map((r) => ({
        source: { name: r.source, type: typeOf.get(r.source)! },
        predicate: r.predicate,
        target: { name: r.target, type: typeOf.get(r.target)! },
        confidence: r.confidence,
      })),
    });
    return ids;
  };
  const basicIds = await seed(basic, basicKeys);
  const realtyIds = await seed(realty, realtyKeys);

  const sets: Array<{ name: string; questions: Fixture["questions"]; keys: Record<string, string>; ids: Record<string, string> }> = [
    { name: "tuned", questions: basic.questions, keys: basicKeys, ids: basicIds },
    { name: "held-out", questions: heldout.questions, keys: basicKeys, ids: basicIds },
    { name: "fresh", questions: fresh.questions, keys: basicKeys, ids: basicIds },
    { name: "realty (synthetic)", questions: realty.questions, keys: realtyKeys, ids: realtyIds },
  ];
  const retrievers: Array<{ name: string; store: PostgresStore; mode: RecallMode; embeds: boolean }> = [
    { name: "keyword", store: noModel, mode: "keyword", embeds: false },
    { name: "graph", store: noModel, mode: "graph", embeds: false },
    { name: "keyword + graph", store: noModel, mode: "hybrid", embeds: false },
    { name: "vector (gte-small)", store: withModel, mode: "vector", embeds: true },
    { name: "hybrid (gte-small)", store: withModel, mode: "hybrid", embeds: true },
  ];

  const results: Array<Record<string, unknown>> = [];
  const keyOf = new Map([...Object.entries(basicIds), ...Object.entries(realtyIds)].map(([k, id]) => [id, k]));
  const firstMisses: Array<Record<string, unknown>> = [];
  const embedMs: number[] = [];
  for (const { name: setName, questions, keys, ids } of sets) {
    for (const r of retrievers) {
      let r1 = 0, r3 = 0, r5 = 0, mrr = 0;
      const recallMs: number[] = [];
      const misses: string[] = [];
      for (const q of questions) {
        const expect = q.expect.map((k) => ids[k]);
        embedder.lastMs = Number.NaN;
        const t = performance.now();
        const out = await r.store.recall(keys.cell, { query: q.question, mode: r.mode, topK: K });
        recallMs.push(performance.now() - t);
        if (r.embeds) {
          // A failed embedding leaves hybrid as hybrid but drops the vector
          // retriever, so check for it and for any warning, not only the mode.
          const usedVector = r.mode === "vector" || (out.retrievers ?? []).includes("vector");
          if (out.mode !== r.mode || !usedVector || out.warnings?.length || Number.isNaN(embedder.lastMs)) {
            throw new Error(`${r.name} did not search by meaning: ${out.warnings ?? out.mode}`);
          }
          embedMs.push(embedder.lastMs);
        }
        const got = out.results.map((x) => x.id as string);
        if (r.name === "hybrid (gte-small)" && got[0] !== expect[0]) {
          firstMisses.push({
            set: setName,
            question: q.question,
            expected: q.expect[0],
            expected_rank: got.indexOf(expect[0]) + 1 || null,
            top: out.results.slice(0, 3).map((x) => ({
              key: keyOf.get(x.id as string),
              kind: x.kind,
              score: x.score,
              by: x.retrieved_by,
            })),
          });
        }
        r1 += recallAtK(got, expect, 1);
        r3 += recallAtK(got, expect, 3);
        r5 += recallAtK(got, expect, 5);
        mrr += reciprocalRank(got, expect, K);
        if (recallAtK(got, expect, K) < 1) misses.push(q.question);
      }
      const n = questions.length;
      results.push({
        set: setName, retriever: r.name, questions: n,
        recall_at_1: r1 / n, recall_at_3: r3 / n, recall_at_5: r5 / n, mrr_at_5: mrr / n,
        recall_ms_median: percentile(recallMs, 50), recall_ms_p95: percentile(recallMs, 95),
        missed_in_top_5: misses,
      });
    }
  }
  // Trust checks on the brokerage tree, with the model on. These change the
  // tree (a retraction, a supersession), so they run after the quality numbers.
  const trust: Array<{ check: string; pass: boolean; detail: string }> = [];
  const realtyCellOnly = new Set(realty.memories.filter((m) => m.level === "cell").map((m) => realtyIds[m.key]));
  const realtyAll = new Set(Object.values(realtyIds));
  const askAll = async (key: string, question: string) => {
    const got: string[][] = [];
    for (const r of retrievers) {
      const out = await r.store.recall(key, { query: question, mode: r.mode, topK: K });
      got.push(out.results.map((x) => x.id as string));
    }
    return got;
  };

  // Cell walls: a sibling cell reads its tower and city, never its sibling;
  // another city reads nothing of this one.
  let siblingLeaks = 0, cityLeaks = 0, asked = 0;
  for (const q of realty.questions) {
    for (const got of await askAll(realtyKeys.sibling, q.question)) siblingLeaks += got.filter((id) => realtyCellOnly.has(id)).length;
    for (const got of await askAll(basicKeys.cell, q.question)) cityLeaks += got.filter((id) => realtyAll.has(id)).length;
    asked += retrievers.length;
  }
  trust.push({ check: "cell walls: sibling cell", pass: siblingLeaks === 0,
    detail: `${asked} recalls, ${siblingLeaks} results from the other cell` });
  trust.push({ check: "cell walls: another city", pass: cityLeaks === 0,
    detail: `${asked} recalls, ${cityLeaks} results from the brokerage city` });

  // Retraction: the memory leaves every retriever at once, graph included.
  const retracted = realtyIds.inspection_vendor;
  await withModel.retract(realtyKeys.cell, retracted);
  let afterRetract = 0, retractAsked = 0;
  for (const q of realty.questions.filter((x) => x.expect.includes("inspection_vendor"))) {
    for (const got of await askAll(realtyKeys.cell, q.question)) afterRetract += got.filter((id) => id === retracted).length;
    retractAsked += retrievers.length;
  }
  trust.push({ check: "retraction", pass: afterRetract === 0,
    detail: `${retractAsked} recalls, retracted memory returned ${afterRetract} times` });

  // Supersession: only the new version answers, by meaning, keyword or graph.
  const oldId = realtyIds.open_house;
  const v2 = await withModel.supersede(realtyKeys.cell, {
    memoryId: oldId,
    content: "Open houses now run on Sunday afternoons only, with visitor sign-in on the tablet kiosk.",
    reason: "The schedule changed.",
  });
  const newId = (v2 as { id: string }).id;
  const ohGot = await askAll(realtyKeys.cell, "Which days are open houses held?");
  const oldSeen = ohGot.filter((got) => got.includes(oldId)).length;
  // Where each meaning-based retriever ranks the new version (0 = not in the top 5).
  const newRanks = retrievers.flatMap((r, i) => (r.embeds ? [ohGot[i].indexOf(newId) + 1] : []));
  trust.push({ check: "supersession", pass: oldSeen === 0 && newRanks.every((n) => n > 0),
    detail: `old version returned by ${oldSeen} of ${retrievers.length} retrievers; new version ranked ${newRanks.join(" and ")} by vector and hybrid` });

  // Never-store with embeddings on: refused before anything is stored or embedded.
  const countRows = async () =>
    (await admin.query<{ n: string }>(
      "SELECT (SELECT count(*) FROM memory.memories) + (SELECT count(*) FROM memory.memory_embeddings) AS n",
    )).rows[0].n;
  const before = await countRows();
  // Built at run time, so no scanner mistakes the samples for real ones.
  const d = (n: number) => "4".repeat(n);
  const hostile = [
    `Email the seller at buyer.${"example"}@example.com about the walkthrough.`,
    `Call the listing agent on (919) 555-01${"43"} after the showing.`,
    `Card ${["4111", "1111", "1111", "1111"].join(" ")} paid the inspection fee.`,
    `The client's SSN is ${["123", "45", "6789"].join("-")}.`,
    `password = "${d(4)}-${"secret"}-${d(4)}"`,
  ];
  let refused = 0;
  for (const content of hostile) {
    try {
      await withModel.remember(realtyKeys.cell, { content, kind: "note" as never });
    } catch (err) {
      if (err instanceof StoreError && err.code === "refused") refused += 1;
      else throw err;
    }
  }
  const after = await countRows();
  trust.push({ check: "never-store with embeddings on", pass: refused === hostile.length && after === before,
    detail: `${refused} of ${hostile.length} refused; memory and embedding rows ${before} before, ${after} after` });

  const timing = {
    embedder: process.env.BENCH_EMBEDDER === "fake" ? "fake (plumbing check only)" : `${MODEL_REPO} via transformers.js, fp32`,
    dimension: embedder.dimension,
    model_load_ms: Math.round(loadMs),
    query_embed_ms_median: Number(percentile(embedMs, 50).toFixed(1)),
    query_embed_ms_p95: Number(percentile(embedMs, 95).toFixed(1)),
  };

  const pct = (x: unknown) => `${Math.round(Number(x) * 100)}%`;
  const lines = [
    `## gte-small retrieval benchmark`,
    ``,
    `Embedder: ${timing.embedder}, ${timing.dimension} dimensions. Model load ${timing.model_load_ms} ms; ` +
      `query embedding median ${timing.query_embed_ms_median} ms, p95 ${timing.query_embed_ms_p95} ms (this runner, not Supabase).`,
    ``,
    `| Questions | Retriever | Recall@1 | Recall@3 | Recall@5 | MRR@5 | Recall ms (median) |`,
    `|---|---|---|---|---|---|---|`,
    ...results.map((r) =>
      `| ${r.set} (${r.questions}) | ${r.retriever} | ${pct(r.recall_at_1)} | ${pct(r.recall_at_3)} | ${pct(r.recall_at_5)} | ` +
        `${Number(r.mrr_at_5).toFixed(2)} | ${Number(r.recall_ms_median).toFixed(1)} |`),
    ``,
    `Trust checks (brokerage tree, model on):`,
    ``,
    `| Check | Result | Detail |`,
    `|---|---|---|`,
    ...trust.map((t) => `| ${t.check} | ${t.pass ? "pass" : "FAIL"} | ${t.detail} |`),
    ``,
    `Missed in the top 5 by hybrid (gte-small):`,
    ...results
      .filter((r) => r.retriever === "hybrid (gte-small)")
      .flatMap((r) => (r.missed_in_top_5 as string[]).map((q) => `- ${r.set}: ${q}`)),
  ];
  const report = lines.join("\n");
  console.log(report);
  writeFileSync("bench-results.json", JSON.stringify({ timing, results, trust, hybrid_first_misses: firstMisses }, null, 2));
  // Why hybrid ranked another memory first, for tuning the blend.
  console.log(`\nHybrid (gte-small) questions whose first result was not the expected memory:`);
  for (const m of firstMisses) console.log(JSON.stringify(m));
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${report}\n`);

  await appPool.end();
  await admin.end();
  if (trust.some((t) => !t.pass)) {
    console.error(`Trust checks failed: ${trust.filter((t) => !t.pass).map((t) => t.check).join(", ")}`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
