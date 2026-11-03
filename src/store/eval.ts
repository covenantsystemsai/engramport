/**
 * Retrieval evals: a set of questions with the memories that answer them, run
 * against a namespace through the same recall a real agent uses, scored as
 * recall@k and mean reciprocal rank per mode. Used by the test suite on a made-up set, and meant for
 * the pilot's own set of real questions once its namespace holds memories.
 * Scores are about ids only; no memory text is printed or stored.
 */
import type { PostgresStore, RecallMode } from "./postgres.js";

export interface EvalQuestion {
  question: string;
  /** Ids of the memories a good answer needs. */
  expect: string[];
}

export interface EvalResult {
  mode: RecallMode;
  k: number;
  /** Mean over questions of the share of expected memories in the top k. */
  recall: number;
  /** Mean over questions of 1 / the rank of the first expected memory (0 when none is in the top k). */
  mrr: number;
  perQuestion: Array<{ question: string; found: number; expected: number }>;
}

export function recallAtK(got: string[], expect: string[], k: number): number {
  if (!expect.length) return 1;
  const top = new Set(got.slice(0, k));
  return expect.filter((id) => top.has(id)).length / expect.length;
}

export function reciprocalRank(got: string[], expect: string[], k: number): number {
  if (!expect.length) return 1;
  const want = new Set(expect);
  const i = got.slice(0, k).findIndex((id) => want.has(id));
  return i < 0 ? 0 : 1 / (i + 1);
}

export async function runEval(
  store: PostgresStore, key: string, questions: EvalQuestion[], mode: RecallMode, k = 10,
): Promise<EvalResult> {
  const perQuestion: EvalResult["perQuestion"] = [];
  let total = 0;
  let rr = 0;
  for (const q of questions) {
    const r = await store.recall(key, { query: q.question, mode, topK: k });
    const got = r.results.map((x) => x.id as string);
    const share = recallAtK(got, q.expect, k);
    total += share;
    rr += reciprocalRank(got, q.expect, k);
    perQuestion.push({ question: q.question, found: Math.round(share * q.expect.length), expected: q.expect.length });
  }
  const n = questions.length;
  return { mode, k, recall: n ? total / n : 1, mrr: n ? rr / n : 1, perQuestion };
}
