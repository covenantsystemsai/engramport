// The Supabase built-in embedder's client side and its settings: it sends the
// shared secret, cuts long text before sending, and refuses answers that are
// from another model or the wrong size. No network: fetch is stubbed.
import { test } from "node:test";
import assert from "node:assert/strict";

import { configProblems, resolveConfig } from "../src/config.ts";
import { MAX_EMBED_CHARS, openAIEmbedder, supabaseEmbedder, vectorLiteral } from "../src/embeddings.ts";

const URL_ = "https://abc.supabase.co/functions/v1/embed";
const SECRET = "s".repeat(40);

function stub(reply: (body: { input: string[] }) => { status?: number; json: unknown }) {
  const calls: Array<{ url: string; headers: Record<string, string>; body: { input: string[] } }> = [];
  const fetchImpl = (async (url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    calls.push({ url, headers: init.headers as Record<string, string>, body });
    const r = reply(body);
    return new Response(JSON.stringify(r.json), { status: r.status ?? 200 });
  }) as unknown as typeof fetch;
  return { calls, fetchImpl };
}

const vec = (n: number) => Array.from({ length: n }, (_, i) => (i % 7) / 7);

test("supabaseEmbedder sends the secret and the text, and returns 384 vectors", async () => {
  const { calls, fetchImpl } = stub((b) => ({ json: { model: "gte-small", embeddings: b.input.map(() => vec(384)) } }));
  const e = supabaseEmbedder(URL_, SECRET, fetchImpl);
  assert.equal(e.model, "gte-small");
  assert.equal(e.dimension, 384);
  const out = await e.embed(["one", "two"]);
  assert.equal(out.length, 2);
  assert.equal(out[0].length, 384);
  assert.equal(calls[0].url, URL_);
  assert.equal(calls[0].headers.Authorization, `Bearer ${SECRET}`);
  assert.deepEqual(calls[0].body, { input: ["one", "two"] });
});

test("supabaseEmbedder cuts long text to what the function takes", async () => {
  const { calls, fetchImpl } = stub((b) => ({ json: { model: "gte-small", embeddings: b.input.map(() => vec(384)) } }));
  await supabaseEmbedder(URL_, SECRET, fetchImpl).embed(["x".repeat(MAX_EMBED_CHARS + 500)]);
  assert.equal(calls[0].body.input[0].length, MAX_EMBED_CHARS);
});

test("supabaseEmbedder refuses another model, a wrong size, a short answer and an error status", async () => {
  const cases: Array<[unknown, number | undefined, RegExp]> = [
    [{ model: "text-embedding-3-small", embeddings: [vec(384)] }, undefined, /another model/],
    [{ model: "gte-small", embeddings: [vec(1536)] }, undefined, /did not match/],
    [{ model: "gte-small", embeddings: [] }, undefined, /did not match/],
    [{ model: "gte-small", embeddings: [[...vec(383), Number.NaN]] }, undefined, /did not match/],
    [{ error: "unauthorized" }, 401, /status 401/],
  ];
  for (const [json, status, want] of cases) {
    const { fetchImpl } = stub(() => ({ json, status }));
    await assert.rejects(supabaseEmbedder(URL_, SECRET, fetchImpl).embed(["one"]), want);
  }
});

test("the OpenAI embedder keeps its 1536 size", async () => {
  const { fetchImpl } = stub(() => ({ json: { data: [{ index: 0, embedding: vec(1536) }] } }));
  const e = openAIEmbedder("sk-test", fetchImpl);
  assert.equal(e.model, "text-embedding-3-small");
  assert.equal((await e.embed(["one"]))[0].length, 1536);
});

test("vectorLiteral takes only the sizes the schema indexes", () => {
  assert.match(vectorLiteral(vec(384), 384), /^\[/);
  assert.match(vectorLiteral(vec(1536)), /^\[/);
  assert.throws(() => vectorLiteral(vec(768)), /wrong size/);
  assert.throws(() => vectorLiteral(vec(384), 1536), /wrong size/);
});

const pg = (o: Record<string, string>) =>
  resolveConfig({
    ENGRAMPORT_STORE: "postgres",
    ENGRAMPORT_KEY_PEPPER: "p".repeat(64),
    ENGRAMPORT_DATABASE_URL: "postgresql://engramport_app@db.example.com:5432/postgres",
    ...o,
  } as unknown as NodeJS.ProcessEnv);

test("embed settings: both or neither, https, a long secret, no query or credentials", () => {
  assert.deepEqual(configProblems(pg({}), "http"), []);
  assert.deepEqual(configProblems(pg({ ENGRAMPORT_EMBED_URL: URL_, ENGRAMPORT_EMBED_SECRET: SECRET }), "http"), []);
  const problems = (o: Record<string, string>) => configProblems(pg(o), "http").join(" | ");
  assert.match(problems({ ENGRAMPORT_EMBED_URL: URL_ }), /ENGRAMPORT_EMBED_SECRET is not set/);
  assert.match(problems({ ENGRAMPORT_EMBED_SECRET: SECRET }), /ENGRAMPORT_EMBED_URL is not/);
  assert.match(problems({ ENGRAMPORT_EMBED_URL: URL_, ENGRAMPORT_EMBED_SECRET: "short" }), /shorter than 32/);
  assert.match(
    problems({ ENGRAMPORT_EMBED_URL: "http://abc.supabase.co/functions/v1/embed", ENGRAMPORT_EMBED_SECRET: SECRET }),
    /must use https/,
  );
  assert.match(problems({ ENGRAMPORT_EMBED_URL: `${URL_}?k=1`, ENGRAMPORT_EMBED_SECRET: SECRET }), /no query or credentials/);
});
