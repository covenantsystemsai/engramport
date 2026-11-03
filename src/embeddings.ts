/**
 * Embeddings for the Postgres store.
 *
 * Two models, one per namespace (migration 0011 records which):
 *
 *   gte-small               384 dimensions, Supabase's built-in model, run by
 *                           the Edge Function in supabase/functions/embed in the
 *                           same Supabase project. Memory text never leaves
 *                           Supabase. The default for new namespaces.
 *   text-embedding-3-small  1536 dimensions, OpenAI's embeddings API. Text is
 *                           sent to OpenAI. Only for namespaces set to it.
 *
 * The server may have either, both or neither. It embeds a namespace's text
 * only with that namespace's own model, so a namespace set to gte-small is
 * never sent to OpenAI even on a server that has an OpenAI key. Secrets come
 * from the secrets manager at deploy time. Without a provider for a
 * namespace's model the store still works, keyword and graph search only, and
 * says so in each recall.
 */

export const GTE_SMALL = { model: "gte-small", dimension: 384 } as const;
export const OPENAI_SMALL = { model: "text-embedding-3-small", dimension: 1536 } as const;

/** OpenAI's size. Kept for callers that predate gte-small. */
export const EMBEDDING_DIMENSION = OPENAI_SMALL.dimension;

/** The vector sizes the schema indexes. */
export const SUPPORTED_DIMENSIONS: readonly number[] = [GTE_SMALL.dimension, OPENAI_SMALL.dimension];

export interface Embedder {
  readonly model: string;
  readonly dimension: number;
  embed(texts: string[]): Promise<number[][]>;
}

function checkVectors(data: unknown, count: number, dimension: number): number[][] {
  if (
    !Array.isArray(data) ||
    data.length !== count ||
    data.some((v) => !Array.isArray(v) || v.length !== dimension || v.some((x) => typeof x !== "number" || !Number.isFinite(x)))
  ) {
    throw new Error("embedding response did not match the request");
  }
  return data as number[][];
}

const OPENAI_URL = "https://api.openai.com/v1/embeddings";

export function openAIEmbedder(apiKey: string, fetchImpl: typeof fetch = fetch): Embedder {
  const { model, dimension } = OPENAI_SMALL;
  return {
    model,
    dimension,
    async embed(texts: string[]): Promise<number[][]> {
      const res = await fetchImpl(OPENAI_URL, {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ model, input: texts, dimensions: dimension }),
        signal: AbortSignal.timeout(20_000),
      });
      if (!res.ok) {
        // The body can echo request details; keep only the status.
        throw new Error(`embedding request failed with status ${res.status}`);
      }
      const body = (await res.json()) as { data?: Array<{ index: number; embedding: number[] }> };
      const data = [...(body.data ?? [])].sort((a, b) => a.index - b.index);
      return checkVectors(data.map((d) => d.embedding), texts.length, dimension);
    },
  };
}

/**
 * Supabase's built-in gte-small, through the embed Edge Function deployed to
 * the same project as the database. `url` is the function's address,
 * https://<project ref>.supabase.co/functions/v1/embed; `secret` is the shared
 * secret set on both sides, sent as a bearer token.
 */
/** The most text the embed function takes per item (see supabase/functions/embed). */
export const MAX_EMBED_CHARS = 8_000;

export function supabaseEmbedder(url: string, secret: string, fetchImpl: typeof fetch = fetch): Embedder {
  const { model, dimension } = GTE_SMALL;
  return {
    model,
    dimension,
    async embed(texts: string[]): Promise<number[][]> {
      const res = await fetchImpl(url, {
        method: "POST",
        headers: { Authorization: `Bearer ${secret}`, "Content-Type": "application/json" },
        // gte-small reads about the first 512 tokens; the function takes at most
        // MAX_EMBED_CHARS, so longer text is cut here rather than refused there.
        body: JSON.stringify({ input: texts.map((t) => t.slice(0, MAX_EMBED_CHARS)) }),
        signal: AbortSignal.timeout(30_000),
      });
      if (!res.ok) throw new Error(`embedding request failed with status ${res.status}`);
      const body = (await res.json()) as { model?: string; embeddings?: unknown };
      if (body.model !== model) throw new Error("embedding response came from another model");
      return checkVectors(body.embeddings, texts.length, dimension);
    },
  };
}

/** pgvector's text form: [0.1,0.2,...]. Postgres casts it to the column's type. */
export function vectorLiteral(v: number[], dimension: number = v.length): string {
  if (!SUPPORTED_DIMENSIONS.includes(dimension) || v.length !== dimension || v.some((x) => !Number.isFinite(x))) {
    throw new Error("embedding has the wrong size or a non-finite value");
  }
  return `[${v.join(",")}]`;
}
