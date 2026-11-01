/**
 * Embeddings for the Postgres store.
 *
 * One model for now: OpenAI text-embedding-3-small at 1536 dimensions, the
 * size the memory schema stores. The provider key comes from the secrets
 * manager at deploy time. Without one the store still works, keyword search
 * only, and says so in each recall.
 */

export const EMBEDDING_DIMENSION = 1536;

export interface Embedder {
  readonly model: string;
  readonly dimension: number;
  embed(texts: string[]): Promise<number[][]>;
}

const OPENAI_URL = "https://api.openai.com/v1/embeddings";

export function openAIEmbedder(
  apiKey: string,
  model = "text-embedding-3-small",
  fetchImpl: typeof fetch = fetch,
): Embedder {
  return {
    model,
    dimension: EMBEDDING_DIMENSION,
    async embed(texts: string[]): Promise<number[][]> {
      const res = await fetchImpl(OPENAI_URL, {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ model, input: texts, dimensions: EMBEDDING_DIMENSION }),
        signal: AbortSignal.timeout(20_000),
      });
      if (!res.ok) {
        // The body can echo request details; keep only the status.
        throw new Error(`embedding request failed with status ${res.status}`);
      }
      const body = (await res.json()) as { data?: Array<{ index: number; embedding: number[] }> };
      const data = [...(body.data ?? [])].sort((a, b) => a.index - b.index);
      if (data.length !== texts.length || data.some((d) => d.embedding?.length !== EMBEDDING_DIMENSION)) {
        throw new Error("embedding response did not match the request");
      }
      return data.map((d) => d.embedding);
    },
  };
}

/** pgvector's text form: [0.1,0.2,...]. Postgres casts it to the column's type. */
export function vectorLiteral(v: number[]): string {
  if (v.length !== EMBEDDING_DIMENSION || v.some((x) => !Number.isFinite(x))) {
    throw new Error("embedding has the wrong size or a non-finite value");
  }
  return `[${v.join(",")}]`;
}
