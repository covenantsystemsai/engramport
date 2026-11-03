// EngramPort's embedding function: Supabase's built-in gte-small model, run
// inside the same Supabase project as the memory database, so memory text sent
// here never leaves Supabase.
//
// Called only by the EngramPort server, with the shared secret
// ENGRAMPORT_EMBED_SECRET as a bearer token. The function is deployed with JWT
// verification off (see supabase/config.toml) because the publishable key that
// would pass that check is public; the shared secret is the real check, so no
// one else can use this as free embedding compute or probe it with text.
//
// It logs nothing about a request's text. Deploying it is a live change and is
// not done by the repository; see docs/embeddings.md.

const MODEL = "gte-small";
const DIMENSION = 384;
const MAX_TEXTS = 100;
const MAX_CHARS = 8_000;

// deno-lint-ignore no-explicit-any
const session = new (globalThis as any).Supabase.ai.Session(MODEL);

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

/** Constant-time comparison, so the secret can't be guessed a byte at a time. */
function sameSecret(given: string, expected: string): boolean {
  const a = new TextEncoder().encode(given);
  const b = new TextEncoder().encode(expected);
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

Deno.serve(async (req: Request) => {
  const secret = Deno.env.get("ENGRAMPORT_EMBED_SECRET") ?? "";
  if (secret.length < 32) return json(503, { error: "not configured" });
  if (req.method !== "POST") return json(405, { error: "POST only" });
  const auth = req.headers.get("authorization") ?? "";
  if (!auth.startsWith("Bearer ") || !sameSecret(auth.slice(7), secret)) return json(401, { error: "unauthorized" });

  let input: unknown;
  try {
    input = (await req.json())?.input;
  } catch {
    return json(400, { error: "body must be JSON" });
  }
  if (
    !Array.isArray(input) || input.length === 0 || input.length > MAX_TEXTS ||
    input.some((t) => typeof t !== "string" || !t.trim() || t.length > MAX_CHARS)
  ) {
    return json(400, { error: `input must be 1 to ${MAX_TEXTS} non-empty strings of at most ${MAX_CHARS} characters` });
  }

  try {
    const embeddings: number[][] = [];
    for (const text of input as string[]) {
      const v = await session.run(text, { mean_pool: true, normalize: true });
      const vector = Array.from(v as ArrayLike<number>);
      if (vector.length !== DIMENSION) return json(500, { error: "unexpected embedding size" });
      embeddings.push(vector);
    }
    return json(200, { model: MODEL, embeddings });
  } catch {
    return json(500, { error: "embedding failed" });
  }
});
