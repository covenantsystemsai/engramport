/**
 * `engramport doctor`: print the resolved settings and check the API answers.
 *
 * Prints only a short key prefix, never the key. Exit code 0 means the
 * settings are usable and the API's /health answered; 1 means something
 * needs fixing, and each problem is printed on its own line.
 */

import { Config, configProblems } from "./config.js";
import { createPool } from "./store/postgres.js";
import { VERSION } from "./server.js";
import { getIdToken } from "./auth.js";

export function keyPreview(key: string): string {
  if (!key) return "(not set)";
  return `${key.slice(0, Math.min(7, Math.floor(key.length / 3)))}… (${key.length} chars)`;
}

/** Host and user of a database URL, never its password. */
export function databasePreview(url: string): string {
  if (!url) return "(not set)";
  try {
    const u = new URL(url);
    return `${decodeURIComponent(u.username) || "(no user)"} @ ${u.hostname}${u.port ? `:${u.port}` : ""}${u.pathname}`;
  } catch {
    return "(not a valid URL)";
  }
}

async function pingDatabase(cfg: Config): Promise<void> {
  const pool = createPool(cfg.databaseUrl, cfg.databaseCaFile || undefined);
  try {
    // The app role must not bypass row security; refuse to call that healthy.
    const r = await pool.query<{ bypass: boolean }>(
      "SELECT rolbypassrls AS bypass FROM pg_roles WHERE rolname = current_user",
    );
    if (r.rows[0]?.bypass) throw new Error("connected role bypasses row security");
  } finally {
    await pool.end();
  }
}

export async function runDoctor(
  cfg: Config,
  out: (line: string) => void = (l) => process.stderr.write(`${l}\n`),
  fetchImpl: typeof fetch = fetch,
  idToken: (audience: string) => Promise<string> = getIdToken,
  dbPing: (cfg: Config) => Promise<void> = pingDatabase,
): Promise<number> {
  out(`EngramPort ${VERSION} doctor`);
  if (cfg.store === "postgres") {
    out(`  mode:      ${cfg.mode}`);
    out(`  store:     postgres`);
    out(`  database:  ${databasePreview(cfg.databaseUrl)}`);
    out(`  pepper:    ${cfg.keyPepper ? "set" : "(not set)"}`);
    out(`  embedding: ${cfg.openaiApiKey ? "openai text-embedding-3-small" : "(off: keyword search only)"}`);
    out(`  api key:   ${cfg.mode === "http" ? "(each caller sends its own)" : keyPreview(cfg.apiKey)}`);
    const problems = configProblems(cfg);
    if (cfg.mode === "stdio" && !cfg.apiKey) problems.push("ENGRAMPORT_API_KEY is not set.");
    for (const p of problems) out(`  problem:   ${p}`);
    if (problems.some((p) => p.includes("DATABASE_URL"))) return 1;
    try {
      await dbPing(cfg);
      out("  database:  reachable");
    } catch (err) {
      out(`  database:  unreachable (${err instanceof Error ? err.message : String(err)})`);
      problems.push("database check failed");
    }
    return problems.length ? 1 : 0;
  }
  out(`  mode:      ${cfg.mode}`);
  out(`  api url:   ${cfg.apiUrl || "(not set)"}`);
  out(`  api key:   ${cfg.mode === "http" ? "(each caller sends its own)" : keyPreview(cfg.apiKey)}`);
  out(`  namespace: ${cfg.namespace}`);

  const problems = configProblems(cfg);
  if (cfg.mode === "stdio" && !cfg.apiKey) problems.push("ENGRAMPORT_API_KEY is not set.");
  for (const p of problems) out(`  problem:   ${p}`);
  if (!cfg.apiUrl || problems.some((p) => p.includes("not a valid URL"))) return 1;

  try {
    // Same Cloud Run gate as normal tool calls (see eidetic.ts), so an
    // IAM-protected backend is not reported as broken.
    const headers: Record<string, string> = {};
    const token = await idToken(cfg.apiUrl);
    if (token) headers["X-Serverless-Authorization"] = `Bearer ${token}`;
    const res = await fetchImpl(`${cfg.apiUrl}/health`, { headers, signal: AbortSignal.timeout(5000) });
    out(`  health:    ${res.status} ${res.ok ? "ok" : res.statusText}`);
    if (res.status === 401 || res.status === 403) {
      out(`  hint:      the backend refused this identity${token ? "" : " (no Cloud Run ID token was available)"}`);
    }
    if (!res.ok) problems.push("health check failed");
  } catch (err) {
    out(`  health:    unreachable (${err instanceof Error ? err.message : String(err)})`);
    problems.push("health check failed");
  }
  return problems.length ? 1 : 0;
}
