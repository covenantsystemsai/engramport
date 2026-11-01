/**
 * `engramport doctor`: print the resolved settings and check the API answers.
 *
 * Prints only a short key prefix, never the key. Exit code 0 means the
 * settings are usable and the API's /health answered; 1 means something
 * needs fixing, and each problem is printed on its own line.
 */

import { Config, configProblems } from "./config.js";
import { VERSION } from "./server.js";

export function keyPreview(key: string): string {
  if (!key) return "(not set)";
  return `${key.slice(0, Math.min(7, Math.floor(key.length / 3)))}… (${key.length} chars)`;
}

export async function runDoctor(
  cfg: Config,
  out: (line: string) => void = (l) => process.stderr.write(`${l}\n`),
  fetchImpl: typeof fetch = fetch,
): Promise<number> {
  out(`EngramPort ${VERSION} doctor`);
  out(`  mode:      ${cfg.mode}`);
  out(`  api url:   ${cfg.apiUrl || "(not set)"}`);
  out(`  api key:   ${cfg.mode === "http" ? "(each caller sends its own)" : keyPreview(cfg.apiKey)}`);
  out(`  namespace: ${cfg.namespace}`);

  const problems = configProblems(cfg);
  if (cfg.mode === "stdio" && !cfg.apiKey) problems.push("ENGRAMPORT_API_KEY is not set.");
  for (const p of problems) out(`  problem:   ${p}`);
  if (!cfg.apiUrl || problems.some((p) => p.includes("not a valid URL"))) return 1;

  try {
    const res = await fetchImpl(`${cfg.apiUrl}/health`, { signal: AbortSignal.timeout(5000) });
    out(`  health:    ${res.status} ${res.ok ? "ok" : res.statusText}`);
    if (!res.ok) problems.push("health check failed");
  } catch (err) {
    out(`  health:    unreachable (${err instanceof Error ? err.message : String(err)})`);
    problems.push("health check failed");
  }
  return problems.length ? 1 : 0;
}
