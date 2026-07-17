/**
 * EngramPort Configuration
 *
 * Only two things needed: where is Eidetic, and what key to use.
 * Everything else is optional.
 */

/**
 * Resolve config from an env map (defaults to process.env). Exposed as a pure
 * function so the env-var resolution — including the ENGRAMPORT_* primary /
 * EIDETIC_* legacy fallback — is unit-testable without mutating the process.
 *
 * ONBOARDING FIX (2.2.0): the README + dashboard tell users to set
 * ENGRAMPORT_API_KEY, but the code only ever read EIDETIC_API_KEY, so a
 * by-the-book setup silently produced "no key" and every request failed. We now
 * read the on-brand ENGRAMPORT_* names first and keep EIDETIC_* as a legacy
 * fallback so existing deployments keep working unchanged.
 */
export function resolveConfig(env: NodeJS.ProcessEnv = process.env) {
  return {
    /** EngramPort API base URL (primary: ENGRAMPORT_API_URL, legacy: EIDETIC_API_URL) */
    apiUrl: env.ENGRAMPORT_API_URL || env.EIDETIC_API_URL || "http://localhost:8000",

    /** API key for authenticating (primary: ENGRAMPORT_API_KEY, legacy: EIDETIC_API_KEY) */
    apiKey: env.ENGRAMPORT_API_KEY || env.EIDETIC_API_KEY || "",

    /** Default namespace (primary: ENGRAMPORT_NAMESPACE, legacy: EIDETIC_NAMESPACE) */
    namespace: env.ENGRAMPORT_NAMESPACE || env.EIDETIC_NAMESPACE || "default",

    /** HTTP server port (for HTTP/SSE mode) */
    port: parseInt(env.ENGRAMPORT_PORT || "3001"),

    /**
     * Transport mode: stdio | http. Auto-detect: if stdout is not a TTY
     * (spawned by an MCP client), default to stdio; interactive terminals
     * default to http. Explicit env var always wins. (2.0.0 launch bug: without
     * auto-detect, MCP clients hit port 3001 conflicts and the banner corrupts
     * JSON-RPC stdin.)
     */
    mode: (env.ENGRAMPORT_MODE ||
      (process.stdout.isTTY ? "http" : "stdio")) as "stdio" | "http",

    // ── Cloud Run OIDC auth (read directly by src/auth.ts; mirrored here) ──
    gcloudAccount: env.GCLOUD_ACCOUNT || "",
    gcloudCmdPath: env.GCLOUD_CMD_PATH || "",
    tokenCachePath: env.OIDC_TOKEN_CACHE_PATH || "",
    tokenTtlMinutes: parseInt(env.OIDC_TOKEN_TTL_MINUTES || "50"),
  };
}

/** Live config resolved from process.env at module load. */
export const config = resolveConfig();

export function validateConfig(): void {
  if (!config.apiKey) {
    console.warn("[EngramPort] No ENGRAMPORT_API_KEY set — requests will fail in production");
  }
}
