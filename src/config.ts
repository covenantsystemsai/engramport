/**
 * EngramPort Configuration
 *
 * Only two things needed: where is Eidetic, and what key to use.
 * Everything else is optional.
 */

export const config = {
  /** Eidetic V2 API base URL */
  apiUrl: process.env.EIDETIC_API_URL || "http://localhost:8000",

  /** API key for authenticating with Eidetic */
  apiKey: process.env.EIDETIC_API_KEY || "",

  /** Default namespace (bot's brain) */
  namespace: process.env.EIDETIC_NAMESPACE || "default",

  /** HTTP server port (for HTTP/SSE mode) */
  port: parseInt(process.env.ENGRAMPORT_PORT || "3001"),

  /**
   * Transport mode: stdio | http.
   *
   * Auto-detect: if stdout is not a TTY (e.g., spawned by Claude Desktop or
   * any MCP client via child_process.spawn), default to stdio. Interactive
   * terminals default to http for the REST/SSE surface. Explicit env var
   * always wins. Without auto-detect, MCP clients hit port 3001 conflicts
   * and the startup banner corrupts JSON-RPC stdin — the 2.0.0 launch bug.
   */
  mode: (process.env.ENGRAMPORT_MODE ||
    (process.stdout.isTTY ? "http" : "stdio")) as "stdio" | "http",

  // ── Cloud Run OIDC auth (see src/auth.ts for full rationale) ──────────────
  // These are read directly by auth.ts at module load; documented here for visibility.

  /** gcloud account to pin when minting identity tokens (avoids multi-account ambiguity) */
  gcloudAccount: process.env.GCLOUD_ACCOUNT || "",

  /** Absolute path override for the gcloud binary (probes well-known paths if empty) */
  gcloudCmdPath: process.env.GCLOUD_CMD_PATH || "",

  /** Cross-process OIDC token cache path */
  tokenCachePath: process.env.OIDC_TOKEN_CACHE_PATH || "",

  /** OIDC token TTL in minutes (Google ID tokens are 1h; 50min default leaves slack) */
  tokenTtlMinutes: parseInt(process.env.OIDC_TOKEN_TTL_MINUTES || "50"),
};

export function validateConfig(): void {
  if (!config.apiKey) {
    console.warn("[EngramPort] No EIDETIC_API_KEY set — requests will fail in production");
  }
}
