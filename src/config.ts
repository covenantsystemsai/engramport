/**
 * EngramPort Configuration
 *
 * Two stores. The default, eidetic, needs the old backend's URL and a key. The
 * postgres store (ENGRAMPORT_STORE=postgres) talks to the memory schema
 * directly and needs a database URL for the engramport_app role and the key
 * pepper, both from the secrets manager.
 */

import { decodePepper } from "./keys.js";

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
    /**
     * EngramPort API base URL (primary: ENGRAMPORT_API_URL, legacy: EIDETIC_API_URL).
     * No default: a silent localhost default made every hosted call fail with a
     * connection error. configProblems() names a missing URL at startup.
     */
    apiUrl: (env.ENGRAMPORT_API_URL || env.EIDETIC_API_URL || "").replace(/\/+$/, ""),

    /** Which store serves the tools: eidetic (old backend, default) or postgres. */
    store: (env.ENGRAMPORT_STORE || "eidetic").toLowerCase(),

    /** Postgres store: connection URL for the engramport_app role. */
    databaseUrl: env.ENGRAMPORT_DATABASE_URL || "",

    /** Postgres store: CA certificate file for the database's TLS (Supabase's CA). */
    databaseCaFile: env.ENGRAMPORT_DATABASE_CA_FILE || "",

    /** Postgres store: pepper for key hashes, base64 or hex, at least 32 bytes. */
    keyPepper: env.ENGRAMPORT_KEY_PEPPER || "",

    /** Postgres store: embedding provider key. Without it, recall is keyword only. */
    openaiApiKey: env.OPENAI_API_KEY || "",

    /** Allow a localhost backend in http mode (local development only). */
    allowLocalBackend: (env.ENGRAMPORT_ALLOW_LOCAL_BACKEND || "").toLowerCase() === "true",

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

export type Config = ReturnType<typeof resolveConfig>;

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"]);

/**
 * Settings that would make every call fail or put a key at risk. Startup
 * refuses to run while any are present; `engramport doctor` lists them.
 */
export function configProblems(cfg: Config, mode: "stdio" | "http" = cfg.mode): string[] {
  if (cfg.store === "postgres") return postgresProblems(cfg, mode);
  if (cfg.store !== "eidetic") return [`ENGRAMPORT_STORE must be eidetic or postgres, not ${cfg.store}.`];
  const problems: string[] = [];
  if (!cfg.apiUrl) {
    problems.push("ENGRAMPORT_API_URL is not set. Set it to your EngramPort API URL.");
    return problems;
  }
  let url: URL;
  try {
    url = new URL(cfg.apiUrl);
  } catch {
    problems.push(`ENGRAMPORT_API_URL is not a valid URL: ${cfg.apiUrl}`);
    return problems;
  }
  const local = LOCAL_HOSTS.has(url.hostname);
  if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
    problems.push("ENGRAMPORT_API_URL must use https, so keys never travel in clear text.");
  }
  if (mode === "http" && local && !cfg.allowLocalBackend) {
    problems.push(
      "ENGRAMPORT_API_URL points at this machine while running hosted. " +
        "Set the real API URL, or ENGRAMPORT_ALLOW_LOCAL_BACKEND=true for local development.",
    );
  }
  return problems;
}

// sslmode in the URL would override the verified TLS the store sets up.
const WEAK_SSLMODE = /[?&]sslmode=/i;

function postgresProblems(cfg: Config, mode: "stdio" | "http"): string[] {
  const problems: string[] = [];
  if (!cfg.databaseUrl) {
    problems.push("ENGRAMPORT_DATABASE_URL is not set. Set it to the engramport_app connection URL.");
  } else {
    let url: URL | undefined;
    try {
      url = new URL(cfg.databaseUrl);
    } catch {
      problems.push("ENGRAMPORT_DATABASE_URL is not a valid URL.");
    }
    if (url) {
      if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") {
        problems.push("ENGRAMPORT_DATABASE_URL must be a postgres:// URL.");
      }
      const local = LOCAL_HOSTS.has(url.hostname);
      if (!local && WEAK_SSLMODE.test(cfg.databaseUrl)) {
        problems.push("Remove sslmode from ENGRAMPORT_DATABASE_URL: the server always verifies TLS to a remote database.");
      }
      if (mode === "http" && local && !cfg.allowLocalBackend) {
        problems.push(
          "ENGRAMPORT_DATABASE_URL points at this machine while running hosted. " +
            "Set the real database URL, or ENGRAMPORT_ALLOW_LOCAL_BACKEND=true for local development.",
        );
      }
      const user = decodeURIComponent(url.username);
      if (user === "postgres" || user === "service_role" || user.startsWith("postgres.") || user === "supabase_admin") {
        problems.push("ENGRAMPORT_DATABASE_URL must connect as engramport_app, not an admin role that skips row security.");
      }
    }
  }
  if (!decodePepper(cfg.keyPepper)) {
    problems.push("ENGRAMPORT_KEY_PEPPER is not set or shorter than 32 bytes.");
  }
  return problems;
}

export function validateConfig(mode: "stdio" | "http" = config.mode): void {
  const problems = configProblems(config, mode);
  if (problems.length) {
    for (const p of problems) console.error(`[EngramPort] ${p}`);
    process.exit(1);
  }
  if (config.store === "postgres" && !config.openaiApiKey) {
    console.warn("[EngramPort] No OPENAI_API_KEY set — the Postgres store will use keyword search only");
  }
  if (mode === "http") {
    // Hosted mode forwards each caller's own key; a server-wide key would give
    // every caller its reach, so it is ignored here.
    if (config.apiKey) {
      console.warn("[EngramPort] ENGRAMPORT_API_KEY is ignored in http mode: each caller sends its own key");
    }
    return;
  }
  if (!config.apiKey) {
    console.warn("[EngramPort] No ENGRAMPORT_API_KEY set — requests will fail in production");
  }
}
