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

    /**
     * Postgres store: OpenAI key, for namespaces set to text-embedding-3-small
     * only. Their text is sent to OpenAI; no other namespace's is.
     */
    openaiApiKey: env.OPENAI_API_KEY || "",

    /**
     * Postgres store: the embed Edge Function in the same Supabase project, for
     * namespaces set to gte-small (the default), and its shared secret.
     */
    embedUrl: env.ENGRAMPORT_EMBED_URL || "",
    embedSecret: env.ENGRAMPORT_EMBED_SECRET || "",

    /**
     * OAuth sign-in for hosted MCP clients (claude.ai). Off unless set to true.
     * Needs the Postgres store, the public URL and Supabase Auth.
     */
    oauth: (env.ENGRAMPORT_OAUTH || "").toLowerCase() === "true",

    /**
     * The page where a person approves or rejects a memory with their own
     * Google sign-in. Off unless set to true. Needs OAuth set up.
     */
    approvalPage: (env.ENGRAMPORT_APPROVAL_PAGE || "").toLowerCase() === "true",

    /**
     * The page where a person with authority reviews and confirms an erasure
     * request with their own Google sign-in. Off unless set to true. Needs OAuth.
     */
    erasurePage: (env.ENGRAMPORT_ERASURE_PAGE || "").toLowerCase() === "true",

    /**
     * The page where a person with an owner's grant downloads a namespace's
     * export with their own Google sign-in. Off unless set to true. Needs OAuth.
     */
    exportPage: (env.ENGRAMPORT_EXPORT_PAGE || "").toLowerCase() === "true",

    /**
     * The page where a person with authority restores a retracted memory, within
     * 30 days, with their own Google sign-in. Off unless set to true. Needs OAuth.
     */
    restorePage: (env.ENGRAMPORT_RESTORE_PAGE || "").toLowerCase() === "true",

    /**
     * The pages where a cell's owner starts a whole-cell erasure and a different
     * person holding the cell-erasure-confirmer role confirms it, each with their
     * own Google sign-in. Off unless set to true. Needs OAuth.
     */
    cellErasurePage: (env.ENGRAMPORT_CELL_ERASURE_PAGE || "").toLowerCase() === "true",

    /**
     * The page where a person accepts or declines, with their own Google sign-in,
     * the approval authority, erase or export grants and confirmer role offered to
     * them. Off unless set to true. Needs OAuth.
     */
    acceptPage: (env.ENGRAMPORT_ACCEPT_PAGE || "").toLowerCase() === "true",

    /**
     * The page where an owner offers another member an erase or export grant by
     * typing their email, with their own Google sign-in. Off unless set to true.
     * Needs OAuth.
     */
    grantPage: (env.ENGRAMPORT_GRANT_PAGE || "").toLowerCase() === "true",

    /** The server's public origin (https, no path): the OAuth issuer. */
    publicUrl: (env.ENGRAMPORT_PUBLIC_URL || "").replace(/\/+$/, ""),

    /** Supabase project URL whose Auth signs people in with Google. */
    supabaseUrl: (env.ENGRAMPORT_SUPABASE_URL || "").replace(/\/+$/, ""),

    /** That project's publishable (anon) key, sent to Supabase Auth only. */
    supabasePublishableKey: env.ENGRAMPORT_SUPABASE_PUBLISHABLE_KEY || "",

    /** Hosts an OAuth client may register an https redirect on. */
    oauthRedirectHosts: (env.ENGRAMPORT_OAUTH_REDIRECT_HOSTS || "claude.ai,claude.com")
      .split(",").map((h) => h.trim().toLowerCase()).filter(Boolean),

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
  if (cfg.oauth) return ["ENGRAMPORT_OAUTH needs ENGRAMPORT_STORE=postgres."];
  if (cfg.approvalPage) return ["ENGRAMPORT_APPROVAL_PAGE needs ENGRAMPORT_STORE=postgres."];
  if (cfg.erasurePage) return ["ENGRAMPORT_ERASURE_PAGE needs ENGRAMPORT_STORE=postgres."];
  if (cfg.exportPage) return ["ENGRAMPORT_EXPORT_PAGE needs ENGRAMPORT_STORE=postgres."];
  if (cfg.restorePage) return ["ENGRAMPORT_RESTORE_PAGE needs ENGRAMPORT_STORE=postgres."];
  if (cfg.cellErasurePage) return ["ENGRAMPORT_CELL_ERASURE_PAGE needs ENGRAMPORT_STORE=postgres."];
  if (cfg.acceptPage) return ["ENGRAMPORT_ACCEPT_PAGE needs ENGRAMPORT_STORE=postgres."];
  if (cfg.grantPage) return ["ENGRAMPORT_GRANT_PAGE needs ENGRAMPORT_STORE=postgres."];
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
  if (cfg.embedUrl || cfg.embedSecret) problems.push(...embedProblems(cfg));
  if (cfg.oauth) problems.push(...oauthProblems(cfg, mode));
  if (cfg.approvalPage && !cfg.oauth) {
    problems.push("ENGRAMPORT_APPROVAL_PAGE needs ENGRAMPORT_OAUTH=true, for its Google sign-in.");
  }
  if (cfg.erasurePage && !cfg.oauth) {
    problems.push("ENGRAMPORT_ERASURE_PAGE needs ENGRAMPORT_OAUTH=true, for its Google sign-in.");
  }
  if (cfg.exportPage && !cfg.oauth) {
    problems.push("ENGRAMPORT_EXPORT_PAGE needs ENGRAMPORT_OAUTH=true, for its Google sign-in.");
  }
  if (cfg.restorePage && !cfg.oauth) {
    problems.push("ENGRAMPORT_RESTORE_PAGE needs ENGRAMPORT_OAUTH=true, for its Google sign-in.");
  }
  if (cfg.cellErasurePage && !cfg.oauth) {
    problems.push("ENGRAMPORT_CELL_ERASURE_PAGE needs ENGRAMPORT_OAUTH=true, for its Google sign-in.");
  }
  if (cfg.acceptPage && !cfg.oauth) {
    problems.push("ENGRAMPORT_ACCEPT_PAGE needs ENGRAMPORT_OAUTH=true, for its Google sign-in.");
  }
  if (cfg.grantPage && !cfg.oauth) {
    problems.push("ENGRAMPORT_GRANT_PAGE needs ENGRAMPORT_OAUTH=true, for its Google sign-in.");
  }
  return problems;
}

function embedProblems(cfg: Config): string[] {
  const problems: string[] = [];
  if (!cfg.embedUrl) problems.push("ENGRAMPORT_EMBED_SECRET is set but ENGRAMPORT_EMBED_URL is not.");
  else {
    let url: URL | undefined;
    try {
      url = new URL(cfg.embedUrl);
    } catch {
      problems.push("ENGRAMPORT_EMBED_URL is not a valid URL.");
    }
    if (url) {
      const local = LOCAL_HOSTS.has(url.hostname);
      if (url.protocol !== "https:" && !(local && cfg.allowLocalBackend && url.protocol === "http:")) {
        problems.push("ENGRAMPORT_EMBED_URL must use https, so memory text never travels in clear text.");
      }
      if (url.search || url.hash || url.username || url.password) {
        problems.push("ENGRAMPORT_EMBED_URL must be the function's address only, with no query or credentials.");
      }
    }
  }
  if (cfg.embedSecret.length < 32) problems.push("ENGRAMPORT_EMBED_SECRET is not set or shorter than 32 characters.");
  return problems;
}

/** An https origin with nothing after it, or http on this machine when allowed. */
function originProblem(name: string, value: string, allowLocal: boolean): string | undefined {
  if (!value) return `${name} is not set.`;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return `${name} is not a valid URL.`;
  }
  if (url.origin !== value) return `${name} must be an origin only, like https://mcp.example.com (no path or query).`;
  const local = LOCAL_HOSTS.has(url.hostname);
  if (url.protocol !== "https:" && !(local && allowLocal && url.protocol === "http:")) {
    return `${name} must use https.`;
  }
  return undefined;
}

function oauthProblems(cfg: Config, mode: "stdio" | "http"): string[] {
  const problems: string[] = [];
  if (mode !== "http") problems.push("ENGRAMPORT_OAUTH works in http mode only.");
  const pub = originProblem("ENGRAMPORT_PUBLIC_URL", cfg.publicUrl, cfg.allowLocalBackend);
  if (pub) problems.push(pub);
  const sb = originProblem("ENGRAMPORT_SUPABASE_URL", cfg.supabaseUrl, cfg.allowLocalBackend);
  if (sb) problems.push(sb);
  if (!cfg.supabasePublishableKey) problems.push("ENGRAMPORT_SUPABASE_PUBLISHABLE_KEY is not set.");
  if (!cfg.oauthRedirectHosts.length) problems.push("ENGRAMPORT_OAUTH_REDIRECT_HOSTS lists no hosts.");
  return problems;
}

export function validateConfig(mode: "stdio" | "http" = config.mode): void {
  const problems = configProblems(config, mode);
  if (problems.length) {
    for (const p of problems) console.error(`[EngramPort] ${p}`);
    process.exit(1);
  }
  if (config.store === "postgres" && !config.embedUrl) {
    console.warn(
      "[EngramPort] No ENGRAMPORT_EMBED_URL set: namespaces on Supabase's built-in model (the default) will use keyword and graph search only",
    );
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
