#!/usr/bin/env node
/**
 * EngramPort — Give any bot a brain.
 *
 * Universal MCP connector for Eidetic memory.
 * Supports stdio (Claude Desktop) and HTTP/SSE (remote bots).
 *
 * Setup:
 *   ENGRAMPORT_API_URL=http://localhost:8000    (legacy alias: EIDETIC_API_URL)
 *   ENGRAMPORT_API_KEY=ek_your_key_here         (legacy alias: EIDETIC_API_KEY)
 *   ENGRAMPORT_NAMESPACE=my-bot-brain           (legacy alias: EIDETIC_NAMESPACE)
 *
 * Run:
 *   ENGRAMPORT_MODE=stdio  npx engramport   # Claude Desktop
 *   ENGRAMPORT_MODE=http   npx engramport   # Remote bots
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { config, validateConfig } from "./config.js";
import { createMcpServer, VERSION } from "./server.js";
import { createHttpApp } from "./http.js";
import { setCallerRequired } from "./caller.js";
import { runDoctor } from "./doctor.js";
import { prewarmToken } from "./auth.js";
import { decodePepper } from "./keys.js";

// CLI: `node dist/index.js prewarm` mints an OIDC token in this process and
// writes the cross-process disk cache, then exits. Run from a working shell
// (where gcloud is healthy) so the long-running server reads the cache and
// never has to shell out to gcloud itself. Uses top-level await to BLOCK
// the rest of module execution; without await the server would start up
// concurrently with prewarm and only exit after the HTTP banner printed.
if (process.argv[2] === "prewarm") {
  try {
    const code = await prewarmToken(config.apiUrl);
    process.exit(code);
  } catch (err) {
    process.stderr.write(`prewarm crashed: ${String(err)}\n`);
    process.exit(2);
  }
}

// CLI: `engramport doctor` prints the resolved settings (key prefix only) and
// checks that the API answers, then exits. Runs before validateConfig so it
// can report a broken setup instead of refusing to start.
if (process.argv[2] === "doctor") {
  process.exit(await runDoctor(config));
}

// CLI: `engramport admin ...` manages namespaces, actors and keys in the
// Postgres store, as the engramport_admin role. See src/admin.ts.
if (process.argv[2] === "admin") {
  const { AdminClient, runAdmin } = await import("./admin.js");
  process.exit(
    await runAdmin(process.argv.slice(3), () => AdminClient.fromEnv(), {
      out: (line) => process.stdout.write(`${line}\n`),
      err: (line) => process.stderr.write(`${line}\n`),
    }),
  );
}

validateConfig(config.mode);

// ═══════════════════════════════════════════════════════════
// HTTP Server (for remote bots)
// ═══════════════════════════════════════════════════════════

/** The Postgres store checks every key up front; OAuth adds sign-in on top. */
async function hostedAuth() {
  if (config.store !== "postgres") return {};
  const { sharedPool, sharedStore } = await import("./tools/store.js");
  const store = sharedStore();
  const authenticate = (key: string) => store.checkKey(key);
  if (!config.oauth) return { authenticate };
  const { createOAuthRouter, resourceMetadataUrl, supabaseIdentity } = await import("./oauth.js");
  const identity = supabaseIdentity(config.supabaseUrl, config.supabasePublishableKey);
  const pepper = decodePepper(config.keyPepper)!;
  const approve = config.approvalPage
    ? (await import("./approve.js")).createApprovalRouter({ publicUrl: config.publicUrl, pepper, db: sharedPool(), identity })
    : undefined;
  const erase = config.erasurePage
    ? (await import("./erase.js")).createErasureRouter({ publicUrl: config.publicUrl, pepper, db: sharedPool(), identity })
    : undefined;
  const exportPage = config.exportPage
    ? (await import("./export.js")).createExportRouter({ publicUrl: config.publicUrl, pepper, db: sharedPool(), identity })
    : undefined;
  const restore = config.restorePage
    ? (await import("./restore.js")).createRestoreRouter({ publicUrl: config.publicUrl, pepper, db: sharedPool(), identity })
    : undefined;
  const cellErasure = config.cellErasurePage
    ? (await import("./cell-erase.js")).createCellErasureRouter({ publicUrl: config.publicUrl, pepper, db: sharedPool(), identity })
    : undefined;
  const accept = config.acceptPage
    ? (await import("./accept.js")).createAcceptRouter({ publicUrl: config.publicUrl, pepper, db: sharedPool(), identity })
    : undefined;
  return {
    authenticate,
    resourceMetadataUrl: resourceMetadataUrl(config.publicUrl),
    oauth: createOAuthRouter({
      publicUrl: config.publicUrl,
      redirectHosts: config.oauthRedirectHosts,
      pepper,
      db: sharedPool(),
      identity,
    }),
    ...(approve ? { approve } : {}),
    ...(erase ? { erase } : {}),
    ...(exportPage ? { exportPage } : {}),
    ...(restore ? { restore } : {}),
    ...(cellErasure ? { cellErasure } : {}),
    ...(accept ? { accept } : {}),
  };
}

async function startHTTP() {
  // A single malformed request or async handler rejection must not take the whole
  // process down (Express 4 does not catch async throws). Log and stay up.
  process.on("unhandledRejection", (reason) => console.error("[engramport] unhandledRejection:", reason));
  process.on("uncaughtException", (err) => console.error("[engramport] uncaughtException:", err));

  // Hosted mode: every backend call must carry the caller's own key.
  setCallerRequired(true);
  const app = createHttpApp({ apiUrl: config.apiUrl, namespace: config.namespace, ...(await hostedAuth()) });

  app.listen(config.port, "0.0.0.0", () => {
    // Banner to STDERR unconditionally. stdout is reserved for protocol output
    // (JSON-RPC when MCP clients connect to /mcp). 2.0.0 used console.log here
    // and broke Claude Desktop's stdio MCP integration when users following
    // documented install steps got auto-defaulted to http mode.
    console.error(`
┌──────────────────────────────────────────────────────┐
│              ENGRAMPORT v${VERSION.padEnd(28)}│
│              Give any bot a brain.                   │
├──────────────────────────────────────────────────────┤
│  Store:        ${(config.store === "postgres" ? "postgres" : config.apiUrl).padEnd(37)}│
│  Namespace:    ${config.namespace.padEnd(37)}│
│  Port:         ${String(config.port).padEnd(37)}│
├──────────────────────────────────────────────────────┤
│  REST Endpoints (any bot):                           │
│    POST /remember        — Store a memory            │
│    POST /recall          — Search by meaning         │
│    POST /chat            — Talk to the brain         │
│    POST /upload          — Ingest a document         │
│    POST /groom           — Discover connections      │
│    POST /dream           — Synthesize insights       │
│    POST /inspect         — Brain stats               │
│    POST /fetch_memory    — Read a memory by ID       │
│    POST /delete_memory   — Remove a memory by ID     │
│    POST /list_namespaces — List namespaces           │
│    POST /export_graph    — Export the graph          │
│                                                      │
│  MCP (Claude/agents):                                │
│    POST /mcp        — MCP streamable HTTP            │
│    GET  /stream     — SSE persistent connection      │
│    GET  /tools      — List available tools            │
└──────────────────────────────────────────────────────┘
    `);
  });
}

// ═══════════════════════════════════════════════════════════
// Start
// ═══════════════════════════════════════════════════════════

if (config.mode === "stdio") {
  const transport = new StdioServerTransport();
  createMcpServer().connect(transport).then(() => {
    console.error("[EngramPort] Running in stdio mode (Claude Desktop)");
  });
} else {
  await startHTTP();
}
