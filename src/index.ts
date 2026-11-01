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
import { prewarmToken } from "./auth.js";

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

validateConfig();

// ═══════════════════════════════════════════════════════════
// HTTP Server (for remote bots)
// ═══════════════════════════════════════════════════════════

function startHTTP() {
  // A single malformed request or async handler rejection must not take the whole
  // process down (Express 4 does not catch async throws). Log and stay up.
  process.on("unhandledRejection", (reason) => console.error("[engramport] unhandledRejection:", reason));
  process.on("uncaughtException", (err) => console.error("[engramport] uncaughtException:", err));

  const app = createHttpApp({ apiUrl: config.apiUrl, namespace: config.namespace });

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
│  Eidetic API:  ${config.apiUrl.padEnd(37)}│
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
  startHTTP();
}
