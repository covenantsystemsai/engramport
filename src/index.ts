#!/usr/bin/env node
/**
 * EngramPort — Give any bot a brain.
 *
 * Universal MCP connector for Eidetic memory.
 * Supports stdio (Claude Desktop) and HTTP/SSE (remote bots).
 *
 * Setup:
 *   EIDETIC_API_URL=http://localhost:8000
 *   EIDETIC_API_KEY=ek_your_key_here
 *   EIDETIC_NAMESPACE=my-bot-brain
 *
 * Run:
 *   ENGRAMPORT_MODE=stdio  npx engramport   # Claude Desktop
 *   ENGRAMPORT_MODE=http   npx engramport   # Remote bots
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import express, { Request, Response } from "express";
import cors from "cors";

import { config, validateConfig } from "./config.js";
import { toolDefinitions, executeTool } from "./tools/index.js";
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
// MCP Server (shared between stdio and HTTP)
// ═══════════════════════════════════════════════════════════

const mcpServer = new Server(
  { name: "engramport", version: "2.0.2" },
  { capabilities: { tools: {} } },
);

mcpServer.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: toolDefinitions,
}));

mcpServer.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  return executeTool(name, (args as Record<string, unknown>) || {});
});

// ═══════════════════════════════════════════════════════════
// HTTP Server (for remote bots)
// ═══════════════════════════════════════════════════════════

function startHTTP() {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: "10mb" }));

  // Health
  app.get("/health", (_req: Request, res: Response) => {
    res.json({
      service: "engramport",
      version: "2.0.2",
      eidetic_api: config.apiUrl,
      namespace: config.namespace,
      tools: toolDefinitions.length,
    });
  });

  // List tools
  app.get("/tools", (_req: Request, res: Response) => {
    res.json({ tools: toolDefinitions });
  });

  // ── Simple REST: POST /remember, /recall, /chat, etc. ──
  // Any bot can call these with a JSON body — no MCP protocol needed.
  for (const tool of toolDefinitions) {
    app.post(`/${tool.name}`, async (req: Request, res: Response) => {
      const result = await executeTool(tool.name, req.body || {});
      const status = result.isError ? 500 : 200;
      try {
        res.status(status).json(JSON.parse(result.content[0].text));
      } catch {
        res.status(status).json({ raw: result.content[0].text });
      }
    });
  }

  // ── MCP JSON-RPC: POST /mcp ──
  // For MCP-aware clients that speak JSON-RPC 2.0.
  app.post("/mcp", async (req: Request, res: Response) => {
    const { jsonrpc, method, params, id } = req.body;

    if (jsonrpc !== "2.0") {
      res.status(400).json({
        jsonrpc: "2.0",
        error: { code: -32600, message: "Invalid JSON-RPC version" },
        id,
      });
      return;
    }

    if (method === "tools/list") {
      res.json({ jsonrpc: "2.0", result: { tools: toolDefinitions }, id });
      return;
    }

    if (method === "tools/call") {
      const { name, arguments: args } = params || {};
      const result = await executeTool(name, args || {});
      res.json({ jsonrpc: "2.0", result, id });
      return;
    }

    res.json({
      jsonrpc: "2.0",
      error: { code: -32601, message: `Unknown method: ${method}` },
      id,
    });
  });

  // ── SSE: GET /stream ──
  // Persistent connection for real-time bots.
  app.get("/stream", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");

    res.write(`data: ${JSON.stringify({ type: "connected", namespace: config.namespace, tools: toolDefinitions.map(t => t.name) })}\n\n`);

    const keepAlive = setInterval(() => res.write(": keepalive\n\n"), 30000);
    req.on("close", () => clearInterval(keepAlive));
  });

  app.listen(config.port, "0.0.0.0", () => {
    // Banner to STDERR unconditionally. stdout is reserved for protocol output
    // (JSON-RPC when MCP clients connect to /mcp). 2.0.0 used console.log here
    // and broke Claude Desktop's stdio MCP integration when users following
    // documented install steps got auto-defaulted to http mode.
    console.error(`
┌──────────────────────────────────────────────────────┐
│              ENGRAMPORT v2.0.2                       │
│              Give any bot a brain.                   │
├──────────────────────────────────────────────────────┤
│  Eidetic API:  ${config.apiUrl.padEnd(37)}│
│  Namespace:    ${config.namespace.padEnd(37)}│
│  Port:         ${String(config.port).padEnd(37)}│
├──────────────────────────────────────────────────────┤
│  REST Endpoints (any bot):                           │
│    POST /remember   — Store a memory                 │
│    POST /recall     — Search by meaning              │
│    POST /chat       — Talk to the brain              │
│    POST /upload     — Ingest a document              │
│    POST /groom      — Discover connections           │
│    POST /dream      — Synthesize insights            │
│    POST /inspect    — Brain stats                    │
│                                                      │
│  MCP (Claude/agents):                                │
│    POST /mcp        — JSON-RPC 2.0                   │
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
  mcpServer.connect(transport).then(() => {
    console.error("[EngramPort] Running in stdio mode (Claude Desktop)");
  });
} else {
  startHTTP();
}
