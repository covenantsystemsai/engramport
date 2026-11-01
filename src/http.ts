/**
 * EngramPort hosted HTTP app.
 *
 * POST /mcp speaks the real MCP streamable HTTP transport (initialize,
 * notifications/initialized, tools/list, tools/call), so claude.ai custom
 * connectors and any spec-compliant MCP client can connect. It runs stateless:
 * every POST gets a fresh server and transport, which suits Cloud Run's
 * scale-to-zero and multiple instances (no sticky sessions needed).
 *
 * The simple REST routes, /health, /tools and /stream are unchanged.
 */

import express, { Request, Response } from "express";
import cors from "cors";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { createMcpServer, defaultDeps, McpDeps, VERSION } from "./server.js";

export interface HttpAppOptions {
  apiUrl: string;
  namespace: string;
  deps?: McpDeps;
}

export function createHttpApp(opts: HttpAppOptions): express.Express {
  const deps = opts.deps ?? defaultDeps;
  const { toolDefinitions, executeTool } = deps;

  const app = express();
  app.use(cors({ exposedHeaders: ["Mcp-Session-Id"] }));
  app.use(express.json({ limit: "10mb" }));

  // Health
  app.get("/health", (_req: Request, res: Response) => {
    res.json({
      service: "engramport",
      version: VERSION,
      eidetic_api: opts.apiUrl,
      namespace: opts.namespace,
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

  // ── MCP streamable HTTP: POST /mcp ──
  app.post("/mcp", async (req: Request, res: Response) => {
    const server = createMcpServer(deps);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless
      enableJsonResponse: true,
    });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error("[engramport] /mcp error:", err);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }
  });

  // Stateless mode has no server-initiated stream and no session to end.
  const methodNotAllowed = (_req: Request, res: Response) => {
    res.status(405).set("Allow", "POST").json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed." },
      id: null,
    });
  };
  app.get("/mcp", methodNotAllowed);
  app.delete("/mcp", methodNotAllowed);

  // ── SSE: GET /stream ──
  // Persistent connection for real-time bots.
  app.get("/stream", (req: Request, res: Response) => {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");

    res.write(`data: ${JSON.stringify({ type: "connected", namespace: opts.namespace, tools: toolDefinitions.map(t => t.name) })}\n\n`);

    const keepAlive = setInterval(() => res.write(": keepalive\n\n"), 30000);
    req.on("close", () => clearInterval(keepAlive));
  });

  return app;
}
