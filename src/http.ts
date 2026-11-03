/**
 * EngramPort hosted HTTP app.
 *
 * POST /mcp speaks the real MCP streamable HTTP transport (initialize,
 * notifications/initialized, tools/list, tools/call), so claude.ai custom
 * connectors and any spec-compliant MCP client can connect. It runs stateless:
 * every POST gets a fresh server and transport, which suits Cloud Run's
 * scale-to-zero and multiple instances (no sticky sessions needed).
 *
 * Every route except /health needs the caller's own key, sent as
 * `Authorization: Bearer <key>` (MCP clients) or `X-API-Key: <key>` (REST
 * bots). That key is what reaches the backend, so a caller can only reach what
 * its own key can reach. A missing or malformed key gets a 401 before any tool
 * runs. The server's own ENGRAMPORT_API_KEY is never used in this mode.
 *
 * With OAuth on (src/oauth.ts), the discovery and sign-in routes are served
 * before that check, a 401 names the resource metadata so clients know where
 * to sign in, and every key is checked against the store up front, so an
 * expired access token gets a 401 (and the client refreshes) instead of a
 * tool error.
 */

import express, { Request, Response, Router } from "express";
import cors from "cors";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { createMcpServer, defaultDeps, McpDeps, VERSION } from "./server.js";
import { keyFromHeaders, runAsCaller } from "./caller.js";

export interface HttpAppOptions {
  apiUrl: string;
  namespace: string;
  deps?: McpDeps;
  /** OAuth routes (createOAuthRouter), served without a key. */
  oauth?: Router;
  /** RFC 9728 metadata URL named in every 401, so clients can start sign-in. */
  resourceMetadataUrl?: string;
  /** Checks a key before any route runs: false means unknown, revoked or expired. */
  authenticate?: (key: string) => Promise<boolean>;
}

export function createHttpApp(opts: HttpAppOptions): express.Express {
  const deps = opts.deps ?? defaultDeps;
  const { toolDefinitions, executeTool } = deps;

  const app = express();
  // One proxy hop (Cloud Run's front end) sets the client address used by rate limits.
  app.set("trust proxy", 1);
  app.use(cors({ exposedHeaders: ["Mcp-Session-Id", "WWW-Authenticate"] }));
  app.use(express.json({ limit: "10mb" }));

  // Health stays open for uptime checks, so it says nothing about the backend
  // URL or namespaces.
  app.get("/health", (_req: Request, res: Response) => {
    res.json({ service: "engramport", version: VERSION, status: "ok" });
  });

  if (opts.oauth) app.use(opts.oauth);

  const challenge = (error?: string) =>
    [
      'Bearer realm="engramport"',
      ...(opts.resourceMetadataUrl ? [`resource_metadata="${opts.resourceMetadataUrl}"`] : []),
      ...(error ? [`error="${error}"`] : []),
    ].join(", ");
  const unauthorized = (res: Response, message: string, error?: string) => {
    res.status(401).set("WWW-Authenticate", challenge(error)).json({
      jsonrpc: "2.0",
      error: { code: -32001, message },
      id: null,
    });
  };

  // Everything below needs a caller key. The key is bound to this request's
  // async context and forwarded to the backend in place of any server key.
  app.use((req: Request, res: Response, next) => {
    const apiKey = keyFromHeaders(req.headers);
    if (!apiKey) {
      unauthorized(res, "Unauthorized: send your EngramPort key as Authorization: Bearer <key>");
      return;
    }
    if (!opts.authenticate) {
      runAsCaller({ apiKey }, next);
      return;
    }
    opts.authenticate(apiKey).then(
      (ok) => {
        if (ok) runAsCaller({ apiKey }, next);
        else unauthorized(res, "Unauthorized: this key is unknown, revoked or expired", "invalid_token");
      },
      (err) => {
        // A store outage is not the caller's fault: a 401 here would make
        // clients throw away good tokens.
        console.error("[engramport] key check failed:", (err as Error).message);
        res.status(503).json({ jsonrpc: "2.0", error: { code: -32603, message: "Temporarily unavailable" }, id: null });
      },
    );
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
