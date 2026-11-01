/**
 * EngramPort MCP server factory.
 *
 * One place that builds the MCP server, shared by stdio mode and the hosted
 * streamable HTTP endpoint. The hosted endpoint is stateless, so it builds a
 * fresh server per request; stdio builds one for the life of the process.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { toolDefinitions as defaultToolDefinitions, executeTool as defaultExecuteTool } from "./tools/index.js";

// Single-source the version so the copies can't drift from package.json.
// Bump alongside package.json on release.
export const VERSION = "2.2.1";

export type ToolResult = { content: Array<{ type: "text"; text: string }>; isError?: boolean };

export interface McpDeps {
  toolDefinitions: ReadonlyArray<{ name: string; description: string; inputSchema: unknown }>;
  executeTool: (name: string, args: Record<string, unknown>) => Promise<ToolResult>;
}

export const defaultDeps: McpDeps = {
  toolDefinitions: defaultToolDefinitions,
  executeTool: defaultExecuteTool,
};

export function createMcpServer(deps: McpDeps = defaultDeps): Server {
  const server = new Server(
    { name: "engramport", version: VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: deps.toolDefinitions as never,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    return deps.executeTool(name, (args as Record<string, unknown>) || {});
  });

  return server;
}
