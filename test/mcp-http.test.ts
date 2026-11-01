// End-to-end check of the hosted /mcp endpoint with the official MCP SDK client:
// the same initialize -> initialized -> tools/list -> tools/call sequence a
// claude.ai custom connector runs. The tool backend is stubbed, so no network.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server as HttpServer } from "node:http";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { createHttpApp } from "../src/http.ts";
import type { McpDeps } from "../src/server.ts";

const calls: Array<{ name: string; args: Record<string, unknown> }> = [];
const deps: McpDeps = {
  toolDefinitions: [
    {
      name: "remember",
      description: "Store a memory",
      inputSchema: { type: "object", properties: { content: { type: "string" } }, required: ["content"] },
    },
  ],
  executeTool: async (name, args) => {
    calls.push({ name, args });
    return { content: [{ type: "text", text: JSON.stringify({ ok: true, echo: args }) }] };
  },
};

let httpServer: HttpServer;
let base: string;

before(async () => {
  const app = createHttpApp({ apiUrl: "http://stub", namespace: "test", deps });
  httpServer = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  base = `http://127.0.0.1:${(httpServer.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => httpServer.close(() => resolve())));

test("SDK client completes the handshake, lists tools and calls one", async () => {
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`)));

  assert.equal(client.getServerVersion()?.name, "engramport");
  assert.ok(client.getServerCapabilities()?.tools, "server advertises tools capability");

  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((t) => t.name), ["remember"]);

  const result = await client.callTool({ name: "remember", arguments: { content: "hello" } });
  const first = (result.content as Array<{ type: string; text: string }>)[0];
  assert.deepEqual(JSON.parse(first.text), { ok: true, echo: { content: "hello" } });
  assert.deepEqual(calls.at(-1), { name: "remember", args: { content: "hello" } });

  await client.close();
});

test("raw initialize over POST returns a JSON-RPC result with protocol version", async () => {
  const res = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "curl", version: "0" } },
    }),
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.id, 1);
  assert.equal(body.result.serverInfo.name, "engramport");
  assert.ok(body.result.protocolVersion);
});

test("GET and DELETE /mcp return 405 in stateless mode", async () => {
  for (const method of ["GET", "DELETE"]) {
    const res = await fetch(`${base}/mcp`, { method });
    assert.equal(res.status, 405, method);
  }
});

test("REST routes and /health still work", async () => {
  const health = await (await fetch(`${base}/health`)).json();
  assert.equal(health.service, "engramport");
  assert.equal(health.tools, 1);

  const res = await fetch(`${base}/remember`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content: "via rest" }),
  });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, echo: { content: "via rest" } });
});
