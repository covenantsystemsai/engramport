// Request ids on the hosted server: every response carries X-Request-Id, a
// tool call runs with that id in its context (so the store can stamp it on
// provenance), a client's own id is kept only when it is plain and short, and
// the one log line per request holds no key, body or query string.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server as HttpServer } from "node:http";

import { createHttpApp } from "../src/http.ts";
import type { McpDeps } from "../src/server.ts";
import { currentRequestId, requestIdFromHeaders } from "../src/caller.ts";

const KEY = "ek_test_request_id_key";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const seen: Array<string | undefined> = [];
const deps: McpDeps = {
  toolDefinitions: [
    { name: "remember", description: "Store a memory", inputSchema: { type: "object", properties: {} } },
  ],
  executeTool: async () => {
    seen.push(currentRequestId());
    return { content: [{ type: "text", text: JSON.stringify({ ok: true }) }] };
  },
};

let httpServer: HttpServer;
let base: string;
const logs: string[] = [];
const realLog = console.log;

before(async () => {
  console.log = (...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  };
  const app = createHttpApp({ apiUrl: "http://stub", namespace: "test", deps });
  httpServer = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  base = `http://127.0.0.1:${(httpServer.address() as AddressInfo).port}`;
});

after(async () => {
  console.log = realLog;
  await new Promise<void>((resolve) => httpServer.close(() => resolve()));
});

const remember = (headers: Record<string, string>, query = "") =>
  fetch(`${base}/remember${query}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${KEY}`, "Content-Type": "application/json", ...headers },
    body: JSON.stringify({ content: "secret memory text" }),
  });

test("requestIdFromHeaders keeps a plain client id and replaces anything else", () => {
  assert.equal(requestIdFromHeaders({ "x-request-id": "client-req_01.a:b" }), "client-req_01.a:b");
  assert.equal(requestIdFromHeaders({ "x-request-id": ["abcdefgh", "zzzzzzzz"] }), "abcdefgh");
  for (const bad of ["short", "x".repeat(129), "has space in it", "line\nbreak!!", "quote\"inside", "ünïcödeid"]) {
    assert.match(requestIdFromHeaders({ "x-request-id": bad }), UUID, JSON.stringify(bad));
  }
  assert.match(requestIdFromHeaders({}), UUID);
  assert.notEqual(requestIdFromHeaders({}), requestIdFromHeaders({}));
});

test("a client's id is returned and is the id the tool runs with", async () => {
  const res = await remember({ "X-Request-Id": "client-trace-0001" });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("x-request-id"), "client-trace-0001");
  assert.equal(seen.at(-1), "client-trace-0001");
});

test("without a usable client id the server makes one and uses it", async () => {
  const res = await remember({});
  const id = res.headers.get("x-request-id") ?? "";
  assert.match(id, UUID);
  assert.equal(seen.at(-1), id);

  const bad = await remember({ "X-Request-Id": "bad id with spaces" });
  const badId = bad.headers.get("x-request-id") ?? "";
  assert.match(badId, UUID);
  assert.equal(seen.at(-1), badId);
});

test("refused requests carry an id too", async () => {
  const res = await fetch(`${base}/remember`, { method: "POST", headers: { "X-Request-Id": "refused-0001" } });
  assert.equal(res.status, 401);
  assert.equal(res.headers.get("x-request-id"), "refused-0001");
  const health = await fetch(`${base}/health`);
  assert.match(health.headers.get("x-request-id") ?? "", UUID);
});

test("one log line per request, with no key, body or query string", async () => {
  logs.length = 0;
  const res = await remember({ "X-Request-Id": "logged-request-0001" }, "?token=abc123");
  assert.equal(res.status, 200);
  await new Promise((r) => setImmediate(r));
  const lines = logs.filter((l) => l.includes("logged-request-0001"));
  assert.equal(lines.length, 1);
  assert.deepEqual(Object.keys(JSON.parse(lines[0])).sort(), ["event", "method", "ms", "path", "request_id", "status"]);
  const line = JSON.parse(lines[0]);
  assert.equal(line.event, "request");
  assert.equal(line.path, "/remember");
  assert.equal(line.status, 200);
  for (const leak of [KEY, "secret memory text", "abc123", "token"]) {
    assert.ok(!lines[0].includes(leak), `log line leaks ${leak}`);
  }
});
