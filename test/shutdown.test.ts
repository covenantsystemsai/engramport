import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { shutdown } from "../src/shutdown.ts";

const listen = (server: Server) =>
  new Promise<number>((resolve) => server.listen(0, "127.0.0.1", () => resolve((server.address() as AddressInfo).port)));
const get = (port: number) =>
  new Promise<{ status: number; body: string }>((resolve, reject) => {
    request({ port, host: "127.0.0.1", path: "/" }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
    }).on("error", reject).end();
  });

test("a request in flight finishes, then the pool closes, then the process exits 0", async () => {
  const order: string[] = [];
  let release!: () => void;
  const held = new Promise<void>((r) => (release = r));
  const server = createServer(async (_req, res) => {
    await held;
    order.push("request done");
    res.end("ok");
  });
  const port = await listen(server);
  const inFlight = get(port);
  await new Promise((r) => setTimeout(r, 50));
  let code = -1;
  const stopping = shutdown(server, {
    graceMs: 5_000,
    closers: [async () => { order.push("pool closed"); }],
    exit: (c) => { code = c; order.push("exit"); },
    log: () => {},
  });
  await new Promise((r) => setTimeout(r, 50));
  await assert.rejects(get(port), "no new connections once stopping");
  release();
  assert.deepEqual(await inFlight, { status: 200, body: "ok" });
  await stopping;
  assert.equal(code, 0);
  assert.deepEqual(order, ["request done", "pool closed", "exit"]);
});

test("past the grace period it exits 1 rather than wait to be killed", async () => {
  const server = createServer(() => { /* never answers */ });
  const port = await listen(server);
  void get(port).catch(() => undefined);
  await new Promise((r) => setTimeout(r, 50));
  let code = -1;
  const lines: string[] = [];
  await shutdown(server, { graceMs: 200, exit: (c) => { code = c; }, log: (l) => lines.push(l) });
  assert.equal(code, 1);
  assert.match(lines.join(" "), /requests still running/);
  server.closeAllConnections();
});

test("a closer that fails is logged, and the others still run", async () => {
  const server = createServer();
  await listen(server);
  const ran: string[] = [];
  const lines: string[] = [];
  let code = -1;
  await shutdown(server, {
    closers: [async () => { throw new Error("pool already closed"); }, async () => { ran.push("second"); }],
    exit: (c) => { code = c; },
    log: (l) => lines.push(l),
  });
  assert.equal(code, 0);
  assert.deepEqual(ran, ["second"]);
  assert.match(lines.join(" "), /pool already closed/);
});
