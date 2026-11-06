import { test } from "node:test";
import { createServer, type Server } from "node:http";
import type { Socket } from "node:net";
import assert from "node:assert/strict";
import { legacyFetch } from "../src/legacy-auth.ts";
import { config, resolveConfig } from "../src/config.ts";
import { backendKey, runAsCaller, setCallerRequired } from "../src/caller.ts";

const direct = resolveConfig({ ENGRAMPORT_API_URL: "https://backend.example.run.app", ENGRAMPORT_MODE: "stdio" });
const gateway = resolveConfig({ ENGRAMPORT_API_URL: "https://gateway.example.com", ENGRAMPORT_LEGACY_AUTH: "gateway", ENGRAMPORT_MODE: "stdio" });
const init = { method: "POST", headers: { "X-API-Key": "synthetic-caller-key" }, body: '{"query":"synthetic"}' };
const noFetch = (async () => { assert.fail("must not contact the backend"); }) as typeof fetch;

test("direct requests fail closed on missing, blank, malformed or unavailable identity", async () => {
  for (const token of ["", " ", "bad\nheader"]) {
    await assert.rejects(legacyFetch(direct, `${direct.apiUrl}/v2/recall`, init, {
      fetchImpl: noFetch, idToken: async () => token,
    }), /no request sent/i);
  }
  const secret = "sensitive provider diagnostic";
  await assert.rejects(legacyFetch(direct, `${direct.apiUrl}/v2/memory`, init, {
    fetchImpl: noFetch, idToken: async () => { throw new Error(secret); },
  }), (e: Error) => e.message.includes("no request sent") && !e.message.includes(secret));
});

test("both direct and gateway tool requests require the caller key", async () => {
  for (const cfg of [direct, gateway]) {
    await assert.rejects(legacyFetch(cfg, `${cfg.apiUrl}/v2/memory`, {}, { fetchImpl: noFetch }), /caller.*API key/);
  }
});

test("direct service call carries distinct credentials and the canonical audience", async () => {
  const cfg = { ...direct, apiUrl: "https://tagged.example.run.app", oidcAudience: direct.apiUrl };
  let count = 0;
  const response = await legacyFetch(cfg, `${cfg.apiUrl}/v2/recall`, {
    ...init, headers: { ...init.headers, "X-Serverless-Authorization": "Bearer spoofed" },
  }, {
    idToken: async (aud) => { assert.equal(aud, direct.apiUrl); return "synthetic-google-token"; },
    fetchImpl: (async (_url, options) => {
      count++;
      const headers = new Headers(options?.headers);
      assert.equal(headers.get("X-API-Key"), init.headers["X-API-Key"]);
      assert.equal(headers.get("X-Serverless-Authorization"), "Bearer synthetic-google-token");
      assert.equal(options?.redirect, "error");
      assert.equal(options?.body, init.body);
      return new Response("{}", { status: 200 });
    }) as typeof fetch,
  });
  assert.equal(response.status, 200);
  assert.equal(count, 1);
});

test("explicit gateway preserves application auth without demanding a user's Google token", async () => {
  const res = await legacyFetch(gateway, `${gateway.apiUrl}/v2/recall`, {
    ...init, headers: { ...init.headers, "X-Serverless-Authorization": "Bearer spoofed" },
  }, {
    idToken: async () => { assert.fail("gateway owns the upstream Google identity"); },
    fetchImpl: (async (_url, options) => {
      const headers = new Headers(options?.headers);
      assert.equal(headers.get("X-API-Key"), init.headers["X-API-Key"]);
      assert.equal(headers.has("X-Serverless-Authorization"), false);
      assert.equal(options?.redirect, "error");
      return new Response("{}");
    }) as typeof fetch,
  });
  assert.equal(res.status, 200);
});

test("unknown mode, unsafe gateway, bad audience and cross-origin requests are refused", async () => {
  for (const cfg of [
    { ...direct, legacyAuth: "off" },
    { ...direct, legacyAuth: "gateway" },
    { ...gateway, apiUrl: "https://backend.example.run.app." },
    { ...gateway, apiUrl: "http://gateway.example.com" },
    { ...gateway, apiUrl: "https://user:password@gateway.example.com" },
    { ...gateway, apiUrl: "https://gateway.example.com/?token=secret" },
    { ...gateway, oidcAudience: direct.apiUrl },
    { ...direct, oidcAudience: "http://bad.example.com" },
    { ...direct, oidcAudience: `${direct.apiUrl}/path` },
  ]) {
    await assert.rejects(legacyFetch(cfg, `${cfg.apiUrl}/v2/recall`, init, { fetchImpl: noFetch }), /configuration/);
  }
  await assert.rejects(legacyFetch(direct, "https://other.example.com/v2/recall", init, { fetchImpl: noFetch }), /origin/);
});

test("401 and 403 are not retried anonymously or through a gateway", async () => {
  // Responses stand in for invalid/expired identity, no Invoker grant, and
  // invalid application key. This does not simulate Google's token verifier.
  for (const status of [401, 403]) {
    let count = 0;
    const res = await legacyFetch(direct, `${direct.apiUrl}/v2/recall`, init, {
      idToken: async () => "synthetic-rejected-token",
      fetchImpl: (async () => { count++; return new Response("", { status }); }) as typeof fetch,
    });
    assert.equal(res.status, status);
    assert.equal(count, 1);
  }
});

test("hosted concurrent calls keep their own key; no server-key fallback", async () => {
  setCallerRequired(true);
  try {
    assert.throws(() => backendKey("server-key"), /No authenticated caller/);
    const seen: string[] = [];
    await Promise.all(["caller-a", "caller-b"].map((apiKey) => runAsCaller({ apiKey }, async () => {
      await Promise.resolve();
      await legacyFetch(direct, `${direct.apiUrl}/v2/recall`, {
        headers: { "X-API-Key": backendKey("server-key") },
      }, {
        idToken: async () => "synthetic-service-token",
        fetchImpl: (async (_url, options) => {
          seen.push(new Headers(options?.headers).get("X-API-Key")!);
          return new Response("{}");
        }) as typeof fetch,
      });
    })));
    assert.deepEqual(seen.sort(), ["caller-a", "caller-b"]);
  } finally { setCallerRequired(false); }
});


test("all legacy tool operations use the guarded transport", async () => {
  const api = await import("../src/eidetic.ts");
  const saved = { ...config };
  const originalFetch = globalThis.fetch;
  const calls = [
    () => api.remember("synthetic note", "test"),
    () => api.recall("synthetic query", "test"),
    () => api.chat("synthetic question", "test"),
    () => api.upload("synthetic document", "note.txt", "test"),
    () => api.groom("test"), () => api.dream("test"), () => api.inspect("test"),
    () => api.graph("test"), () => api.fetchMemory("test-id", "test"),
    () => api.deleteMemory("test-id", "test"), () => api.listNamespaces(),
    () => api.exportBrain("test"),
  ];
  let count = 0;
  globalThis.fetch = (async (_url, options) => {
    count++;
    assert.equal(new Headers(options?.headers).get("X-API-Key"), "synthetic-caller-key");
    assert.equal(options?.redirect, "error");
    return new Response("{}");
  }) as typeof fetch;
  try {
    Object.assign(config, gateway, { apiKey: "" });
    for (const call of calls) await assert.rejects(call(), /caller.*API key/);
    assert.equal(count, 0);
    for (const call of calls) await runAsCaller({ apiKey: "synthetic-caller-key" }, call);
    assert.equal(count, calls.length);
    globalThis.fetch = (async () => new Response("sensitive upstream body", { status: 403 })) as typeof fetch;
    await assert.rejects(runAsCaller({ apiKey: "synthetic-caller-key" }, calls[0]),
      (e: Error) => e.message.includes("403") && !e.message.includes("sensitive"));
  } finally { Object.assign(config, saved); globalThis.fetch = originalFetch; }
});

test("legacy error responses are closed unread, so connections don't pile up", async () => {
  const api = await import("../src/eidetic.ts");
  const saved = { ...config };
  const originalFetch = globalThis.fetch;
  const open = new Set<Socket>();
  const big = "x".repeat(256 * 1024);
  const server: Server = createServer((_req, res) => {
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end(big);
  });
  server.on("connection", (socket: Socket) => {
    open.add(socket);
    socket.on("close", () => open.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  // The client is configured for a reviewed https gateway; the test routes each
  // request to a local plain-HTTP server that answers with a large error body.
  globalThis.fetch = ((url: string | URL | Request, options?: RequestInit) => {
    const u = new URL(String(url));
    return originalFetch(`http://127.0.0.1:${port}${u.pathname}`, options);
  }) as typeof fetch;
  try {
    Object.assign(config, gateway, { apiKey: "" });
    for (let i = 0; i < 20; i++) {
      await assert.rejects(runAsCaller({ apiKey: "synthetic-caller-key" }, () => api.recall("synthetic query", "test")),
        (e: Error) => e.message.includes("500") && !e.message.includes("xxxx"));
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.ok(open.size <= 2, `${open.size} connections still open after 20 error responses`);
  } finally {
    Object.assign(config, saved);
    globalThis.fetch = originalFetch;
    for (const socket of open) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
