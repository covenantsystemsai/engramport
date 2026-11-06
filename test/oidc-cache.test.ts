import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("OIDC disk and memory caches are audience-bound and respect a pinned disk identity", async () => {
  const dir = mkdtempSync(join(tmpdir(), "engramport-oidc-test-"));
  const cache = join(dir, "cache.json");
  const before = { cache: process.env.OIDC_TOKEN_CACHE_PATH, account: process.env.GCLOUD_ACCOUNT };
  const originalFetch = globalThis.fetch;
  process.env.OIDC_TOKEN_CACHE_PATH = cache;
  process.env.GCLOUD_ACCOUNT = "developer@example.invalid";
  let mints = 0;
  const audiences: string[] = [];
  globalThis.fetch = (async (url) => {
    const parsed = new URL(String(url));
    assert.equal(parsed.hostname, "metadata.google.internal");
    const aud = parsed.searchParams.get("audience")!;
    audiences.push(aud);
    mints++;
    // Synthetic token: no network, gcloud process, real credentials or home cache.
    return new Response(`header.${Buffer.from(JSON.stringify({ email: process.env.GCLOUD_ACCOUNT, aud })).toString("base64url")}.signature`);
  }) as typeof fetch;
  const seed = (audience?: string, identity = process.env.GCLOUD_ACCOUNT) => writeFileSync(cache, JSON.stringify({
    token: "synthetic-disk-token", identity, audience, expires_at: Date.now() + 600_000,
  }));
  try {
    const { getIdToken } = await import("../src/auth.ts");
    seed("https://a.example.run.app");
    assert.equal(await getIdToken("https://a.example.run.app"), "synthetic-disk-token");
    assert.equal(mints, 0);
    await getIdToken("https://b.example.run.app");
    assert.equal(mints, 1, "neither memory nor disk may reuse A for B");
    await getIdToken("https://b.example.run.app");
    assert.equal(mints, 1, "same audience reuses memory cache");
    seed();
    await getIdToken("https://c.example.run.app");
    assert.equal(mints, 2, "old disk entry without an audience is refused");
    seed("https://d.example.run.app", "different@example.invalid");
    await getIdToken("https://d.example.run.app");
    assert.equal(mints, 3, "disk cache cannot override pinned developer identity");
    assert.deepEqual(audiences, ["https://b.example.run.app", "https://c.example.run.app", "https://d.example.run.app"]);
  } finally {
    globalThis.fetch = originalFetch;
    for (const [key, value] of [["OIDC_TOKEN_CACHE_PATH", before.cache], ["GCLOUD_ACCOUNT", before.account]]) {
      if (value === undefined) delete process.env[key!]; else process.env[key!] = value;
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
