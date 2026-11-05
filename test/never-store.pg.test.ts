/**
 * The never-store policy (D-07) on every write path, against a real database:
 * each refused write answers "refused" and leaves nothing behind (no memory,
 * no provenance, no graph row), while an ordinary write still works. Needs
 * ENGRAMPORT_TEST_DATABASE_URL (a superuser URL to a THROWAWAY database), as
 * store.pg.test.ts does.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import pg from "pg";

import { hashKey, mintKey } from "../src/keys.ts";
import type { Extractor } from "../src/store/extract.ts";
import { PostgresStore } from "../src/store/postgres.ts";
import { executeStoreTool } from "../src/tools/store.ts";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const pepper = randomBytes(32);
const secret = `${"gh"}p_${"a".repeat(36)}`;

describe("never-store policy on every write path", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  let admin: pg.Pool;
  let appPool: pg.Pool;
  let store: PostgresStore;
  let jobStore: PostgresStore;
  let key: string;
  let nsId: string;
  const logged: string[] = [];
  const origLog = console.log;
  const origErr = console.error;

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    const ns = async (slug: string, level: string, parent: string | null) =>
      (await admin.query<{ id: string }>(
        "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, $2, $3) RETURNING id",
        [parent, level, slug],
      )).rows[0].id;
    const city = await ns(`ns-${run}`, "city", null);
    const tower = await ns("tower", "tower", city);
    nsId = await ns("cell", "cell", tower);
    const actor = (await admin.query<{ id: string }>(
      "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', $1, $1) RETURNING id", [`ns-${run}`],
    )).rows[0].id;
    const k = mintKey();
    await admin.query(
      "INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes) VALUES ($1, $2, $3, $4, $5)",
      [nsId, actor, k.prefix, hashKey(k.key, pepper), ["read", "write"]],
    );
    key = k.key;
    const appUrl = new URL(ADMIN_URL!);
    appUrl.username = "engramport_app";
    appUrl.password = "engramport-test-only";
    appPool = new pg.Pool({ connectionString: appUrl.toString() });
    store = new PostgresStore(appPool, { pepper, transport: "streamable_http" });
    jobStore = new PostgresStore(appPool, { pepper, transport: "job" });
    console.log = (...a: unknown[]) => void logged.push(a.map(String).join(" "));
    console.error = (...a: unknown[]) => void logged.push(a.map(String).join(" "));
  });

  after(async () => {
    console.log = origLog;
    console.error = origErr;
    await appPool?.end();
    await admin?.end();
  });

  /** Rows this namespace holds, by table. */
  const counts = async () => {
    const one = async (sql: string) => Number((await admin.query<{ n: string }>(sql, [nsId])).rows[0].n);
    return {
      memories: await one("SELECT count(*) AS n FROM memory.memories WHERE namespace_id = $1"),
      provenance: await one("SELECT count(*) AS n FROM memory.provenance WHERE namespace_id = $1"),
      entities: await one("SELECT count(*) AS n FROM memory.entities WHERE namespace_id = $1"),
      relations: await one("SELECT count(*) AS n FROM memory.relations WHERE namespace_id = $1"),
    };
  };

  const refused = async (tool: string, args: Record<string, unknown>, field: RegExp) => {
    const before = await counts();
    const res = await executeStoreTool(tool, args, store, key);
    assert.equal(res.isError, true, `${tool} should be refused`);
    const body = JSON.parse(res.content[0].text);
    assert.equal(body.code, "refused", `${tool}: ${body.error}`);
    assert.match(body.error, field);
    assert.ok(!body.error.includes(secret));
    assert.deepEqual(await counts(), before, `${tool} left something behind`);
  };

  test("an ordinary write still works on each path", async () => {
    const m = JSON.parse((await executeStoreTool("remember", {
      content: "Decision (Nov 3, owner role): task cards show the closing date first.",
      metadata: { topic: "tasks" }, source_url: "https://github.com/example/repo/issues/75",
    }, store, key)).content[0].text);
    assert.ok(m.id);
    const s = await executeStoreTool("supersede_memory", {
      memory_id: m.id, content: "Decision: task cards show the closing date and status first.", reason: "Nov 5 meeting",
    }, store, key);
    assert.ok(!s.isError, s.content[0].text);
    const u = await executeStoreTool("upload", { content: "Section 7.1 Setbacks. Ten feet.", filename: "ordinance-7.txt" }, store, key);
    assert.ok(!u.isError, u.content[0].text);
    const l = await executeStoreTool("link", { entities: [{ name: "Property PROP-2026-0042", type: "property" }] }, store, key);
    assert.ok(!l.isError, l.content[0].text);
  });

  test("remember refuses each kind of item in each field, and stores nothing", async () => {
    await refused("remember", { content: `deploy token ${secret}` }, /content looks like a secret/);
    await refused("remember", { content: "Seller: jane.doe@example.com" }, /content has contact details/);
    await refused("remember", { content: "[00:01] Sam: hi\n[00:02] Lee: hey\n[00:03] Sam: so" }, /meeting transcript/);
    await refused("remember", { content: "fine", dedup_key: secret }, /dedup_key looks like a secret/);
    await refused("remember", { content: "fine", metadata: { buyer_name: "x" } }, /metadata\.buyer_name/);
    await refused("remember", { content: "fine", metadata: { nested: { a: 1 } } }, /metadata\.nested/);
    await refused("remember", { content: "fine", source_url: "https://x.example.com/f?token=abc" }, /source_url has a link/);
    await refused("remember", { content: "fine", source_url: "http://x.example.com/f" }, /source_url isn't a field/);
  });

  test("supersede_memory refuses the new text and the reason, and adds no version", async () => {
    const m = JSON.parse((await executeStoreTool("remember", { content: "Status: open." }, store, key)).content[0].text);
    await refused("supersede_memory", { memory_id: m.id, content: "Card 4111 1111 1111 1111", reason: "update" }, /content has what looks like a card/);
    await refused("supersede_memory", { memory_id: m.id, content: "Status: closed.", reason: `call 252-555-0143` }, /reason has contact details/);
  });

  test("upload refuses a transcript file or text, and stores no chunk", async () => {
    await refused("upload", { content: "Section 1.", filename: "Nov 3 call.vtt" }, /filename looks like a meeting transcript/);
    await refused("upload", { content: "WEBVTT\n\n00:00:01.000 --> 00:00:02.000\nhi", filename: "notes.txt" }, /content looks like a meeting transcript/);
  });

  test("link refuses names, aliases, descriptions and evidence, and writes no graph row", async () => {
    await refused("link", { entities: [{ name: "jane.doe@example.com", type: "person" }] }, /entities\[0\]\.name has contact details/);
    await refused("link", { entities: [{ name: "Seller", type: "role", aliases: ["(919) 555-0199"] }] }, /aliases\[0\]/);
    await refused("link", { entities: [{ name: "Gate", type: "place", description: "gate code: 4471#" }] }, /description looks like a secret/);
    const m = JSON.parse((await executeStoreTool("remember", { content: "Vendors." }, store, key)).content[0].text);
    await refused("link", {
      memory_id: m.id,
      relations: [{ source: { name: "a co", type: "org" }, predicate: "pays", target: { name: "b co", type: "org" }, evidence: `key ${secret}` }],
    }, /relations\[0\]\.evidence looks like a secret/);
  });

  test("extraction is held to the same rules", async () => {
    await executeStoreTool("remember", { content: "Extraction sample." }, store, key);
    const extractor: Extractor = {
      id: `ns-test-${run}/v1`,
      async extract() {
        return { entities: [{ name: "owner@example.com", type: "person" }], relations: [] };
      },
    };
    const before = await counts();
    const summary = await jobStore.extract(key, extractor, { limit: 50 });
    assert.ok(summary.failed >= 1);
    assert.equal(summary.entities, 0);
    const after = await counts();
    assert.equal(after.entities, before.entities);
  });

  test("nothing refused reaches a log line", () => {
    assert.ok(logged.some((l) => l.includes('"event":"write_refused"')));
    for (const l of logged) {
      assert.ok(!l.includes(secret), "a log line holds the secret");
      assert.ok(!l.includes("jane.doe@example.com"), "a log line holds the email");
    }
  });
});
