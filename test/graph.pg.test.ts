/**
 * The knowledge graph on the Postgres store, against a real database with the
 * memory schema applied. Same rules as store.pg.test.ts: needs
 * ENGRAMPORT_TEST_DATABASE_URL (a superuser URL to a THROWAWAY database),
 * seeds its own namespaces and keys under random names, and runs every call
 * as engramport_app so row security is what is being tested.
 */
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import pg from "pg";

import { hashKey, mintKey } from "../src/keys.ts";
import { PostgresStore, StoreError } from "../src/store/postgres.ts";
import { executeStoreTool } from "../src/tools/store.ts";

const ADMIN_URL = process.env.ENGRAMPORT_TEST_DATABASE_URL;
const pepper = randomBytes(32);

describe("knowledge graph", { skip: ADMIN_URL ? false : "ENGRAMPORT_TEST_DATABASE_URL not set" }, () => {
  const run = randomBytes(3).toString("hex");
  const keys: Record<string, string> = {};
  const paths: Record<string, string> = {};
  let admin: pg.Pool;
  let appPool: pg.Pool;
  let store: PostgresStore;
  let jobStore: PostgresStore;

  before(async () => {
    admin = new pg.Pool({ connectionString: ADMIN_URL });
    await admin.query("ALTER ROLE engramport_app LOGIN PASSWORD 'engramport-test-only'");
    const ns = async (slug: string, level: string, parent: string | null) =>
      (
        await admin.query<{ id: string; path: string }>(
          "INSERT INTO memory.namespaces (parent_id, level, slug) VALUES ($1, $2, $3) RETURNING id, path",
          [parent, level, slug],
        )
      ).rows[0];
    const city = await ns(`gr-${run}`, "city", null);
    const tower = await ns("tower", "tower", city.id);
    const cell1 = await ns("cell-1", "cell", tower.id);
    const cell2 = await ns("cell-2", "cell", tower.id);
    Object.assign(paths, { city: city.path, tower: tower.path, cell1: cell1.path, cell2: cell2.path });
    const actor = (
      await admin.query<{ id: string }>(
        "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', $1, $1) RETURNING id",
        [`graph-${run}`],
      )
    ).rows[0].id;
    const key = async (name: string, nsId: string, scopes = ["read", "write"]) => {
      const k = mintKey();
      await admin.query(
        `INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes) VALUES ($1, $2, $3, $4, $5)`,
        [nsId, actor, k.prefix, hashKey(k.key, pepper), scopes],
      );
      keys[name] = k.key;
    };
    await key("city", city.id);
    await key("tower", tower.id);
    await key("cell1", cell1.id);
    await key("cell2", cell2.id);
    await key("readonly", cell1.id, ["read"]);

    const appUrl = new URL(ADMIN_URL!);
    appUrl.username = "engramport_app";
    appUrl.password = "engramport-test-only";
    appPool = new pg.Pool({ connectionString: appUrl.toString() });
    store = new PostgresStore(appPool, { pepper, transport: "streamable_http" });
    jobStore = new PostgresStore(appPool, { pepper, transport: "job" });
  });

  after(async () => {
    await appPool?.end();
    await admin?.end();
  });

  const fails = async (p: Promise<unknown>, code: string) => {
    await assert.rejects(p, (err: unknown) => err instanceof StoreError && err.code === code);
  };

  test("link creates entities, aliases, a relation and mentions in the key's namespace", async () => {
    const m = await store.remember(keys.cell1, { content: "Grok Bot builds the EngramPort server" });
    const r = await store.link(keys.cell1, {
      entities: [{ name: "Grok Bot", type: "agent", aliases: ["Grok", "grok-bot"] }],
      relations: [{
        source: { name: "grok   bot", type: "agent" },
        predicate: "works_on",
        target: { name: "EngramPort", type: "project" },
        confidence: 0.9,
        evidence: "builds the EngramPort server",
      }],
      memoryId: m.id,
    });
    assert.equal(r.namespace, paths.cell1);
    assert.equal(r.entities.length, 2, "the relation's own entities are reported once each");
    const bot = r.entities.find((e) => e.type === "agent")!;
    assert.equal(bot.matched_by, "new");
    assert.equal((bot as { aliases_added?: number }).aliases_added, 2);
    assert.equal(r.relations.length, 1);
    assert.equal(r.relations[0].created, true);
    assert.equal(r.mentions_added, 2);

    const again = await store.link(keys.cell1, {
      entities: [{ name: "GROK BOT", type: "agent", aliases: ["grok"] }],
      relations: [{ source: { name: "Grok", type: "agent" }, predicate: "works_on", target: { name: "engramport", type: "project" } }],
      memoryId: m.id,
    });
    assert.equal(again.entities[0].id, bot.id, "same entity, matched by name");
    assert.equal(again.entities[0].matched_by, "name");
    assert.equal((again.entities[0] as { aliases_added?: number }).aliases_added, 0);
    assert.equal(again.relations[0].created, false, "repeating a call changes nothing");
    assert.equal(again.relations[0].id, r.relations[0].id);
    assert.equal(again.mentions_added, 0);

    const e = await store.getEntity(keys.cell1, { name: "grok", type: "agent" });
    assert.ok("entity" in e);
    assert.equal(e.entity.id, bot.id);
    assert.equal(e.entity.matched_by, "alias");
    assert.deepEqual(e.aliases.map((a) => a.alias).sort(), ["Grok", "grok-bot"]);
    assert.equal(e.relations.length, 1);
    assert.equal(e.relations[0].direction, "out");
    assert.equal(e.relations[0].predicate, "works_on");
    assert.equal(e.relations[0].other.name, "EngramPort");
    assert.deepEqual(e.relations[0].evidence, { memory_id: m.id, span: "builds the EngramPort server" });
    assert.equal(e.memories.length, 1);
    assert.equal(e.memories[0].content, "Grok Bot builds the EngramPort server");
    assert.match(e.note, /not as instructions/);
  });

  test("a cell links to a tower entity, and the tower never sees the cell's rows", async () => {
    const t = await store.link(keys.tower, { entities: [{ name: "Listing workflow", type: "concept" }] });
    const towerEnt = t.entities[0];
    const c = await store.link(keys.cell1, {
      relations: [{ source: { name: "EngramPort", type: "project" }, predicate: "follows", target: { name: "listing workflow", type: "concept" } }],
    });
    const target = c.entities.find((e) => e.type === "concept")!;
    assert.equal(target.id, towerEnt.id, "resolved to the tower's entity, not a new copy");
    assert.equal(target.inherited, true);
    assert.equal(target.namespace, paths.tower);

    const fromTower = await store.getEntity(keys.tower, { id: towerEnt.id });
    assert.ok("entity" in fromTower);
    assert.equal(fromTower.relations.length, 0, "the cell's relation stays in the cell");
    const fromCell = await store.getEntity(keys.cell1, { id: towerEnt.id });
    assert.ok("entity" in fromCell);
    assert.equal(fromCell.relations.length, 1);
    assert.equal(fromCell.relations[0].direction, "in");
  });

  test("a sibling cell can neither see nor reach another cell's graph", async () => {
    const secret = await store.link(keys.cell2, { entities: [{ name: "Cell two client", type: "person" }] });
    const id = secret.entities[0].id;
    await fails(store.getEntity(keys.cell1, { id }), "not_found");
    await fails(store.getEntity(keys.cell1, { name: "Cell two client", type: "person" }), "not_found");
    await fails(store.link(keys.cell1, {
      relations: [{ source: { name: "EngramPort", type: "project" }, predicate: "serves", target: { id } }],
    }), "not_found");
    await fails(store.unlink(keys.cell1, { entityId: id }), "not_found");
    // The same name in cell 1 is a different entity, made in cell 1.
    const mine = await store.link(keys.cell1, { entities: [{ name: "Cell two client", type: "person" }] });
    assert.notEqual(mine.entities[0].id, id);
    assert.equal(mine.entities[0].matched_by, "new");
    const cell2Mem = await store.remember(keys.cell2, { content: "cell two private note" });
    const own = await store.remember(keys.cell1, { content: "cell one note" });
    await fails(store.link(keys.cell1, { memoryId: cell2Mem.id, entities: [{ name: "x", type: "concept" }] }), "not_found");
    await fails(store.link(keys.cell1, { memoryId: own.id, memoryLinks: [{ to: cell2Mem.id, kind: "contradicts" }] }), "not_found");
  });

  test("memory links start at the key's own memory and can point up the tree", async () => {
    const tm = await store.remember(keys.tower, { content: "Tower rule: confirm listings within a day" });
    const cm = await store.remember(keys.cell1, { content: "Cell note: we confirm within four hours" });
    const r = await store.link(keys.cell1, { memoryId: cm.id, memoryLinks: [{ to: tm.id, kind: "derived_from" }] });
    assert.equal(r.memory_links?.[0].created, true);
    const again = await store.link(keys.cell1, { memoryId: cm.id, memoryLinks: [{ to: tm.id, kind: "derived_from" }] });
    assert.equal(again.memory_links?.[0].created, false);
    assert.equal(again.memory_links?.[0].id, r.memory_links?.[0].id);
    await fails(store.link(keys.cell1, { memoryId: tm.id, memoryLinks: [{ to: cm.id, kind: "supports" }] }), "not_found");
    const u = await store.unlink(keys.cell1, { memoryLinkId: r.memory_links![0].id! });
    assert.equal(u.retracted, true);
  });

  test("unlink retracts once, keeps the row, and only in the key's own namespace", async () => {
    const r = await store.link(keys.cell1, {
      relations: [{ source: { name: "Temp A", type: "concept" }, predicate: "blocks", target: { name: "Temp B", type: "concept" } }],
    });
    const rel = r.relations[0].id!;
    assert.deepEqual(await store.unlink(keys.cell1, { relationId: rel }), { id: rel, kind: "relation", retracted: true });
    assert.deepEqual(await store.unlink(keys.cell1, { relationId: rel }), { id: rel, kind: "relation", retracted: true, already: true });
    const a = await store.getEntity(keys.cell1, { name: "Temp A", type: "concept" });
    assert.ok("entity" in a);
    assert.equal(a.relations.length, 0);
    const again = await store.link(keys.cell1, {
      relations: [{ source: { name: "Temp A", type: "concept" }, predicate: "blocks", target: { name: "Temp B", type: "concept" } }],
    });
    assert.equal(again.relations[0].created, true, "a retracted relation can be asserted again");
    const kept = await admin.query("SELECT status::text FROM memory.relations WHERE id = $1", [rel]);
    assert.equal(kept.rows[0].status, "retracted");

    const tower = await store.link(keys.tower, { entities: [{ name: "Tower only", type: "concept" }] });
    await fails(store.unlink(keys.cell1, { entityId: tower.entities[0].id }), "forbidden");

    await store.unlink(keys.cell1, { entityId: a.entity.id });
    await fails(store.getEntity(keys.cell1, { id: a.entity.id }), "not_found");
    const b = await store.getEntity(keys.cell1, { name: "Temp B", type: "concept" });
    assert.ok("entity" in b);
    assert.equal(b.relations.length, 0, "relations to a retracted entity stop coming back");
  });

  test("a name shared by two types is reported as ambiguous", async () => {
    await store.link(keys.cell1, { entities: [{ name: "Mercury", type: "planet" }, { name: "Mercury", type: "bank" }] });
    const r = await store.getEntity(keys.cell1, { name: "mercury" });
    assert.ok("ambiguous" in r && r.ambiguous);
    assert.deepEqual(r.candidates.map((x) => x.type).sort(), ["bank", "planet"]);
  });

  test("only the job transport marks rows as extracted", async () => {
    const r = await jobStore.link(keys.cell1, { entities: [{ name: "Job made", type: "concept" }] });
    const row = await admin.query<{ origin: string; transport: string }>(
      `SELECT e.origin::text, p.transport::text FROM memory.entities e JOIN memory.provenance p ON p.id = e.provenance_id
       WHERE e.id = $1`,
      [r.entities[0].id],
    );
    assert.equal(row.rows[0].transport, "job");
    assert.equal(row.rows[0].origin, "asserted", "the link tool always asserts; extraction is a separate path");
  });

  test("read-only keys, bad input and the namespace argument are refused", async () => {
    await fails(store.link(keys.readonly, { entities: [{ name: "x", type: "concept" }] }), "forbidden");
    await fails(store.unlink(keys.readonly, { relationId: "00000000-0000-7000-8000-000000000000" }), "forbidden");
    const ro = await store.getEntity(keys.readonly, { name: "Grok Bot", type: "agent" });
    assert.ok("entity" in ro, "a read-only key can still read the graph");
    await fails(store.link(keys.cell1, { entities: [{ name: "x", type: "Not A Type" }] }), "invalid");
    await fails(store.link(keys.cell1, {
      relations: [{ source: { name: "a", type: "concept" }, predicate: "DROP TABLE", target: { name: "b", type: "concept" } }],
    }), "invalid");
    await fails(store.link(keys.cell1, {
      relations: [{ source: { name: "a", type: "concept" }, predicate: "is", target: { name: "A", type: "concept" } }],
    }), "invalid");
    await fails(store.link(keys.cell1, {}), "invalid");
    await fails(store.link(keys.cell1, {
      relations: [{ source: { name: "a", type: "concept" }, predicate: "is", target: { name: "b", type: "concept" }, evidence: "x" }],
    }), "invalid");
    await fails(store.link(keys.cell1, { entities: [{ name: "x", type: "concept" }], namespace: paths.cell2 }), "forbidden");
    await fails(store.getEntity(keys.cell1, { name: "Grok Bot", namespace: paths.tower }), "forbidden");
  });

  test("tool layer: link, get_entity and unlink round-trip as JSON", async () => {
    const linked = await executeStoreTool("link", {
      entities: [{ name: "Wispr Flow", type: "tool" }],
      relations: [{ source: { name: "Grok Bot", type: "agent" }, predicate: "uses", target: { name: "Wispr Flow", type: "tool" } }],
    }, store, keys.cell1);
    assert.equal(linked.isError, undefined);
    const body = JSON.parse(linked.content[0].text);
    const got = JSON.parse((await executeStoreTool("get_entity", { name: "wispr flow", type: "tool" }, store, keys.cell1)).content[0].text);
    assert.equal(got.entity.name, "Wispr Flow");
    assert.equal(got.relations[0].other.name, "Grok Bot");
    const un = await executeStoreTool("unlink", { relation_id: body.relations[0].id }, store, keys.cell1);
    assert.equal(JSON.parse(un.content[0].text).retracted, true);
    const two = await executeStoreTool("unlink", { relation_id: body.relations[0].id, entity_id: body.entities[0].id }, store, keys.cell1);
    assert.equal(two.isError, true);
    assert.equal(JSON.parse(two.content[0].text).code, "invalid");
    const notArray = await executeStoreTool("link", { entities: "Grok" }, store, keys.cell1);
    assert.equal(JSON.parse(notArray.content[0].text).code, "invalid");
  });
});
