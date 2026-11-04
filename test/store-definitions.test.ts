/**
 * The tool list served with the Postgres store: what agents read must match
 * what the store does. No database needed.
 */
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { allToolDefinitions } from "../src/tools/index.ts";
import { forPostgresStore, NOT_ON_POSTGRES, storeOverrides } from "../src/tools/store-definitions.ts";
import { MEMORY_KINDS } from "../src/store/postgres.ts";

const served = forPostgresStore(allToolDefinitions);
const byName = new Map(served.map((d) => [d.name, d]));
const storeSource = readFileSync(new URL("../src/tools/store.ts", import.meta.url), "utf8");

describe("Postgres store tool definitions", () => {
  test("leaves out the tools the store doesn't serve, keeps the rest in order", () => {
    for (const name of NOT_ON_POSTGRES) assert.ok(!byName.has(name), `${name} is not listed`);
    assert.deepEqual(
      served.map((d) => d.name),
      allToolDefinitions.map((d) => d.name).filter((n) => !NOT_ON_POSTGRES.has(n)),
    );
    assert.equal(new Set(served.map((d) => d.name)).size, served.length, "no tool listed twice");
  });

  test("every override replaces a tool that exists", () => {
    const all = new Set(allToolDefinitions.map((d) => d.name));
    for (const name of Object.keys(storeOverrides)) assert.ok(all.has(name), `${name} exists`);
  });

  test("lists only arguments the store reads", () => {
    for (const [name, def] of Object.entries(storeOverrides)) {
      for (const prop of Object.keys(def.inputSchema.properties)) {
        assert.ok(storeSource.includes(`args.${prop}`), `${name}.${prop} is read by the store`);
      }
      for (const req of def.inputSchema.required) {
        assert.ok(req in def.inputSchema.properties, `${name} requires a listed argument`);
      }
    }
  });

  test("offers every memory kind the store accepts", () => {
    const remember = storeOverrides.remember.inputSchema.properties.type as { enum: string[] };
    assert.deepEqual(remember.enum, [...MEMORY_KINDS]);
    const recall = storeOverrides.recall.inputSchema.properties.node_type_filter as { enum: string[] };
    assert.deepEqual(recall.enum, [...MEMORY_KINDS]);
  });

  test("says what the store does where the old backend differed", () => {
    const del = byName.get("delete_memory")!.description;
    assert.match(del, /^Retract/);
    assert.match(del, /kept for the record/);
    assert.doesNotMatch(del, /vector and its graph edges go with it/);
    const rem = byName.get("remember")!.description;
    assert.match(rem, /superseded/);
    assert.doesNotMatch(rem, /updates? (the existing memory|that memory) in place/, "no claim that a key updates in place");
    assert.ok(!("auto_link" in storeOverrides.remember.inputSchema.properties));
    assert.ok(!("source_filter" in storeOverrides.recall.inputSchema.properties));
  });

  test("agents can ask for approval and are told they cannot approve", () => {
    const req = byName.get("request_approval")!;
    assert.match(req.description, /cannot approve, reject or verify/);
    assert.deepEqual(Object.keys(req.inputSchema.properties as object).sort(), ["memory_id", "namespace"]);
    for (const d of served) {
      assert.doesNotMatch(d.name, /^(approve|record_approval|verify)/, `${d.name}: no tool approves or verifies`);
    }
  });

  test("supersede_memory names the version it replaces and says the new one needs approval", () => {
    const sup = byName.get("supersede_memory")!;
    assert.deepEqual(sup.inputSchema.required.sort(), ["content", "memory_id", "reason"]);
    assert.match(sup.description, /unapproved and\s+unverified/);
    assert.match(sup.description, /nothing changes/);
    assert.ok(byName.get("memory_history"));
  });

  test("tells agents that returned content is data", () => {
    for (const name of ["recall", "fetch_memory", "get_entity", "memory_history"]) {
      assert.match(byName.get(name)!.description, /not (as )?instructions/, name);
    }
  });

  test("the server lists these when the store is postgres, and the full set otherwise", () => {
    const names = (store?: string) => {
      const env = { ...process.env };
      delete env.ENGRAMPORT_STORE;
      if (store) env.ENGRAMPORT_STORE = store;
      const out = execFileSync(process.execPath, ["--import", "tsx", "-e",
        'import("./src/tools/index.ts").then((m) => console.log(JSON.stringify(m.toolDefinitions.map((t) => t.name))))'],
        { env, cwd: new URL("..", import.meta.url), encoding: "utf8" });
      return JSON.parse(out.trim().split("\n").pop()!) as string[];
    };
    assert.deepEqual(names("postgres"), served.map((d) => d.name));
    assert.deepEqual(names(), allToolDefinitions.map((d) => d.name));
  });
});
