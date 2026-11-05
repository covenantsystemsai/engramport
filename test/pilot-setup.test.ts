import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, statSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { maskEmail, openKeysFile, parsePilotConfig, planFrom, type PilotConfig } from "../src/pilot-setup.ts";
import type { PilotTarget } from "../src/admin.ts";

const good = {
  namespace: "acme-city/realty/max",
  embedding_model: "gte-small",
  owner: {
    actor: "max-owner",
    display: "Max owner",
    email: "Owner@Example.com ",
    authority: { scope: "cell_knowledge", can_delegate: true, expires_in: "365d" },
  },
  agents: [
    { actor: "max-claude", display: "Claude for Max", read_only: false, expires_in: "90d" },
    { actor: "max-grok", display: "Grok for Max", read_only: true, expires_in: "30d" },
  ],
};
const parse = (o: unknown) => parsePilotConfig(JSON.stringify(o));
const refused = (o: unknown, pattern: RegExp) => assert.throws(() => parse(o), pattern);

test("a good config is read, with the email tidied", () => {
  const cfg = parse(good);
  assert.equal(cfg.owner.email, "owner@example.com");
  assert.equal(cfg.agents.length, 2);
});

test("anything unexpected in the config is refused, not ignored", () => {
  assert.throws(() => parsePilotConfig("{not json"), /not valid JSON/);
  refused({ ...good, extra: 1 }, /unknown field: extra/);
  refused({ ...good, owner: { ...good.owner, password: "x" } }, /owner has an unknown field: password/);
  refused({ ...good, namespace: "acme-city/max" }, /city\/tower\/cell/);
  refused({ ...good, namespace: "Acme/Realty/Max" }, /city\/tower\/cell/);
  refused({ ...good, owner: { ...good.owner, email: "not-an-address" } }, /not an email/);
  refused({ ...good, owner: { ...good.owner, authority: { ...good.owner.authority, scope: "promotion" } } }, /scope is one of cell_knowledge/);
  refused({ ...good, agents: [] }, /1 to 8 agents/);
  refused({ ...good, agents: [{ ...good.agents[0], expires_in: "400d" }] }, /at most 366 days/);
  refused({ ...good, agents: [{ ...good.agents[0], expires_in: "0" }] }, /more than 0/);
  refused({ ...good, agents: [{ ...good.agents[0], read_only: "no" }] }, /true or false/);
  refused({ ...good, agents: [{ ...good.agents[0], actor: "max-owner" }] }, /must be different/);
  refused({ ...good, agents: [{ ...good.agents[0], display: "a\u0007b" }] }, /printable/);
  const { owner: _o, ...noOwner } = good;
  refused(noOwner, /needs owner/);
});

const fresh: PilotTarget = {
  pieces: [
    { path: "acme-city", exists: false, level: null, purpose: null },
    { path: "acme-city/realty", exists: false, level: null, purpose: null },
    { path: "acme-city/realty/max", exists: false, level: null, purpose: null },
  ],
  takenActors: [],
  schemaReady: true,
  models: ["gte-small", "text-embedding-3-small"],
};

test("the plan names every step and masks the owner's email", () => {
  const plan = planFrom(parse(good) as PilotConfig, fresh, true);
  assert.deepEqual(plan.problems, []);
  assert.equal(plan.steps.length, 3 + 2 + 2);
  assert.ok(plan.steps.some((s) => s.includes("o***@example.com")));
  assert.ok(!plan.steps.join(" ").includes("owner@example.com"));
  assert.match(plan.steps.join(" "), /counts only once they accept it/);
  assert.equal(maskEmail("owner@example.com"), "o***@example.com");
});

test("the plan refuses what is already there, a company city, a missing schema or no pepper", () => {
  const cfg = parse(good) as PilotConfig;
  const exists = (i: number, level: string, purpose: "client" | "company") => ({
    ...fresh, pieces: fresh.pieces.map((p, j) => (j === i ? { ...p, exists: true, level, purpose } : p)),
  });
  assert.match(planFrom(cfg, exists(2, "cell", "client"), true).problems.join(" "), /already exists/);
  assert.match(planFrom(cfg, exists(0, "city", "company"), true).problems.join(" "), /company namespace/);
  assert.deepEqual(planFrom(cfg, exists(0, "city", "client"), true).problems, [], "an existing client city is used");
  assert.match(planFrom(cfg, { ...fresh, takenActors: ["max-grok"] }, true).problems.join(" "), /max-grok is already taken/);
  assert.match(planFrom(cfg, { ...fresh, schemaReady: false, models: [] }, true).problems.join(" "), /missing migrations/);
  assert.match(planFrom(cfg, { ...fresh, models: ["text-embedding-3-small"] }, true).problems.join(" "), /no embedding model gte-small/);
  assert.match(planFrom(cfg, fresh, false).problems.join(" "), /KEY_PEPPER/);
});

test("the keys file is new, readable only by its owner, and never inside a repository", () => {
  const dir = mkdtempSync(join(tmpdir(), "ep-keys-"));
  try {
    const f = openKeysFile(join(dir, "keys.jsonl"));
    assert.equal(statSync(f.path).mode & 0o777, 0o600);
    assert.throws(() => openKeysFile(join(dir, "keys.jsonl")), /already exists/);
    writeFileSync(join(dir, "existing"), "x");
    assert.throws(() => openKeysFile(join(dir, "existing")), /already exists/);
    assert.throws(() => openKeysFile(join(dir, "nowhere", "keys.jsonl")), /does not exist/);
    mkdirSync(join(dir, "repo", ".git"), { recursive: true });
    mkdirSync(join(dir, "repo", "sub"));
    assert.throws(() => openKeysFile(join(dir, "repo", "sub", "keys.jsonl")), /inside a git working tree/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the example config in deploy/pilot is one the tool accepts", async () => {
  const { readFileSync } = await import("node:fs");
  const cfg = parsePilotConfig(readFileSync(new URL("../deploy/pilot/pilot.example.json", import.meta.url), "utf8"));
  assert.equal(cfg.namespace, "example-client/operations/pilot");
  assert.equal(cfg.agents.length, 3);
});
