/** cleanExtraction: what of an extractor's output may reach the graph. No database needed. */
import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { cleanExtraction, ExtractorError } from "../src/store/extract.ts";

const text = "Grok Bot builds the EngramPort server.";

describe("cleanExtraction", () => {
  test("output that is not an object of lists is bad output", () => {
    for (const raw of [null, "text", 42, [], { entities: "x" }, { relations: {} }]) {
      assert.throws(() => cleanExtraction(raw, text), (e: unknown) => e instanceof ExtractorError && e.errorClass === "bad_output");
    }
  });

  test("an empty object is an empty reading", () => {
    assert.deepEqual(cleanExtraction({}, text), { entities: [], relations: [] });
  });

  test("names and types are normalised, bad and repeated items dropped", () => {
    const r = cleanExtraction({
      entities: [
        { name: "  Grok   Bot ", type: "Agent" },
        { name: "grok bot", type: "agent" },
        { name: "x".repeat(201), type: "agent" },
        { name: "Ok", type: "9bad" },
        { name: 7, type: "agent" },
        "Grok Bot",
      ],
    }, text);
    assert.deepEqual(r.entities, [{ name: "Grok Bot", type: "agent" }]);
  });

  test("evidence must be in the memory word for word", () => {
    const r = cleanExtraction({
      relations: [
        { source: { name: "Grok Bot", type: "agent" }, predicate: "builds", target: { name: "EngramPort", type: "project" },
          evidence: "builds the EngramPort server" },
        { source: { name: "Grok Bot", type: "agent" }, predicate: "owns", target: { name: "EngramPort", type: "project" },
          evidence: "Grok Bot owns EngramPort" },
      ],
    }, text);
    assert.equal(r.relations[0].evidence, "builds the EngramPort server");
    assert.equal(r.relations[1].evidence, undefined);
  });

  test("predicates become slugs; self-relations, bad confidence and repeats are dropped", () => {
    const g = { name: "Grok Bot", type: "agent" };
    const e = { name: "EngramPort", type: "project" };
    const r = cleanExtraction({
      relations: [
        { source: g, predicate: "Works On", target: e, confidence: 2 },
        { source: g, predicate: "works-on", target: e },
        { source: g, predicate: "is", target: { name: "grok bot", type: "agent" } },
        { source: g, predicate: "", target: e },
        { source: g, predicate: "drop table", target: { name: "", type: "x" } },
      ],
    }, text);
    assert.deepEqual(r.relations, [{ source: g, predicate: "works_on", target: e }]);
    assert.deepEqual(r.entities, [g, e], "a relation's ends are counted as entities");
  });

  test("caps keep a runaway extractor within the graph's limits", () => {
    const entities = Array.from({ length: 80 }, (_, i) => ({ name: `E${i}`, type: "concept" }));
    const relations = Array.from({ length: 150 }, (_, i) => ({
      source: { name: `S${i}`, type: "concept" }, predicate: "rel", target: { name: `T${i}`, type: "concept" },
    }));
    const r = cleanExtraction({ entities, relations }, text);
    assert.equal(r.entities.length, 50);
    assert.equal(r.relations.length, 0, "no room left for any relation's ends, so none are kept");
    const r2 = cleanExtraction({ relations }, text);
    assert.equal(r2.entities.length, 50);
    assert.equal(r2.relations.length, 25);
  });

  test("an error class is a short word, or plain 'error'", () => {
    assert.equal(new ExtractorError("timeout").errorClass, "timeout");
    assert.equal(new ExtractorError("Provider said: secret text").errorClass, "error");
  });
});
