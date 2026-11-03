/**
 * The extraction job's model-independent half: what an extractor must return,
 * and how its output is checked before any of it reaches the graph.
 *
 * An extractor reads one memory's text and names the entities and relations in
 * it. Whatever it returns is untrusted: a model can be wrong, repeat itself,
 * invent quotes or be steered by the text it reads. So cleanExtraction keeps
 * only well-formed items within the graph's limits, drops a quote that is not
 * in the memory word for word, drops self-relations and duplicates, and never
 * takes aliases or memory links, which stay for agents to assert. What is left
 * is written by PostgresStore.extract with origin 'extracted', which only the
 * job transport may use, so readers can always tell a model's reading from an
 * agent's claim.
 */

export interface ExtractedEntity {
  name: string;
  type: string;
  description?: string;
}

export interface ExtractedRelation {
  source: { name: string; type: string };
  predicate: string;
  target: { name: string; type: string };
  confidence?: number;
  /** Words copied from the memory that support the relation. */
  evidence?: string;
}

export interface Extraction {
  entities: ExtractedEntity[];
  relations: ExtractedRelation[];
}

/**
 * Reads one memory. id names the extractor and its version, such as
 * "claude-haiku/v1": a memory is read once per id, so a better extractor gets
 * a new id and reads everything again.
 */
export interface Extractor {
  readonly id: string;
  extract(input: { text: string; kind: string }): Promise<unknown>;
}

/**
 * A failure the job records as a short class, never as a message: a
 * provider's error text can echo the memory it was sent.
 */
export class ExtractorError extends Error {
  readonly errorClass: string;
  constructor(errorClass: string) {
    super(`extractor failed: ${errorClass}`);
    this.name = "ExtractorError";
    this.errorClass = ERROR_CLASS.test(errorClass) ? errorClass : "error";
  }
}

export const EXTRACTOR_ID = /^[a-z0-9][a-z0-9._/-]{0,63}$/;
export const ERROR_CLASS = /^[a-z_]{1,32}$/;
export const MAX_EXTRACTED_ENTITIES = 50;
export const MAX_EXTRACTED_RELATIONS = 100;
const TYPE = /^[a-z][a-z0-9_]{0,31}$/;
const PREDICATE = /^[a-z][a-z0-9_]{0,47}$/;
const MAX_NAME = 200;
const MAX_DESCRIPTION = 2000;
const MAX_EVIDENCE = 1000;

/** "Works On" and "works-on" both become works_on; anything else that fails is dropped. */
function slug(value: unknown, pattern: RegExp): string | null {
  if (typeof value !== "string") return null;
  const s = value.normalize("NFKC").trim().toLowerCase().replace(/[\s-]+/g, "_");
  return pattern.test(s) ? s : null;
}

/** Control characters, NUL included, which Postgres text cannot hold. */
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

function name(value: unknown): string | null {
  if (typeof value !== "string" || CONTROL.test(value)) return null;
  const s = value.normalize("NFKC").replace(/\s+/g, " ").trim();
  return s.length >= 1 && s.length <= MAX_NAME ? s : null;
}

/** Close to memory.norm_key, for spotting duplicates before the database does. */
function key(n: string, type: string): string {
  return `${type}:${n.toLowerCase()}`;
}

function ref(value: unknown): { name: string; type: string } | null {
  if (!value || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  const n = name(v.name);
  const t = slug(v.type, TYPE);
  return n && t ? { name: n, type: t } : null;
}

/**
 * Check an extractor's raw output against the memory it read. Throws
 * ExtractorError("bad_output") only when the output is not an object with
 * entity and relation lists at all; bad items inside are dropped one by one.
 */
export function cleanExtraction(raw: unknown, text: string): Extraction {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new ExtractorError("bad_output");
  const r = raw as Record<string, unknown>;
  const rawEntities = r.entities ?? [];
  const rawRelations = r.relations ?? [];
  if (!Array.isArray(rawEntities) || !Array.isArray(rawRelations)) throw new ExtractorError("bad_output");

  const entities = new Map<string, ExtractedEntity>();
  for (const item of rawEntities) {
    if (entities.size >= MAX_EXTRACTED_ENTITIES) break;
    const e = ref(item);
    if (!e || entities.has(key(e.name, e.type))) continue;
    const d = (item as Record<string, unknown>).description;
    const description =
      typeof d === "string" && d.trim() && d.length <= MAX_DESCRIPTION && !CONTROL.test(d) ? d.trim() : undefined;
    entities.set(key(e.name, e.type), description ? { ...e, description } : e);
  }

  const relations = new Map<string, ExtractedRelation>();
  for (const item of rawRelations) {
    if (relations.size >= MAX_EXTRACTED_RELATIONS) break;
    if (!item || typeof item !== "object") continue;
    const v = item as Record<string, unknown>;
    const source = ref(v.source);
    const target = ref(v.target);
    const predicate = slug(v.predicate, PREDICATE);
    if (!source || !target || !predicate) continue;
    const s = key(source.name, source.type);
    const t = key(target.name, target.type);
    if (s === t) continue;
    const k = `${s}|${predicate}|${t}`;
    if (relations.has(k)) continue;
    const rel: ExtractedRelation = { source, predicate, target };
    if (typeof v.confidence === "number" && v.confidence >= 0 && v.confidence <= 1) rel.confidence = v.confidence;
    if (typeof v.evidence === "string") {
      const ev = v.evidence.trim();
      if (ev && ev.length <= MAX_EVIDENCE && text.includes(ev)) rel.evidence = ev;
    }
    relations.set(k, rel);
  }

  // A relation's ends count as found even when the extractor did not list them,
  // but only while there is room under the entity cap.
  for (const rel of relations.values()) {
    for (const end of [rel.source, rel.target]) {
      const k = key(end.name, end.type);
      if (!entities.has(k) && entities.size < MAX_EXTRACTED_ENTITIES) entities.set(k, end);
    }
  }
  const keep = [...relations.values()].filter(
    (rel) => entities.has(key(rel.source.name, rel.source.type)) && entities.has(key(rel.target.name, rel.target.type)),
  );
  return { entities: [...entities.values()], relations: keep };
}
