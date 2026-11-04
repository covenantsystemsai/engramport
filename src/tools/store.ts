/**
 * Tool calls served by the Postgres store (ENGRAMPORT_STORE=postgres).
 *
 * remember, recall, upload, fetch_memory, delete_memory (which retracts),
 * list_namespaces and inspect run against the memory schema, and so do the
 * graph tools link, unlink and get_entity. chat, groom,
 * dream and export_graph need the graph and synthesis work that comes in later
 * PRs, so they answer with a clear error instead of reaching the old backend.
 */

import type pg from "pg";

import { config } from "../config.js";
import { backendKey } from "../caller.js";
import { Embedder, openAIEmbedder, supabaseEmbedder } from "../embeddings.js";
import { decodePepper } from "../keys.js";
import type { LinkInput } from "../store/graph.js";
import { NOT_ON_POSTGRES } from "./store-definitions.js";
import { ClaimType, createPool, MEMORY_KINDS, MemoryKind, PostgresStore, RECALL_MODES, RecallMode, StoreError } from "../store/postgres.js";

type ToolResult = { content: Array<{ type: "text"; text: string }>; isError?: boolean };


let shared: PostgresStore | undefined;
let sharedPg: pg.Pool | undefined;

/** The process-wide pool, as engramport_app. The store and OAuth share it. */
export function sharedPool(): pg.Pool {
  sharedPg ??= createPool(config.databaseUrl, config.databaseCaFile || undefined);
  return sharedPg;
}

/**
 * The providers this server has. Each namespace's text goes only to the one
 * for its own model, so adding an OpenAI key never sends a gte-small
 * namespace's text to OpenAI.
 */
function configuredEmbedders(): Embedder[] {
  return [
    ...(config.embedUrl && config.embedSecret ? [supabaseEmbedder(config.embedUrl, config.embedSecret)] : []),
    ...(config.openaiApiKey ? [openAIEmbedder(config.openaiApiKey)] : []),
  ];
}

/** The process-wide store, built from config on first use. */
export function sharedStore(): PostgresStore {
  if (!shared) {
    const pepper = decodePepper(config.keyPepper);
    if (!pepper) throw new Error("ENGRAMPORT_KEY_PEPPER is missing or too short");
    shared = new PostgresStore(sharedPool(), {
      pepper,
      embedders: configuredEmbedders(),
      transport: config.mode === "stdio" ? "stdio" : "streamable_http",
    });
  }
  return shared;
}

/** The old tools call a plain fact "memory"; the schema calls it "fact". */
function toKind(value: unknown): MemoryKind | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (value === "memory") return "fact";
  if (MEMORY_KINDS.includes(value as MemoryKind)) return value as MemoryKind;
  throw new StoreError("invalid", `unknown memory type: ${String(value)}`);
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v !== "" ? v : undefined);
const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : undefined);

function ok(result: unknown): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
}

function fail(error: string, code: string): ToolResult {
  return { content: [{ type: "text", text: JSON.stringify({ error, code }) }], isError: true };
}

export async function executeStoreTool(
  name: string,
  args: Record<string, unknown>,
  store?: PostgresStore,
  callerKey?: string,
): Promise<ToolResult> {
  // Only a namespace the caller actually sent is checked against the key;
  // the configured default belongs to the old backend.
  const namespace = str(args.namespace);
  try {
    let key: string;
    try {
      key = callerKey ?? backendKey(config.apiKey);
    } catch {
      throw new StoreError("unauthorized", "no EngramPort key for this request");
    }
    store ??= sharedStore();
    switch (name) {
      case "remember": {
        const metadata = args.metadata && typeof args.metadata === "object" && !Array.isArray(args.metadata)
          ? (args.metadata as Record<string, unknown>)
          : undefined;
        // Approval and verification are recorded as their own events, never by the writer.
        for (const field of ["approval_state", "verification_state", "approved", "verified"]) {
          if (args[field] !== undefined) {
            throw new StoreError("invalid", `${field} can't be set by a write; every new memory starts unapproved and unverified`);
          }
        }
        return ok(await store.remember(key, {
          content: args.content as string,
          kind: toKind(args.type),
          claimType: args.claim_type as ClaimType | undefined,
          expectedVersion: str(args.expected_version),
          metadata,
          dedupKey: str(args.dedup_key),
          sourceUrl: str(args.source_url),
          namespace,
        }));
      }
      case "recall": {
        const mode = str(args.mode);
        if (mode !== undefined && !RECALL_MODES.includes(mode as RecallMode)) {
          throw new StoreError("invalid", `mode must be one of ${RECALL_MODES.join(", ")}`);
        }
        if (str(args.source_filter)) throw new StoreError("invalid", "source_filter is not supported by this store yet");
        return ok(await store.recall(key, {
          query: args.query as string,
          topK: num(args.top_k),
          mode: mode as RecallMode | undefined,
          kind: toKind(args.node_type_filter),
          minScore: num(args.min_score),
          dateFrom: str(args.date_from),
          dateTo: str(args.date_to),
          namespace,
        }));
      }
      case "upload":
        return ok(await store.upload(key, {
          content: args.content as string,
          filename: args.filename as string,
          namespace,
        }));
      case "fetch_memory":
        return ok(await store.fetch(key, args.memory_id as string, namespace));
      case "delete_memory":
        return ok(await store.retract(key, args.memory_id as string, namespace));
      case "list_namespaces":
        return ok(await store.listNamespaces(key));
      case "inspect":
        return ok(await store.inspect(key, namespace));
      case "link": {
        const arr = (v: unknown, what: string): unknown[] | undefined => {
          if (v === undefined || v === null) return undefined;
          if (!Array.isArray(v)) throw new StoreError("invalid", `${what} must be an array`);
          return v;
        };
        return ok(await store.link(key, {
          entities: arr(args.entities, "entities") as LinkInput["entities"],
          relations: arr(args.relations, "relations") as LinkInput["relations"],
          memoryId: str(args.memory_id),
          memoryLinks: arr(args.memory_links, "memory_links") as LinkInput["memoryLinks"],
          namespace,
        }));
      }
      case "unlink": {
        const given = (["relation_id", "memory_link_id", "entity_id"] as const).filter((k) => str(args[k]));
        if (given.length !== 1) throw new StoreError("invalid", "give exactly one of relation_id, memory_link_id or entity_id");
        const id = str(args[given[0]])!;
        const target = given[0] === "relation_id" ? { relationId: id }
          : given[0] === "memory_link_id" ? { memoryLinkId: id } : { entityId: id };
        return ok(await store.unlink(key, target, namespace));
      }
      case "get_entity":
        if (!str(args.entity_id) && !str(args.name)) throw new StoreError("invalid", "give entity_id or name");
        return ok(await store.getEntity(key, {
          id: str(args.entity_id),
          name: str(args.name),
          type: str(args.type),
          memoryLimit: num(args.memory_limit),
          namespace,
        }));
      default:
        if (NOT_ON_POSTGRES.has(name)) return fail(`${name} is not available on the Postgres store yet`, "not_available");
        return fail(`Unknown tool: ${name}`, "invalid");
    }
  } catch (err) {
    if (err instanceof StoreError) return fail(err.message, err.code);
    // Database errors can carry row values; log only the class, return nothing specific.
    const code = (err as { code?: string })?.code;
    console.error(`[engramport] store error in ${name}${code ? ` (${code})` : ""}`);
    if (code === "42501") return fail("not allowed for this key", "forbidden");
    return fail("store error", "internal");
  }
}
