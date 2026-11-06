/**
 * EngramPort — Eidetic V2 API Client
 *
 * Thin wrapper over the V2 REST API. No direct DB access.
 * All brain operations go through the Eidetic backend.
 */

import { config } from "./config.js";
import { legacyFetch } from "./legacy-auth.js";
import { backendKey } from "./caller.js";
import { chunkText } from "./chunk.js";

async function request(method: string, path: string, body?: unknown): Promise<unknown> {
  const url = `${config.apiUrl}${path}`;
  const headers: Record<string, string> = {
    "X-API-Key": backendKey(config.apiKey),
    "Content-Type": "application/json",
  };

  const opts: RequestInit = { method, headers };
  if (body !== undefined) {
    opts.body = JSON.stringify(body);
  }

  const res = await legacyFetch(config, url, opts);
  if (!res.ok) {
    // Backend errors may contain request content or credentials.
    throw new Error(`Eidetic API ${res.status}: request refused or failed`);
  }
  return res.json();
}

// ── Memory Operations ─────────────────────────────────────

export interface RememberOptions {
  dedupKey?: string;
  sourceUrl?: string;
  autoLink?: boolean;
}

export async function remember(
  content: string,
  namespace: string,
  nodeType: string = "memory",
  metadata: Record<string, unknown> = {},
  options: RememberOptions = {},
): Promise<unknown> {
  return request("POST", "/v2/memory", {
    content,
    namespace,
    node_type: nodeType,
    metadata,
    auto_link: options.autoLink ?? true,
    dedup_key: options.dedupKey ?? null,
    source_url: options.sourceUrl ?? null,
  });
}

export interface RecallOptions {
  nodeTypeFilter?: string;
  minScore?: number;
  sourceFilter?: string;
  dateFrom?: string;
  dateTo?: string;
}

export async function recall(
  query: string,
  namespace: string,
  topK: number = 5,
  options: RecallOptions = {},
): Promise<unknown> {
  return request("POST", "/v2/recall", {
    query,
    namespace,
    top_k: topK,
    include_context: true,
    node_type_filter: options.nodeTypeFilter ?? null,
    min_score: options.minScore ?? 0,
    source_filter: options.sourceFilter ?? null,
    date_from: options.dateFrom ?? null,
    date_to: options.dateTo ?? null,
  });
}

export async function chat(
  message: string,
  namespace: string,
  mode: string = "reflex",
  systemPrompt?: string,
): Promise<unknown> {
  return request("POST", "/v2/chat", {
    message,
    namespace,
    mode,
    system_prompt: systemPrompt || null,
    top_k: mode === "deep_think" ? 10 : 5,
  });
}

export async function upload(
  content: string,
  filename: string,
  namespace: string,
): Promise<unknown> {
  // For MCP, we ingest text content as bulk memories (chunked by the caller)
  // Real file upload goes through the frontend/REST API directly
  const chunks = chunkText(content, 2000);
  return request("POST", "/v2/memory/bulk", {
    memories: chunks.map((chunk, i) => ({
      content: chunk,
      namespace,
      node_type: "memory",
      metadata: { source_file: filename, chunk_index: i },
      auto_link: true,
    })),
  });
}

export async function groom(
  namespace: string,
  batchSize: number = 20,
): Promise<unknown> {
  return request("POST", "/v2/brain/groom", {
    namespace,
    batch_size: batchSize,
  });
}

export async function dream(namespace: string): Promise<unknown> {
  return request("POST", `/v2/brain/dream?namespace=${encodeURIComponent(namespace)}`);
}

export async function inspect(namespace: string): Promise<unknown> {
  return request("GET", `/v2/brain/stats?namespace=${encodeURIComponent(namespace)}`);
}

export async function graph(namespace: string): Promise<unknown> {
  return request("GET", `/v2/brain/graph?namespace=${encodeURIComponent(namespace)}`);
}

export async function fetchMemory(memoryId: string, namespace: string): Promise<unknown> {
  return request("GET", `/v2/memory/${encodeURIComponent(memoryId)}?namespace=${encodeURIComponent(namespace)}`);
}

export async function deleteMemory(memoryId: string, namespace: string): Promise<unknown> {
  return request("DELETE", `/v2/memory/${encodeURIComponent(memoryId)}?namespace=${encodeURIComponent(namespace)}`);
}

export async function listNamespaces(): Promise<unknown> {
  return request("GET", "/v2/namespaces");
}

export async function exportBrain(namespace: string): Promise<unknown> {
  return request("GET", `/v2/memory/export/${encodeURIComponent(namespace)}`);
}
