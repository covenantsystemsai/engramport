/**
 * EngramPort — Eidetic V2 API Client
 *
 * Thin wrapper over the V2 REST API. No direct DB access.
 * All brain operations go through the Eidetic backend.
 */

import { config } from "./config.js";
import { getIdToken } from "./auth.js";

async function request(method: string, path: string, body?: unknown): Promise<unknown> {
  const url = `${config.apiUrl}${path}`;
  const headers: Record<string, string> = {
    "X-API-Key": config.apiKey,
    "Content-Type": "application/json",
  };

  // Cloud Run gate: add OIDC Bearer when available. Empty token is a fast,
  // visible 403 from Cloud Run rather than a silent swallow.
  const idToken = await getIdToken(config.apiUrl);
  if (idToken) {
    headers["X-Serverless-Authorization"] = `Bearer ${idToken}`;
  }

  const opts: RequestInit = { method, headers };
  if (body !== undefined) {
    opts.body = JSON.stringify(body);
  }

  const res = await fetch(url, opts);
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`Eidetic API ${res.status}: ${text}`);
  }
  return res.json();
}

// ── Memory Operations ─────────────────────────────────────

export async function remember(
  content: string,
  namespace: string,
  nodeType: string = "memory",
  metadata: Record<string, unknown> = {},
): Promise<unknown> {
  return request("POST", "/v2/memory", {
    content,
    namespace,
    node_type: nodeType,
    metadata,
    auto_link: true,
  });
}

export async function recall(
  query: string,
  namespace: string,
  topK: number = 5,
): Promise<unknown> {
  return request("POST", "/v2/recall", {
    query,
    namespace,
    top_k: topK,
    include_context: true,
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

export async function deleteMemory(memoryId: string, namespace: string): Promise<unknown> {
  return request("DELETE", `/v2/memory/${memoryId}?namespace=${encodeURIComponent(namespace)}`);
}

export async function exportBrain(namespace: string): Promise<unknown> {
  return request("GET", `/v2/memory/export/${encodeURIComponent(namespace)}`);
}

// ── Helpers ───────────────────────────────────────────────

function chunkText(text: string, maxChars: number): string[] {
  const chunks: string[] = [];
  const paragraphs = text.split(/\n\n+/);
  let current = "";

  for (const para of paragraphs) {
    if (current.length + para.length + 2 > maxChars && current.length > 0) {
      chunks.push(current.trim());
      current = "";
    }
    current += (current ? "\n\n" : "") + para;
  }
  if (current.trim()) chunks.push(current.trim());
  return chunks.length > 0 ? chunks : [text];
}
