/**
 * EngramPort — MCP Tool Definitions
 *
 * 7 tools that give any bot a complete brain:
 *   remember  — Store a memory
 *   recall    — Search memories by meaning
 *   chat      — Talk to the brain (RAG)
 *   upload    — Ingest a document
 *   groom     — Auto-discover connections
 *   dream     — Synthesize new insights
 *   inspect   — Check brain stats
 */

import { config } from "../config.js";
import * as eidetic from "../eidetic.js";

// ── Tool Definitions ──────────────────────────────────────

export const toolDefinitions = [
  {
    name: "remember",
    description:
      "Store a memory in the brain. Memories are automatically linked to similar existing memories. " +
      "Types: memory (facts/data), insight (patterns/observations), principle (core truths), hypothesis (unverified ideas).",
    inputSchema: {
      type: "object" as const,
      properties: {
        content: {
          type: "string",
          description: "The content to remember",
        },
        type: {
          type: "string",
          enum: ["memory", "insight", "principle", "hypothesis"],
          description: "Type of memory node (default: memory)",
        },
        namespace: {
          type: "string",
          description: `Brain namespace (default: ${config.namespace})`,
        },
        metadata: {
          type: "object",
          description: "Optional metadata to attach",
        },
      },
      required: ["content"],
    },
  },
  {
    name: "recall",
    description:
      "Search the brain for memories similar to a query. Returns the most relevant memories " +
      "with similarity scores, plus graph-connected context.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "What to search for (semantic search)",
        },
        top_k: {
          type: "number",
          description: "Number of results (1-20, default: 5)",
        },
        namespace: {
          type: "string",
          description: `Brain namespace (default: ${config.namespace})`,
        },
      },
      required: ["query"],
    },
  },
  {
    name: "chat",
    description:
      "Ask the brain a question. The brain retrieves relevant memories, then synthesizes " +
      "an answer grounded in stored knowledge. Three modes (cheapest to deepest): " +
      "reflex (fast, single-pass, Haiku-tier), deep_think (multi-step plan + multi-recall + " +
      "Sonnet-tier synthesis), intense (4-6 plan queries, wider recall, Opus-tier " +
      "synthesis — use for hard reasoning over the full graph).",
    inputSchema: {
      type: "object" as const,
      properties: {
        message: {
          type: "string",
          description: "Question or message to the brain",
        },
        mode: {
          type: "string",
          enum: ["reflex", "deep_think", "intense"],
          description: "Thinking mode (default: reflex). Use intense for the deepest GraphRAG pass.",
        },
        system_prompt: {
          type: "string",
          description: "Optional system prompt override",
        },
        namespace: {
          type: "string",
          description: `Brain namespace (default: ${config.namespace})`,
        },
      },
      required: ["message"],
    },
  },
  {
    name: "upload",
    description:
      "Ingest a document into the brain. Provide the text content and filename. " +
      "The content is automatically chunked and each chunk becomes a linked memory.",
    inputSchema: {
      type: "object" as const,
      properties: {
        content: {
          type: "string",
          description: "Full text content of the document",
        },
        filename: {
          type: "string",
          description: "Name of the source file",
        },
        namespace: {
          type: "string",
          description: `Brain namespace (default: ${config.namespace})`,
        },
      },
      required: ["content", "filename"],
    },
  },
  {
    name: "groom",
    description:
      "Trigger grooming — the brain scans recent memories and auto-discovers connections " +
      "between related concepts. Creates typed edges (supports, contradicts, synthesizes, etc.).",
    inputSchema: {
      type: "object" as const,
      properties: {
        batch_size: {
          type: "number",
          description: "Number of memories to process (1-100, default: 20)",
        },
        namespace: {
          type: "string",
          description: `Brain namespace (default: ${config.namespace})`,
        },
      },
      required: [],
    },
  },
  {
    name: "dream",
    description:
      "Trigger dreaming — the brain analyzes clusters of connected memories and synthesizes " +
      "new insight nodes. These are higher-order patterns the brain discovers autonomously.",
    inputSchema: {
      type: "object" as const,
      properties: {
        namespace: {
          type: "string",
          description: `Brain namespace (default: ${config.namespace})`,
        },
      },
      required: [],
    },
  },
  {
    name: "inspect",
    description:
      "Check the brain's vital stats: total memories, insights, principles, edge count, " +
      "and Graph Quality Index (GQI). Use this to understand the brain's current state.",
    inputSchema: {
      type: "object" as const,
      properties: {
        namespace: {
          type: "string",
          description: `Brain namespace (default: ${config.namespace})`,
        },
      },
      required: [],
    },
  },
];

// ── Tool Executor ─────────────────────────────────────────

export async function executeTool(
  name: string,
  args: Record<string, unknown>,
): Promise<{ content: Array<{ type: "text"; text: string }>; isError?: boolean }> {
  const ns = (args.namespace as string) || config.namespace;

  try {
    let result: unknown;

    switch (name) {
      case "remember":
        result = await eidetic.remember(
          args.content as string,
          ns,
          (args.type as string) || "memory",
          (args.metadata as Record<string, unknown>) || {},
        );
        break;

      case "recall":
        result = await eidetic.recall(
          args.query as string,
          ns,
          (args.top_k as number) || 5,
        );
        break;

      case "chat":
        result = await eidetic.chat(
          args.message as string,
          ns,
          (args.mode as string) || "reflex",
          args.system_prompt as string | undefined,
        );
        break;

      case "upload":
        result = await eidetic.upload(
          args.content as string,
          args.filename as string,
          ns,
        );
        break;

      case "groom":
        result = await eidetic.groom(ns, (args.batch_size as number) || 20);
        break;

      case "dream":
        result = await eidetic.dream(ns);
        break;

      case "inspect":
        result = await eidetic.inspect(ns);
        break;

      default:
        return {
          content: [{ type: "text", text: JSON.stringify({ error: `Unknown tool: ${name}` }) }],
          isError: true,
        };
    }

    return {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text", text: JSON.stringify({ error: msg }) }],
      isError: true,
    };
  }
}
