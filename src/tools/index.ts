/**
 * EngramPort — MCP Tool Definitions
 *
 * 12 tools that give any bot a complete brain:
 *   remember        — Store a memory
 *   recall          — Search memories by meaning
 *   chat            — Talk to the brain (RAG)
 *   upload          — Ingest a document
 *   groom           — Auto-discover connections
 *   dream           — Synthesize new insights
 *   inspect         — Check brain stats
 *   fetch_memory    — Read one memory by ID
 *   delete_memory   — Remove a memory by ID
 *   list_namespaces — List accessible namespaces
 *   export_graph    — Export the knowledge graph (nodes + edges)
 */

import { config } from "../config.js";
import * as eidetic from "../eidetic.js";

// ── Tool Definitions ──────────────────────────────────────

export const toolDefinitions = [
  {
    name: "remember",
    description:
      "Persist a memory so it survives across sessions and tools. Call this PROACTIVELY whenever something is worth keeping — a decision made, a fact the user states, a conclusion you reach, a preference expressed. Don't wait to be asked: storing as you go is what lets any future session (yours or another agent's) continue without re-learning. Auto-linked into the knowledge graph. " +
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
        dedup_key: {
          type: "string",
          description:
            "Optional idempotency key. When set, the memory's identity becomes namespace+dedup_key instead of namespace+content. Two items with identical content no longer collide, and re-writing the same key updates the existing memory in place. Use it when you want a stable handle on a memory you may revise.",
        },
        source_url: {
          type: "string",
          description: "Optional source URL to record where this memory came from",
        },
        auto_link: {
          type: "boolean",
          description: "Auto-link this memory to its semantic neighbors in the graph (default: true)",
        },
      },
      required: ["content"],
    },
  },
  {
    name: "recall",
    description:
      "Search the brain BEFORE acting on anything that may depend on prior context. Call this FIRST when the user references past work, when continuity matters, or before answering from assumption — the brain may already hold the decision, preference, or fact you need. Returns the most relevant memories " +
      "with similarity scores, plus graph-connected neighbors (context a flat search misses). Recall first; don't start from a blank slate.",
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
        node_type_filter: {
          type: "string",
          enum: ["memory", "insight", "principle", "hypothesis"],
          description: "Restrict results to one node type",
        },
        min_score: {
          type: "number",
          description: "Drop matches below this similarity score (0-1)",
        },
        source_filter: {
          type: "string",
          description: "Restrict results to one source (e.g. gmail, slack, gdrive)",
        },
        date_from: {
          type: "string",
          description: "Only return memories created on or after this ISO date",
        },
        date_to: {
          type: "string",
          description: "Only return memories created on or before this ISO date",
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
  {
    name: "fetch_memory",
    description:
      "Read one memory by its ID. Returns the full content, node type, provenance hash, " +
      "metadata, and the IDs of its graph-linked neighbors. Use it when you already hold " +
      "a memory_id (from a recall result or an earlier write) and want the exact stored record.",
    inputSchema: {
      type: "object" as const,
      properties: {
        memory_id: {
          type: "string",
          description: "ID of the memory to fetch",
        },
        namespace: {
          type: "string",
          description: `Brain namespace (default: ${config.namespace})`,
        },
      },
      required: ["memory_id"],
    },
  },
  {
    name: "delete_memory",
    description:
      "Remove one memory by its ID. The vector and its graph edges go with it. " +
      "Use it to retract something stored in error or to prune stale records.",
    inputSchema: {
      type: "object" as const,
      properties: {
        memory_id: {
          type: "string",
          description: "ID of the memory to delete",
        },
        namespace: {
          type: "string",
          description: `Brain namespace (default: ${config.namespace})`,
        },
      },
      required: ["memory_id"],
    },
  },
  {
    name: "list_namespaces",
    description:
      "List every namespace this key can reach, each with its memory count. Use it to " +
      "discover which brains exist before you read from or write to one.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "export_graph",
    description:
      "Export the knowledge graph for a namespace: every node (memory, insight, principle) " +
      "and every typed edge between them. Use it to visualize the graph or back up its structure.",
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
          {
            dedupKey: args.dedup_key as string | undefined,
            sourceUrl: args.source_url as string | undefined,
            autoLink: args.auto_link as boolean | undefined,
          },
        );
        break;

      case "recall":
        result = await eidetic.recall(
          args.query as string,
          ns,
          (args.top_k as number) || 5,
          {
            nodeTypeFilter: args.node_type_filter as string | undefined,
            minScore: args.min_score as number | undefined,
            sourceFilter: args.source_filter as string | undefined,
            dateFrom: args.date_from as string | undefined,
            dateTo: args.date_to as string | undefined,
          },
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

      case "fetch_memory":
        result = await eidetic.fetchMemory(args.memory_id as string, ns);
        break;

      case "delete_memory":
        result = await eidetic.deleteMemory(args.memory_id as string, ns);
        break;

      case "list_namespaces":
        result = await eidetic.listNamespaces();
        break;

      case "export_graph":
        result = await eidetic.graph(ns);
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
