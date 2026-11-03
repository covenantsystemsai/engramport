# EngramPort

**Give any AI agent persistent memory.** MCP-native, bring-your-own-LLM (any model via OpenRouter), graph-RAG.

[engramport.com](https://engramport.com) · [Docs](https://engramport.com/docs) · [Pricing](https://engramport.com/#pricing) · [npm](https://www.npmjs.com/package/engramport)

EngramPort is the persistent-memory layer for AI agents. Your bot remembers across sessions, recalls by meaning, and synthesizes higher-order insights from the patterns in what it has seen. Built on the [Model Context Protocol](https://modelcontextprotocol.io), it plugs into Claude Desktop, Cursor, Cline, the OpenAI Agents SDK, or any MCP-aware client with three lines of config.

```bash
npm install -g engramport
```

```jsonc
// claude_desktop_config.json
{
  "mcpServers": {
    "engramport": {
      "command": "npx",
      "args": ["engramport"],
      "env": {
        "ENGRAMPORT_API_KEY": "ek_bot_...",
        "ENGRAMPORT_NAMESPACE": "my-brain",
        "LLM_PROVIDER": "anthropic",
        "LLM_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

Restart your client. Your agent now has memory.

## What you get

Twelve MCP tools, mapped 1:1 to a graph-RAG memory substrate:

| Tool | What it does |
|---|---|
| `remember` | Store a memory. Auto-links to similar memories already in your namespace. |
| `recall` | Semantic search. Returns top-k matches with similarity scores and graph-expanded context. |
| `chat` | Ask your brain a grounded question. Modes: `reflex` (fast), `deep_think` (multi-step plan + multi-recall + synthesis), `intense` (deepest pass, more queries, wider recall). |
| `upload` | Ingest a document. Auto-chunked into linked memories. |
| `groom` | Auto-discover typed edges between memories: `supports`, `contradicts`, `synthesizes`, and more. |
| `dream` | Cluster analysis. Brain reads connected memories and produces higher-order INSIGHT and PRINCIPLE nodes. |
| `inspect` | Brain vitals: memory count, edge count, Graph Quality Index. |
| `fetch_memory` | Read one memory by ID. Returns its content, type, content hash, metadata, and linked neighbors. |
| `delete_memory` | Remove one memory by ID. The vector and its graph edges go with it. |
| `list_namespaces` | List every namespace this key can reach, each with its memory count. |
| `export_graph` | Export a namespace's graph: every node and every typed edge between them. |

### remember parameters

| Param | Type | Default | What it does |
|---|---|---|---|
| `content` | string | required | The text to store. |
| `type` | string | `memory` | Node type: `memory`, `insight`, `principle`, `hypothesis`. |
| `namespace` | string | your default | Which brain to write to. |
| `metadata` | object | `{}` | Arbitrary key/value pairs to attach. |
| `dedup_key` | string | none | Idempotency key. When set, the memory's identity is `namespace + dedup_key` rather than `namespace + content`. Two items with identical content no longer collide, and re-writing the same key updates that memory in place. Use it when you want a stable handle on a record you may revise. |
| `source_url` | string | none | Records where the memory came from. |
| `auto_link` | boolean | `true` | Auto-link the new memory to its semantic neighbors in the graph. |

### recall parameters

| Param | Type | Default | What it does |
|---|---|---|---|
| `query` | string | required | What to search for, by meaning. |
| `top_k` | number | `5` | How many matches to return (1 to 20). |
| `namespace` | string | your default | Which brain to search. |
| `node_type_filter` | string | none | Restrict to one node type: `memory`, `insight`, or `principle`. |
| `min_score` | number | `0` | Drop matches below this similarity score (0 to 1). |
| `source_filter` | string | none | Restrict to one source, such as `gmail`, `slack`, or `gdrive`. |
| `date_from` | ISO string | none | Only memories created on or after this date. |
| `date_to` | ISO string | none | Only memories created on or before this date. |

### Graph and namespace tools

| Tool | Params | Returns |
|---|---|---|
| `fetch_memory` | `memory_id`, `namespace` | The full stored record for one memory. |
| `delete_memory` | `memory_id`, `namespace` | Confirmation that the memory and its edges are gone. |
| `list_namespaces` | none | Every reachable namespace with its memory count. |
| `export_graph` | `namespace` | Nodes and typed edges for the namespace. |

## Bring your own LLM

EngramPort does not resell LLM calls. You pay for vector storage, embeddings, and the MCP transport on a flat tier; the LLM bill goes to your provider directly. Three providers natively, plus virtually any model (DeepSeek, Mistral, Llama, Qwen, and more) through OpenRouter:

| Provider | Set `LLM_PROVIDER` to | Suggested fast / balanced / intense models |
|---|---|---|
| Anthropic | `anthropic` | `claude-haiku-4-5-20251001` / `claude-sonnet-4-6` / `claude-opus-4-7` |
| OpenAI | `openai` | `gpt-4.1-nano` / `gpt-4.1-mini` / `gpt-4.1` |
| Google | `google` | `gemini-2.0-flash` / `gemini-1.5-pro` / `gemini-1.5-pro` |
| OpenRouter | `openrouter` | any OpenRouter slug, e.g. `openai/gpt-4o-mini` / `openai/gpt-4o` / `anthropic/claude-3.5-sonnet` |

Defaults flip automatically based on your `LLM_API_KEY` prefix. Override any tier via env (`FAST_MODEL`, `BALANCED_MODEL`, `INTENSE_MODEL`) or in your dashboard at [engramport.com/dashboard](https://engramport.com/dashboard).

## Why graph, not just vectors

Most memory layers stop at vector similarity. EngramPort builds a typed graph on top: every memory you store is auto-linked to its semantic neighbors, and the `groom` and `dream` passes promote dense clusters into named insights and principles. Recall returns direct vector matches AND graph-expanded context. The result is responses grounded in the patterns across your memories, not just the nearest paragraph.

The substrate is a graph-RAG engine over managed vector and Postgres storage. EngramPort is the MCP wrapper that exposes the substrate to any agent.

## Quickstart

1. **Sign up** at [engramport.com/signup](https://engramport.com/signup). Magic-link email. Choose a namespace. Paste your LLM provider key.
2. **Get your config snippet.** EngramPort issues you an `ek_bot_...` API key and a copy-paste config block.
3. **Drop into your client.** Paste into `claude_desktop_config.json` (or the equivalent for Cursor, Cline, your custom agent). Restart.
4. **Use it.** Ask your agent to `remember`, `recall`, or `chat` with grounded context.

See [engramport.com/docs/quickstart](https://engramport.com/docs/quickstart) for a step-by-step walkthrough.

## Configuration

| Variable | Required | What it does |
|---|---|---|
| `ENGRAMPORT_API_URL` | yes | Your EngramPort API URL, from your config snippet. Must be `https` (plain `http` only for `localhost`). There is no default. |
| `ENGRAMPORT_API_KEY` | stdio mode | Your `ek_` key. In hosted (`http`) mode it's ignored: each caller sends its own key as `Authorization: Bearer <key>`. |
| `ENGRAMPORT_NAMESPACE` | no | Default namespace for tool calls that don't name one. |
| `ENGRAMPORT_MODE` | no | `stdio` or `http`. Picked automatically when unset. |
| `ENGRAMPORT_ALLOW_LOCAL_BACKEND` | no | `true` lets hosted mode talk to a backend on `localhost`, for local development only. |

### Postgres store (preview)

Set `ENGRAMPORT_STORE=postgres` and the server reads and writes the memory schema in `db/` directly instead of calling the backend API. It is off by default while it is being built out. Keys for this store look like `ep_live_...` and are bound to one namespace; a `namespace` argument, when sent, must be the key's own.

| Variable | Required | What it does |
|---|---|---|
| `ENGRAMPORT_STORE` | no | `eidetic` (default) or `postgres`. |
| `ENGRAMPORT_DATABASE_URL` | postgres | Connection URL for the `engramport_app` role. Admin roles are refused, since they skip row security. Leave `sslmode` out: TLS to a remote host is always verified. |
| `ENGRAMPORT_DATABASE_CA_FILE` | for Supabase | The database's CA certificate file, so TLS can be verified. |
| `ENGRAMPORT_KEY_PEPPER` | postgres | At least 32 random bytes, base64 or hex, used to hash keys. |
| `OPENAI_API_KEY` | no | Turns on embeddings, so recall can search by meaning. Without it, hybrid recall uses its keyword and graph retrievers only. |

Keep all of these in a secrets manager, never in a file in the repo. On this store `delete_memory` retracts: the memory stops coming back from recall but its text is kept for the record. `chat`, `groom`, `dream` and `export_graph` are not available on it yet. It also adds three knowledge-graph tools: `link` (assert entities, aliases, relations, which entities a memory mentions, and links between memories), `unlink` (retract one of them) and `get_entity` (an entity with its aliases, relations and the memories that mention it). They follow the same namespace rules as memories.

On this store `recall` takes a `mode`. The default, `hybrid`, runs three retrievers in one database call over everything the key can read: by meaning (the query's embedding), by words (any of the query's words may match), and by the graph (entities the query names, and memories up to two hops away across relations of confidence 0.5 or more). Their scores are blended, 40% meaning and 25% words, then recency, memory kind (decisions first) and provenance quality reorder results of similar relevance without ever lifting one that matches nothing. A tie goes to the nearest namespace, so a cell's own memory comes before its tower's and city's. Each result says its `level` and which retrievers found it (`retrieved_by`). `vector`, `keyword` (every word must match) and `graph` run one retriever alone. A small eval set (`test/fixtures/eval-basic.json`) checks that hybrid ranks an answer first for every question and beats each retriever alone; `src/store/eval.ts` runs the same check on a real namespace's questions.

An extraction job (in progress) will read each new memory with a model and add the entities and relations it finds to the graph, marked as extracted so they are never mistaken for an agent's own claims. Each memory is read once per extractor version, a near spelling of an entity the namespace can read is reused rather than duplicated, a quote is kept only if it is in the memory word for word, and a failure is stored as a short class such as `timeout`, never as the provider's message. The job runs only as a server-side job; no agent tool can start it or write extracted rows. Which model it uses is not settled yet, so it does not run anywhere today.

#### Managing namespaces and keys

`engramport admin` creates namespaces and actors and mints, rotates and revokes keys for this store. It also shows the audit trail. It runs as the `engramport_admin` database role, which can do exactly that and nothing more: it cannot read memories, embeddings, graph rows or stored key hashes, it sees provenance metadata but never content, and it cannot delete anything.

```
engramport admin namespace create acme                # a city
engramport admin namespace create acme/ops            # a tower
engramport admin namespace create acme/ops/pilot      # a cell
engramport admin namespace create mycompany --company # your own company's city, once
engramport admin namespace create mycompany/knowledge
engramport admin namespace create mycompany/knowledge/hq
engramport admin actor create claude --kind agent --display "Claude"
engramport admin key mint --namespace acme/ops/pilot --actor claude --expires-in 90d
engramport admin key list --namespace acme/ops/pilot
engramport admin key rotate ep_live_XXXXXXXXXXXX --grace 24h
engramport admin key revoke ep_live_XXXXXXXXXXXX
engramport admin audit --namespace acme --since 7d   # who wrote what, where and when
```

A minted key is printed once, alone on stdout, so you can pipe it straight into your secrets manager; only its HMAC is stored. Rotation keeps the old key working for the grace period (`--grace 0` revokes it at once), and revoking or disabling an actor takes effect on the key's next request. Revoke and rotate take the key's prefix, never the whole key, so keys stay out of shell history. City and tower names must not name a client.

Your own company gets one city of its own, made with `--company`. Its towers and cells are company namespaces too, and the database refuses to put a client namespace under it or a company namespace under a client, so company knowledge and client data never share a city and neither can read the other. Mint its keys like any other.

`audit` lists, newest first, every write (the agent, its key, the tool, the transport and client, the namespace and the time) and every key minted or revoked. It never shows memory text, its hash, fields an agent claims about itself, or source references: the admin role cannot read them. `--namespace` includes everything under that path; `--actor`, `--since`, `--limit` (up to 1000) and `--writes-only` narrow it.

| Variable | What it does |
|---|---|
| `ENGRAMPORT_ADMIN_DATABASE_URL` | A login role that has been granted `SET` on `engramport_admin`. The tool switches to that role for every statement. |
| `ENGRAMPORT_KEY_PEPPER` | The same pepper the server uses. Needed to mint and rotate. |
| `ENGRAMPORT_DATABASE_CA_FILE` | As above. |

Run `npx engramport doctor` to check your setup. It prints the settings it resolved (only a short prefix of your key) and whether the API answers.

## How it fits with other agent frameworks

| Client | Config path | Notes |
|---|---|---|
| Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json` (Windows) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) | Restart the app fully after editing. |
| Cursor | `~/.cursor/mcp.json` or workspace `.cursor/mcp.json` | Cursor will surface tools in the chat sidebar. |
| Cline | VS Code settings: `cline.mcpServers` | Same JSON shape. |
| OpenAI Agents SDK | Pass to the agent's MCP server list | See [docs/openai-sdk](https://engramport.com/docs/openai-sdk). |
| Any MCP-aware client | stdio command + env | EngramPort speaks vanilla MCP stdio. |

## What we provide vs. what you provide

| Layer | Provider |
|---|---|
| Vector storage (Pinecone) | EngramPort |
| Graph database (Supabase Postgres) | EngramPort |
| Embedding generation (OpenAI `text-embedding-3-small`) | EngramPort |
| MCP transport (stdio + HTTP) | EngramPort |
| Memory substrate | EngramPort |
| **LLM completions** (chat, dream synthesis) | **You** (your provider API key) |

Your LLM bill goes to your provider directly. Our infrastructure cost is covered by your tier subscription.

## Pricing

| Tier | Free | Hobbyist | Pro | Team | Enterprise |
|---|---|---|---|---|---|
| **Price** | $0 | $9/mo | $29/mo | $99/mo | Contact us |
| Namespaces | 1 | 10 | unlimited | unlimited | custom |
| Memories stored | 1,000 | 100,000 | 1,000,000 | 1M per user | custom |
| Daily `groom`/`dream` | 1/day | 4/day | 24/day | 24/day | custom |
| `intense` mode | gated | yes | yes | yes | yes |
| Audit log | none | none | basic | full | full |
| Workspace SSO | no | no | no | yes | yes |
| Sentinel OS bundled | no | no | no | no | yes |

LLM cost is yours regardless of tier.

Sign up free at [engramport.com](https://engramport.com).

## Privacy and data integrity

- Your memories are stored in your namespace on Pinecone and Supabase. We do not train models on your memories.
- Your LLM API key is encrypted at rest using AES-256-GCM. It is decrypted only at request time to forward your call to your provider.
- Every memory carries a SHA-256 content hash, so any later alteration of a
  stored memory is detectable. This is **tamper-evidence**, not cryptographic
  provenance: a hash produced and served by the same service cannot prove
  origin to a third party. Digital signatures over published checkpoints are on
  the roadmap and are not shipped today.
- Full data export is available from your dashboard at any time.

See [engramport.com/docs/privacy](https://engramport.com/docs/privacy) and [engramport.com/terms](https://engramport.com/terms).

## Project

EngramPort is a product of **Covenant Systems AI LLC**, a North Carolina LLC. Source for this MCP wrapper is MIT-licensed. The underlying engine is proprietary.ai](mailto:hello@covenantsystems.ai) for enterprise self-host inquiries.

## Contributing

Issues and pull requests welcome at [github.com/covenantsystemsai/engramport](https://github.com/covenantsystemsai/engramport). The MCP wrapper is intentionally thin; substrate-level changes are made privately, but improvements to the wrapper, docs, and client-integration patterns are open contributions.

---

EngramPort, a Covenant Systems product · © 2026 Covenant Systems AI LLC · [engramport.com](https://engramport.com)
