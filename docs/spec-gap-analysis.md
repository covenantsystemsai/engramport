# Phase 0 audit: the master spec v1.0 against what's built

This is the Phase 0 deliverable from the master engineering specification v1.0 (§20, §23). It records what the repository does today, sorts every spec section into one of the six classes the spec asks for, and proposes the smallest set of changes that would get the first multi-agent pilot to the §22 acceptance criteria.

It describes the code on `main` at commit `aeed605` (PR 27). Nothing has been deployed. The hosted Supabase project has only `0001_memory_core` applied. Every claim below comes from reading the code or from the test runs listed under "What the tests show"; where a finding rests on reading code alone, it says so.

Namespaces are written as `<city>/<tower>/<cell>`. No client, product or project is named here.

## Summary

The foundation the spec asks to preserve is real and well tested: database-enforced isolation, city / tower / cell namespaces, server-attested provenance, a typed knowledge graph, hybrid retrieval in one SQL function, content-blind administration, and an OAuth 2.1 server with immediate revocation. Those parts pass 57 unit tests, 72 database-backed store tests and 325 SQL assertions on a local Postgres 16.

The gaps are concentrated in the spec's "shared memory is not shared truth" layer:

1. **No evidence or epistemic model.** A memory has a `kind` and a `status` (active, superseded, retracted). There is no approval, verification or review state, no evidence reference beyond one `source_ref` string, and `hypothesis` is a kind rather than a separate dimension (§6, §8).
2. **Supersession is last-write-wins by key.** Writing the same `dedup_key` again supersedes the active memory with no expected version, which §10 forbids for decisions and verified facts.
3. **No temporal model beyond `created_at`.** No `observed_at`, `valid_from`, `valid_until` or `as_of` recall (§6, §4.2).
4. **Retraction is not deletion.** Retracted text, its embedding and its graph rows stay in the database, and from reading the code a relation's evidence quote from a retracted memory can still come back from `get_entity` (§13). There is no export or tenant termination.
5. **Half the tool family is missing.** `history`, `feedback`, `prepare_handoff`, `find_conflicts`, `timeline`, `batch` and `propose_promotion` don't exist; `context`, `get`, `supersede` and `graph_neighbors` exist only in part (§4, §5).
6. **No observability.** No metrics and no correlation IDs; the `request_id` and `session_id` provenance columns exist but the server never fills them (§14).
7. **Nothing is live.** Live OAuth sign-in, any client's compatibility, deployment and the pilot are unverified (§11, §19, §22).

Two facts the spec doesn't mention change the security story and belong in front of a decision:

- **Memory text leaves Supabase for embedding.** The Postgres store sends every memory's text to OpenAI's embeddings API, and the planned extraction job would send it to a model provider too. Content-blind administration (§12) holds inside EngramPort, but those providers see content.
- **The default store is still the old backend.** `ENGRAMPORT_STORE` defaults to `eidetic`, which proxies to the old Cloud Run service. The Postgres store is opt-in.

## Current-state architecture

**Server.** One Node 20 / TypeScript process (`src/index.ts`) runs over stdio or HTTP. In HTTP mode (`src/http.ts`) it serves:

- MCP over Streamable HTTP at `POST /mcp`, stateless, JSON responses. `GET` and `DELETE /mcp` answer 405.
- A REST mirror: `POST /<tool>` for every tool.
- `GET /stream`, a keep-alive SSE stream.
- `GET /health`, open.
- With OAuth on, the authorization server routes (`src/oauth.ts`).

Every route except `/health` and OAuth's own needs a bearer key, checked against the store on each request. A per-key rate limit of 600 requests a minute is held in memory on each instance. JSON bodies are capped at 10 MB and memory text at 32,000 characters.

**Stores.** `src/tools/store.ts` serves the tools from Postgres when `ENGRAMPORT_STORE=postgres`; otherwise `src/eidetic.ts` forwards them to the old backend. `chat`, `groom`, `dream` and `export_graph` answer "not yet" on the Postgres store.

**Database.** Everything lives in schema `memory`, applied by `db/migrate.sh`, which records each file in `engramport_meta.schema_migrations`.

| Migration | What it adds |
|---|---|
| 0001 memory core | namespaces, actors, API keys, provenance, memories, embeddings (`halfvec(1536)`, HNSW), full-text index, row security forced on every table |
| 0002 admin role | `engramport_admin`: namespaces, actors and keys, never content |
| 0003 FK indexes | an index on every foreign key |
| 0004 graph | entities, aliases, relations, entity mentions, memory links; append-only, retract once |
| 0005 company namespace | a `purpose` on cities (client or company) |
| 0006 admin audit | the admin reads provenance metadata, never content, hashes, claims or source references |
| 0007 extraction | the extraction run ledger and the job-only `extracted` origin |
| 0008 search | `memory.search`: vector, keyword and graph retrieval fused in one invoker-rights function |
| 0009 OAuth | members, clients, grants, codes, rotating refresh tokens and revocation cascades |

**Identity and isolation.**

- A key belongs to one namespace and one actor, and is stored only as an HMAC-SHA256 under a server pepper.
- Each transaction sets the key's id and namespace with `set_config(..., true)`, and every policy goes through `memory.current_key()`, which rechecks revocation, expiry and the actor's state.
- The app role is `NOSUPERUSER NOBYPASSRLS`, and Supabase's `anon`, `authenticated` and `service_role` are revoked from the schema.
- A key reads its own namespace and the namespaces above it (cell, then tower, then city) and writes only its own. So a tower key never reads its cells, and nothing crosses cities.

**Provenance.**

- Every write first inserts a provenance row whose namespace, key and actor the database takes from the key, never from the caller.
- The row records the tool, transport and client, plus `claimed` for anything the agent asserts about itself and a content SHA-256.
- Content is never updated in place: the app may change only `status` and `supersedes_id`.

**Graph.**

- Entities carry a type, a name and aliases. Relations are typed predicates with a confidence, an evidence memory and a verbatim evidence span.
- Memory links are `supports`, `contradicts`, `derived_from`, `synthesizes` or `related`.
- Every row is `asserted` (by an agent) or `extracted` (by the job transport only).

**Extraction.**

- `src/store/extract.ts` validates a model's output: well-formed items only, quotes that appear word for word in the memory, no self-relations or duplicates.
- The run ledger caps retries per memory.
- The model adapter isn't built yet; that waits on the choice of extraction model.

**Retrieval.**

- `memory.search` fuses cosine similarity, full-text rank and a walk of up to two hops from entities named in the query.
- It then weights by recency, kind and provenance quality, drops hits under 5% relevance, and breaks ties toward the nearest namespace.
- It returns only active memories, with each retriever's rank.

**OAuth.**

- EngramPort is its own OAuth 2.1 authorization server, with RFC 8414 and RFC 9728 metadata, dynamic client registration, S256 PKCE, single-use codes and the `resource` parameter checked.
- People sign in with Google through Supabase Auth. Only a verified Google email that is an active member gets a choice of namespace.
- Access tokens are ordinary API keys that expire in an hour. Refresh tokens rotate, and reuse revokes the grant.
- Revoking a member or a grant revokes its keys in the same transaction, so access ends on the next request.

**Administration.** `engramport admin` (`src/admin.ts`) manages namespaces, actors, keys, OAuth members and connections, and reads the audit trail. Every admin transaction runs `SET LOCAL ROLE engramport_admin`.

**CI and supply chain.** GitHub Actions runs:

- build, unit tests and `npm audit --omit=dev --audit-level=high`
- a secret scan
- the SQL suites on Postgres with pgvector
- the store tests
- CodeQL

`publish.yml` publishes to npm on `v*` tags.

**Deployment.** A `Dockerfile` (node:20-slim, aimed at Cloud Run) is the only deploy file. There is no service config, no secrets wiring, no extraction worker deployment and no backup or restore procedure.

## What the tests show

Run on 2026-11-03 against `main` at `aeed605`:

| Suite | Result |
|---|---|
| `npm test` (unit, no database) | 57 of 57 pass |
| `npm run test:store` (store, admin, graph, extraction, eval, OAuth, OAuth over HTTP) | 72 of 72 pass |
| `db/test/run.sh` (row security, admin, graph, company, audit, extraction, search, OAuth, indexes) | 325 assertions pass, all 9 suites |

Two caveats:

- The local Postgres has no `halfvec`, so these local runs swap it for `vector`. CI runs the real type.
- The retrieval eval is one fixture of 34 memories and 6 questions, with a deterministic stand-in embedder. On it, hybrid scores recall@10 1.00 and MRR 1.00, vector alone 1.00 and 0.92, graph alone 0.17, and keyword alone 0.00. That shows hybrid working on a purpose-built set. It is not evidence of retrieval quality on real data, and the keyword score suggests the set was built around the other retrievers.

Nothing has been tested in a real MCP client, against a live Supabase Auth, or with a real embedding model.

## Classification of every spec section

Classes, as §23 defines them:

- **Verified**: implemented and verified by automated tests.
- **Undertested**: implemented but insufficiently tested.
- **Partial**: partially implemented.
- **Missing**: not implemented.
- **Conflicts**: conflicts with the current architecture.
- **Decision**: requires a product decision.

| § | Requirement | Class | Notes |
|---|---|---|---|
| 0 | Reconnaissance, no rebuild | Verified | This document |
| 1 | The ten questions every memory should answer | Partial | Answers what, who, when, where from and which namespace. Can't answer what evidence, is it current (as a validity window), approved or verified, or contradicted (as a state) |
| 2 | System boundaries | Partial | EngramPort stores no work-order state. No rule stops an agent writing "work order done" as a fact (see §15) |
| 3 | Cities isolated by default | Verified | `rls_test.sql`, `company_test.sql` |
| 3 | Credentials bound to namespace and scope | Verified | One namespace per key, `read`/`write` scopes |
| 3 | Cross-cell denied, tower doesn't imply its cells | Verified | Reads go up the tree only |
| 3 | Revocation stops prior credentials | Verified | Checked on every request; cascades tested |
| 3 | Isolation in the database, not the API | Verified | Forced row security, `NOBYPASSRLS` app role |
| 3 | Background jobs obey isolation | Verified | Extraction runs as the namespace's key, as `engramport_app` |
| 3 | Ranking and metadata don't reveal unauthorized memories | Undertested | Search runs with the caller's rights. No test aims at timing, counts or error-text leakage |
| 3 | Knowledge promotion workflow | Missing | Writes only go to the key's own namespace, so nothing can be promoted, automatically or otherwise. A tower memory today is written by a tower key |
| 4.1 | `memory.context` | Partial | `list_namespaces` and `inspect`. No principal, effective permissions, capabilities or versions in one answer |
| 4.2 | `memory.recall` | Partial | Hybrid, per-retriever ranks, kind and date filters, `min_score`. No `as_of`, include-superseded, evidence-state, entity or source filters, detail level or cursor; `source_filter` is refused on Postgres |
| 4.3 | `memory.get` | Partial | `fetch_memory` returns metadata and provenance and answers "not found" for ids outside reach. No version, relationship or history options |
| 4.4 | `memory.remember` | Partial | Server-attested attribution, idempotency by `dedup_key`, a `source_url`. No type validation, epistemic state, entities or relations in the same call, validity window or sensitivity. The tool's input schema still lists the old four types, so `decision` isn't advertised |
| 4.5 | `memory.link` | Partial | `link` asserts entities, aliases, relations and memory links, and both ends must be readable. The link kinds don't cover implements, validates, affects, depends on or motivates |
| 4.6 | `memory.supersede` | Conflicts | Only by reusing a `dedup_key`, with no expected version, so it is last-write-wins (§10) |
| 4.7 | `memory.history` | Missing | `supersedes` on one memory is the whole history |
| 4.8 | `memory.feedback` | Missing | |
| 5.1 | `prepare_handoff` | Missing | |
| 5.2 | `find_conflicts` | Missing | `contradicts` links exist; nothing finds or reports them |
| 5.3 | `timeline` | Missing | Recall's date range is the nearest thing |
| 5.4 | `graph_neighbors` | Partial | `get_entity` returns one entity, its direct relations and the memories that mention it. No depth, relation or time filters, or caps |
| 5.5 | `batch` | Missing | `upload` chunks one document; no general batch |
| 5.6 | `propose_promotion` | Missing | |
| 6 | Identity fields | Partial | No `project_id` (the cell is the project), no `schema_version` on the row |
| 6 | Content fields | Partial | Content and metadata only. No title, summary or keywords; entity references only through mentions |
| 6 | Provenance fields | Partial | Principal, actor, tool, client, transport, source kind and reference, content hash, created at. No originating model (correctly; it can't be authenticated), no source version or source content hash |
| 6 | Epistemic dimensions | Missing | |
| 6 | Temporal fields | Partial | `created_at` (recorded at) and `supersedes_id`. Nothing else |
| 6 | Security fields | Missing | Only a `retention` JSON on namespaces, which nothing reads |
| 6 | Retrieval fields | Partial | Embedding model per row; extractor id per run. No index status, so a memory whose embedding failed has no backfill |
| 6 | Concurrency fields | Conflicts | See 4.6. No version number or lock value |
| 7 | 16-type taxonomy | Partial | Eight kinds: fact, decision, note, summary, insight, principle, hypothesis, document_chunk. No per-type validation |
| 8 | Seven evidence states | Missing | Only "superseded" exists, as a status |
| 8 | No self-verification | Partial | `claimed` keeps agent assertions apart from server facts, and `extracted` can only come from the job. But an agent can write "verified" into metadata, and nothing marks it as unverified |
| 9 | Three retrievers, configurable fusion | Verified | `search_test.sql`, `eval.pg.test.ts`. Weights live in SQL, not config |
| 9 | Temporal, supersession and evidence-aware ranking | Partial | Recency and supersession filtering, yes; validity windows and evidence, no |
| 9 | Entity disambiguation, duplicate consolidation | Partial | Type plus normalized name, fuzzy candidates. No merge |
| 9 | Query types benchmarked | Missing | Six questions, no labels by query type |
| 9 | Extraction pipeline rules | Undertested | Tenant scoped, idempotent, retried, verbatim-quote checked, origin marked, all tested. No model adapter, so never run end to end, and no reprocessing on a new extractor version |
| 9 | Eval metrics and baselines | Partial | Recall@K and MRR across hybrid, vector, keyword and graph. No nDCG, citation accuracy, temporal correctness, leakage rate, latency, cost or tokens; no held-out set |
| 10 | Cross-agent collaboration | Partial | Several actors can share a cell, with durable ids and server attribution. No verify or challenge step, no expected-version writes |
| 11 | ChatGPT connector | Undertested | OAuth metadata, DCR, PKCE, refresh and revocation exist and pass local HTTP tests. Never tried in ChatGPT or claude.ai. Tool naming needs a decision (below) |
| 12 | Database security | Verified | Row security, least-privilege roles, `SECURITY DEFINER` functions tested, vector and full-text isolation tested, graph walks tested |
| 12 | Token security | Verified | Short-lived keys, rotating refresh, reuse detection, cascading revocation. No pepper rotation |
| 12 | MCP threat model | Partial | Recall and fetch carry an "untrusted data" note; extraction treats text as data. No adversarial test suite |
| 12 | Content-blind administration | Undertested | The admin role is tested blind. The limits beyond it aren't documented (see Security risks) |
| 12 | Rate limits, quotas, size limits | Partial | Per-instance rate limit and size caps. No quotas, abuse detection or shared limiter across instances |
| 12 | Secure logging, redaction | Partial | Logs avoid content by convention. No redaction layer, no structured logs |
| 12 | Retention, deletion, backup and restore | Missing | |
| 12 | Dependency scanning | Verified | `npm audit` and CodeQL in CI |
| 13 | Lifecycle operations | Partial | Create, index, retrieve, supersede and retract. No review, archive, delete or export |
| 13 | Deletion across derived indexes | Missing | Retraction keeps text, embedding and graph rows |
| 13 | Tenant termination and export | Missing | |
| 14 | Metrics | Missing | |
| 14 | Correlation IDs | Missing | Columns exist, never filled |
| 15 | AN2X relationship chain | Missing | Needs the type taxonomy and the new link kinds |
| 15 | Completion claims need authoritative evidence | Missing | Part of the evidence model |
| 16 | Public self-serve tier | Missing | By plan: after the pilot |
| 17 | Supabase install | Partial | Versioned migrations, extensions noted, row security, indexes and roles in SQL, an OAuth setup guide, `doctor`. No env template, deploy config, worker config, backup or rollback guide, or post-install security check |
| 18 | Functional tests | Partial | Create, recall, exact lookup, supersession by key, linking. No temporal, handoff, feedback or conflict tests |
| 18 | Cross-model tests | Missing | No client has connected |
| 18 | Isolation tests | Verified | Cell, tower, city, revoked, expired, worker, graph and vector covered. Metadata and error-text leakage aren't specifically covered, and promotion doesn't exist |
| 18 | Reliability tests | Partial | Concurrent dedup writes and extraction races tested. No retry storms, network faults, restarts or oversized-payload tests |
| 18 | Trust tests | Missing | |
| 19 | First pilot | Decision | Which cell goes first is open (below) |
| 20 | Phases | Partial | Phase 0 is this document. Phase 1 waits on deploy and a live sign-in |
| 21 | Documentation set | Partial | `README.md`, `db/README.md`, `docs/oauth-setup.md`, this file |
| 22 | Acceptance criteria | Partial | See "Effect on the pilot" |

## Where the spec and the current build differ

**Tool names.**

- The spec's dotted names (`memory.recall`) don't match today's (`recall`, `fetch_memory`).
- The spec itself says to keep working names and add aliases.
- Dots may also be a problem: OpenAI's function-calling interface has required names to match `^[a-zA-Z0-9_-]{1,64}$`, and how ChatGPT maps MCP tool names hasn't been checked.
- Proposal: keep every current name working, and add the new tools with underscores (`memory_history`). Treat the dotted form as the spec's label, not the wire name, until each target client is tried.

| Spec | Today |
|---|---|
| `memory.context` | `list_namespaces` + `inspect` |
| `memory.recall` | `recall` |
| `memory.get` | `fetch_memory` |
| `memory.remember` | `remember` (and `upload` for documents) |
| `memory.link` | `link` / `unlink` |
| `memory.supersede` | `remember` with the same `dedup_key` |
| `memory.history`, `memory.feedback`, `memory.prepare_handoff`, `memory.find_conflicts`, `memory.timeline`, `memory.batch`, `memory.propose_promotion` | none |
| `memory.graph_neighbors` | `get_entity` |
| none | `delete_memory` (retracts), `export_graph`, `chat`, `groom`, `dream` (not on Postgres) |

**Tool descriptions are the old backend's.** On the Postgres store:

- `delete_memory` says the vector and edges go with the memory; it only retracts.
- `remember` says reusing a `dedup_key` updates in place; it supersedes.

Agents act on these descriptions, so they should say what the Postgres store does.

**Evidence and epistemic states.**

- The spec wants independent dimensions.
- Today `kind` mixes type and certainty (`hypothesis`, `principle`), and `status` mixes lifecycle and truth (`superseded`, `retracted`).
- Proposal: leave both columns as they are for compatibility and add new ones beside them.

**Supersession.**

- The spec wants optimistic concurrency and immutable history.
- History is immutable today: text is never rewritten.
- Supersession has no expected version, though, and one key carries both identity and idempotency.
- Proposal: split them. `idempotency_key` replays the same request; `memory.supersede` takes the expected current version and refuses on a mismatch. Keep `dedup_key` for existing clients.

**Deletion.**

- The spec says a logical marker isn't enough.
- Retraction is a logical marker. The design kept text "for the record", and that choice has to be revisited for real deletion.

**Promotion.** None exists today. That is the safe default: no upward path at all. The spec's workflow would add the first controlled path.

**Content-blind admin.** The spec's limits are right and aren't written down yet (Security risks below).

**Pilot.** The spec names a pilot cell that differs from the one planned so far. That choice is a product decision and isn't assumed here.

## Security risks

Ranked by what they'd cost in a pilot with real client data.

1. **Content goes to third parties for embedding and extraction.**
   - Every memory's text goes to OpenAI for embedding, and the extraction job would send it to a model provider.
   - This isn't a flaw in isolation, but it is outside "content-blind" and outside Supabase.
   - It needs a decision per client, and a line in the security model.
2. **Retracted text stays retrievable through derived rows** (from reading the code; no test yet).
   - `get_entity` returns a relation's `evidence_span` whenever both entities are active, without checking that the evidence memory is still active.
   - Entities extracted only from a retracted memory stay active, and their names steer graph retrieval.
   - The embedding of a retracted memory stays in the HNSW index (search filters it out, but it is still stored).
3. **No real deletion, export or backup policy.**
   - A client who asks for their data to be removed can't be served today.
   - Supabase's backups keep whatever the plan keeps, and that window isn't recorded anywhere.
4. **Who can still read content.** Ordinary row security doesn't stop:
   - the Supabase `postgres` role and anyone holding the migration credential
   - Supabase staff with infrastructure access
   - backups and point-in-time restores
   - logs if a future change ever writes content to them
   - the embedding and extraction providers

   "Content-blind" means the EngramPort admin role and CLI, nothing more. If a client needs more, the options are application-level or customer-held keys, at the cost of server-side search over that content. This should be stated before any client contract says otherwise.
5. **Self-asserted truth.**
   - An agent can store "verified", "approved" or "deployed" as text or metadata, and recall returns it ranked like anything else.
   - The `claimed` field and the `extracted` origin are the only separation today.
6. **Last-write-wins on `dedup_key`.** Two agents revising the same decision silently replace each other's version. The old text survives, but the active answer flips.
7. **No correlation IDs or metrics.** An incident in a pilot couldn't be traced from an MCP call to the database row, and failed auth or denials wouldn't be counted.
8. **Per-instance rate limits.** With more than one instance, the effective limit multiplies. There are no quotas.
9. **The REST mirror and `/stream`.**
   - Every tool error on the REST mirror returns HTTP 500, so a client can't tell a refusal from an outage.
   - `/stream` tells any key holder the server's configured default namespace path.
   - Neither is used by MCP clients. Both could be switched off in hosted mode.
10. **The old backend is the default store.** Any deployment that forgets `ENGRAMPORT_STORE=postgres` serves the old backend. A hosted build should refuse to start without an explicit store.
11. **No pepper rotation.** Rotating the key pepper today invalidates every key at once.

## Minimal schema changes

All forward-only and additive. Existing columns, tools and data keep working.

1. **Correlation (no migration).** Fill `provenance.request_id` and `session_id` from the HTTP request, and log the same id.
2. **Epistemic and temporal columns on `memories`:**
   - `assertion` (observed, inferred, proposed), set by the writer.
   - `approval_state`, `verification_state` and `review_state`, which only the server changes.
   - `observed_at`, `valid_from` and `valid_until`.
   - `version` (integer, starting at 1).
   - `sensitivity`.

   `recorded_at` is the existing `created_at`.
3. **`memory_events`**: an append-only table of approval, verification, review, feedback, contradiction and deletion events. Each row has the actor, provenance, evidence and the state it moved to. The states in (2) are always derived from these events, never written directly.

   Verification and approval events would be accepted only from actors and transports marked for them: a CI service actor for "verified by test", a human actor for "approved". An agent's key can propose, never self-verify.
4. **`memory_evidence`**: typed references with a reference, version or commit, content hash, location and the verifying actor. Kinds: URL, git commit, pull request, CI run, transcript, memory.
5. **A memory type alongside `kind`**: the spec's 16 types as a checked text column, mapped from existing kinds, with per-type validation in a `memory.remember_v2` function.
6. **New memory link kinds**: `supersedes`, `implements`, `validates`, `affects`, `depends_on`, `motivates`, `derived_from_conversation`. This is an enum extension.
7. **Concurrency**: an `idempotency_keys` table (key, namespace, request hash, result, expiry), and `memory.supersede(id, expected_version, ...)`, which refuses on a mismatch.
8. **Deletion**: a `deletion_state` column and `memory.erase(id)`. It would:
   - replace content with a tombstone
   - delete the embedding
   - retract mentions, and relations whose evidence is that memory
   - retract entities whose only provenance is extraction from it
   - record an event

   Hiding evidence from non-active memories in `get_entity` and `memory.search` comes first, as a fix that needs no migration.
9. **Feedback and promotion**: `memory_feedback` (or feedback rows in `memory_events`), and `promotion_proposals` (source memory, target namespace, sanitized text, privacy class, reviewer, decision, audit link). Approval writes a new memory in the target namespace with provenance pointing back. The source text is never copied.

## MCP tool changes

Keep every current name. Add the following, underscored, each in its own PR:

| New tool | Built on |
|---|---|
| `memory_context` | key, namespaces, scopes, tool list, schema version |
| `memory_get` | `fetch_memory`, plus version, relationships and history options |
| `memory_history` | `supersedes` chain plus `memory_events` |
| `memory_supersede` | expected version, reason, evidence |
| `memory_feedback` | writes feedback events; affects ranking only through a bounded weight; never changes verification |
| `memory_timeline` | events and memories in a date range, in order |
| `memory_find_conflicts` | `contradicts` links, plus active memories of the same type and entities with incompatible states |
| `memory_graph_neighbors` | `get_entity` with depth up to 2, filters and caps |
| `memory_prepare_handoff` | a bounded briefing that separates verified, approved, observed and proposed items, each citing a memory id |
| `memory_batch` | up to 50 reads or writes, each authorized on its own, with per-item results |
| `memory_propose_promotion` | creates a proposal only; approval happens in the admin CLI by a human |

Widen `recall` with:

- `as_of`
- `include_superseded`
- evidence-state, entity and source filters
- `detail`
- `cursor`

Fix the descriptions of `remember` and `delete_memory`, and advertise all eight existing kinds.

## Build sequence

Small PRs, in order. Phase 1 items that touch a live system each wait for their own yes.

1. This document.
2. Hide evidence spans and graph hits from non-active memories, with tests (risk 2).
3. Correct the tool descriptions for the Postgres store, map REST errors to 400, 403, 404 and 503, and refuse hosted start without an explicit store.
4. Correlation ids into provenance and logs, and a structured log line per request with no content.
5. Deploy config and an env template, as files only (held earlier).
6. Phase 1, live, each on its own yes:
   - apply 0002–0009 to a development project
   - sign in from claude.ai, and from ChatGPT where the plan allows
   - record which tools each client lists and calls
7. Migration 0010: the epistemic and temporal columns, `memory_events` and `memory_evidence`.
8. `memory_supersede` with expected versions, and idempotency keys apart from `dedup_key`.
9. `memory_get` and `memory_history`.
10. Typed `remember` (the 16 types, validation, evidence, assertion) and new link kinds.
11. `memory_context` and `recall`'s new filters.
12. `memory_feedback`.
13. The eval expansion:
    - a held-out set labelled by query type
    - nDCG, leakage, temporal correctness, latency and cost
    - a run with the real embedding model, reported as measured
14. `memory_timeline`, `memory_find_conflicts` and `memory_graph_neighbors`.
15. `memory_prepare_handoff`.
16. `memory.erase` across derived rows, export, and a documented backup window.
17. Promotion proposals.
18. Metrics.
19. The rest of the documentation set.

Items 2 to 4 are small and can go before the pilot with no product decision.

## Test plan

Each PR adds its own tests in the existing suites. Beyond those:

- **Isolation.** Keep `rls_test.sql` as the gate. Add tests for:
  - error-text and count leakage (an unauthorized id gives the same answer as a missing one)
  - leakage through derived rows of a retracted or erased memory
  - promotion bypass, once promotion exists
- **Trust.** Tests that an agent key:
  - can't set approval or verification
  - can't forge provenance through `claimed`
  - can't link to a memory it can't read

  Plus tests that a contradiction is kept and reported, and that a memory containing instructions is returned as data with the untrusted note.
- **Concurrency.** Two writers superseding the same version: exactly one wins, the other gets a conflict. Replaying an idempotency key returns the first result.
- **Temporal.** `as_of` returns what was active then. A memory past `valid_until` drops out of current-state queries and stays in timelines.
- **Retrieval.** The held-out eval runs in CI with the stand-in embedder, and records its numbers. Every run with the real model reports its date, model and cost. No method is called better without both runs.
- **Clients.** A checklist per client (claude.ai, ChatGPT, Claude Code, others), recording:
  - connect, sign-in and namespace choice
  - the tool list
  - a read and a write
  - token refresh, revocation and reconnect

  Only a box ticked in the real client counts.

## Effect on the pilot

Against the §22 acceptance criteria today:

| # | Criterion | Today |
|---|---|---|
| 1, 2 | Two remote clients authenticate | Built, not run live |
| 3 | Both reach the same namespace | Built (members), not run live |
| 4, 5 | Store with provenance, retrieve from another agent | Built and tested locally |
| 6 | A fresh session reconstructs context | Possible with `recall`; no handoff tool |
| 7 | Claims distinguishable by evidence and status | Not built |
| 8 | Temporal supersession | Partial: by key, no versions |
| 9 | Concurrent writes don't corrupt | Not met for revisions (last-write-wins) |
| 10 | Cross-namespace restrictions | Built and tested |
| 11 | Revoked access fails | Built and tested |
| 12 | Reproducible retrieval benchmark | Partial: one small set |
| 13 | Audit identifies principals and operations | Built and tested |
| 14 | Admin respects the content-blind boundary | Built and tested; limits not documented |
| 15 | Failures observable | Not built |
| 16 | No known critical security finding | Risks 1 and 2 need a decision or a fix first |

A first pilot that stores and recalls cell memories across two clients needs:

- build items 2 to 6
- a decision on risk 1

A pilot that meets all of §22 also needs items 7 to 10 and 13 to 15.

## Decisions needed

1. **Which cell is the first pilot.** The spec names one; the plan so far named another.
2. **Content leaving Supabase.** Whether pilot content may go to OpenAI for embeddings, and to which provider for extraction. Or whether the pilot cell turns embedding and extraction off, and runs keyword and asserted-graph retrieval only.
3. **Deletion semantics.** Whether an erased memory keeps a tombstone and its provenance row for audit, and what backup window to promise.
4. **Tool naming.** Underscored names with the current ones kept, or the spec's dotted names after testing in each client.
5. **Who may approve and verify.** Which actors count as authorities: a human role, and a CI service actor.
6. **Tower and city reads.** Every cell reads its tower and city today. That fits shared product knowledge, but it means anything a tower key writes reaches every cell under it.
