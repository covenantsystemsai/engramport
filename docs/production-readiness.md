# Production readiness: where EngramPort stands against the readiness directive

Written 2026-11-04 against `main` at `0f5601d`. This is the Gate 1 reconnaissance the
production readiness directive asks for: what the repository actually does, a capability
matrix, the founder decisions that block later gates, and a dependency-ordered backlog.
It changes no code, applies no migration and deploys nothing.

Everything marked *verified* below was checked by running it, not by reading a claim.
Where this document and an older one disagree, this one was checked later.

## 1. Evidence reproduced

| Check | Command | Result on `0f5601d` |
| --- | --- | --- |
| Unit tests | `npm test` | 76 pass, 0 fail |
| Store tests against Postgres 16 + pgvector | `ENGRAMPORT_TEST_DATABASE_URL=… npm run test:store` | 82 pass, 0 fail |
| Migrations and row security | `DATABASE_URL=… db/test/run.sh` (applies 0001 to 0013, then 11 SQL test files) | 351 assertions pass, 0 fail |
| Retrieval benchmark (CI, `gte-small`) | `embedding-bench.yml` | Recall@1: tuned set 92%, held-out 95%, fresh 96%. Top-3 is 100% on both unseen sets |

Notes on the local run: the CI image has `halfvec`; the local Postgres used `vector`
instead, which changes storage width, not behaviour. CI runs the same three suites on
every pull request, plus CodeQL, `npm audit --omit=dev --audit-level=high` and a secret scan.

The live Supabase project, read on 2026-11-04 through the management API:

- Postgres 17, healthy, one migration applied (`0001_memory_core`) of the 13 on `main`.
- No namespaces, actors, keys, memories, embeddings or provenance rows. No Edge Functions.
- One advisor note: `rls_enabled_no_policy` on `memory.api_keys`. That is by design: the
  table is reached only through the definer functions `current_key()` and `authenticate()`.

Not checkable from here: the old Cloud Run service (no Google Cloud credentials in this
environment), branch protection on `main`, and any live client (claude.ai connector,
ChatGPT, Grok, Codex). None has ever been tried against the Postgres store.

## 2. What the system is today

- **Store.** Postgres only: `pgvector` for embeddings, tables for entities, relations and
  memory links, generated `tsvector` for keywords. Schema `memory`, 13 forward-only migrations.
- **Isolation.** Every memory table has forced row security. The server runs as
  `engramport_app` (no superuser, no `BYPASSRLS`) and refuses to start on a role that skips
  row security. A request sets
  `app.api_key_id` and `app.namespace_id` only after `memory.authenticate()` accepts the
  key, inside the request's own transaction.
- **Namespaces.** `city / tower / cell`. A key writes only its own namespace and reads its
  own namespace plus its ancestors (`memory.readable_namespaces()`). Siblings never see
  each other. Nothing flows upward on its own.
- **Provenance.** Every write calls `memory.record_provenance()`, which takes the key,
  namespace and actor from `current_key()`, not from the caller. What a client sends about
  itself is stored separately as `claimed`.
- **Admin.** `engramport_admin` manages namespaces, actors and keys and reads provenance
  metadata. It cannot read memory text, embeddings, graph rows, `claimed`, `source_ref` or
  content hashes. This is "manage and audit only".
- **Retrieval.** Hybrid: vector and keyword candidates blended by `0013_hybrid_blend`, with
  vector-only, keyword-only and graph modes. Each namespace names its embedding model
  (`0011`); vectors from another model are skipped, not compared (`0012`).
- **Transport.** MCP over stdio and streamable HTTP (`POST /mcp`), plus REST per tool.
  OAuth 2.1 with dynamic client registration and protected-resource metadata for claude.ai
  (`0009`, `src/oauth.ts`). Per-key rate limit. No localhost default for hosted use.

## 3. Capability matrix

Categories follow section 3 of the directive. "Section" is the directive section it answers.

### Implemented and verified

| Capability | Section | Evidence |
| --- | --- | --- |
| Per-namespace isolation by forced row security | 5 | `db/test/rls_test.sql`, store tests |
| Keys scoped to one namespace; read and write scopes; expiry and revocation | 5, 8 | `rls_test.sql`, `admin_test.sql` |
| Cell reads ancestors, never siblings or children | 5 | `rls_test.sql` |
| Server-established provenance (key, actor, namespace, tool, transport, request id) | 6.2 | `audit_test.sql`, `store.pg.test.ts` |
| Admin manages and audits without reading content | 4 | `admin_test.sql`, `admin.pg.test.ts` |
| Company namespace kept apart from client namespaces | 5 | `company_test.sql` |
| Versioning by `dedup_key`: a new write supersedes the active one and points back to it | 6.4 (partial) | `store.pg.test.ts` |
| Retraction keeps the text and hides it from recall; derived graph rows hidden too | 7 (partial) | `store.pg.test.ts`, `graph_test.sql` |
| Graph: entities, relations, memory links (`supports`, `contradicts`, `derived_from`, `synthesizes`, `related`) | 4, 8 | `graph_test.sql`, `graph.pg.test.ts` |
| Hybrid recall with date filters and kind filter | 8 | `search_test.sql`, benchmark |
| Per-namespace embedding model; stale vectors excluded | 4 | `embedding_test.sql`, `embedding-models.pg.test.ts` |
| OAuth flow and MCP handshake over HTTP (in tests) | 8 | `oauth-http.pg.test.ts`, `mcp-http.test.ts` |
| Request ids on every response | 15 (partial) | `request-id.test.ts` |
| Tool descriptions tell agents stored text is data, not instructions | 13 | `store-definitions.test.ts` |

### Implemented but unverified

| Capability | Why unverified |
| --- | --- |
| claude.ai custom connector end to end | Never run against a deployed server |
| Real Google sign-in through Supabase Auth | Only a test identity provider has been used |
| Embedding Edge Function (`supabase/functions/embed`) | Never deployed |
| Migrations 0002 to 0013 on the live project | Applied only to test databases |
| Extraction (`src/store/extract.ts`, `0007`) | Tested with a fake extractor; no provider chosen |

### Partially implemented

| Capability | Section | What exists | What is missing |
| --- | --- | --- | --- |
| Supersession | 6.4 | `dedup_key` versioning with `expected_version`; `supersede_memory`, which names the version it replaces and records why; `memory_history`; an approved memory is revised only by a proposal a person approves (D-04) | No person's retraction path for an approved memory yet |
| Contradictions | 6.5 | A `contradicts` link kind; `find_conflicts` lists open ones, and one closes when either side is superseded or retracted | An agent can still remove a flag with `unlink`; dismissing a conflict without changing either memory should need a person |
| Deletion lifecycle | 7 | Retraction; export of one namespace by its owner, streamed and never stored (`/export`); the owner's erasure page (`/erase`); delegated erase and export grants that the holder accepts with their own sign-in; restoring a retracted memory by a person with authority over it, within 30 days of the retraction, after which it is final; whole-cell erasure started by the owner and confirmed by a different person holding the cell-erasure-confirmer role, with the cell frozen while it waits; erasure of up to 100 memories per request, decided by an owner with a fresh sign-in, removing every version and everything derived, verified and recorded with a content-free tombstone; `request_erasure` for agents; reapplying erasures after a restore (D-02, `docs/erasure.md`) | Pages to give and accept delegated grants, to restore a retracted memory, and to start and confirm a whole-cell erasure and accept the confirmer role are still to build |
| Claim types | 6.1 | `memory_kind` has `decision`, `hypothesis`, `insight`, `fact` | Kind mixes claim type with content type; no approval, verification or lifecycle dimensions |
| Telemetry | 15 | Request ids, provenance timestamps | No metrics, no `session_id` filled, no latency or error counts |
| Tool contract | 8 | `remember`, `recall`, `fetch_memory`, `delete_memory`, `link`, `unlink`, `get_entity`, `upload`, `inspect`, `list_namespaces` | `context`, `history`, `timeline`, `feedback`, `prepare_handoff`, `find_conflicts`, `graph_neighbors`, `propose_promotion`; `recall` has no as-of or pagination |

### Missing

| Capability | Section |
| --- | --- |
| Approval evidence as a record (authority, scope, action, target, version, time, expiry) | 6.3 |
| Verification linked to an artifact that agents cannot forge | 6.6 |
| Controlled promotion from cell to tower to city | 5 |
| As-of (point-in-time) recall and history | 8 |
| Handoff packets with a token budget | 8, 9 |
| Supervisor integration boundary (defined in section 6 below, not built) | 9 |
| Self-serve tier, MCP registry listing, abuse checks | later |

### Conflicting with the requested architecture

| Item | Conflict | Proposed fix |
| --- | --- | --- |
| `ENGRAMPORT_STORE` defaults to `eidetic` (`src/config.ts`) | The old backend is still the default | Default to `postgres`, keep `eidetic` as an explicit opt-in (one small PR) |
| `Dockerfile` targets the old Cloud Run backend and its service account | The image does not run the Postgres store as designed | New deploy artifacts under D-05; until then do not use this image |
| `package.json` description says "bring-your-own-LLM (any model via OpenRouter)" | Not what the product is now | Fix with the next release under D-08 |
| `publish.yml` publishes to npm on any `v*` tag | A tag is a release; the published packages predate all Postgres work | Leave alone until D-08; consider an approval environment on that job |
| Memory text may carry "approved" in prose | Section 6.3: a model writing "approved" is not an authorization | The trust layer stores approval only as a separate, server-recorded event |

### Requires founder decision

See the decision register in section 4: D-01 to D-09.

## 4. Founder decision register

Each decision is open until the founder answers it in his own words. A recommended default
is a starting point for that conversation, not an assumption anything is built on.

| Id | Decision | Recommended default | Blocks |
| --- | --- | --- | --- |
| D-01 | Automatic extraction of entities and relations | None for the first pilot (option A). Graph rows only when an agent calls `link`. Revisit after the pilot with a named provider | Gate 3 scope |
| D-02 | Deletion, retention, backups and export | Decided Nov 4: a person with authority erases, agents only ask; erasure removes the text and everything derived and keeps a tombstone with no content-derived data, not even a fingerprint; at most 100 memories per request; whole-cell erasure needs the owner and a different person with AN2B governance authority, decided Nov 4 as a dedicated cell-erasure-confirmer role (D-02.1a: explicitly assigned to a named human, accepted with their own sign-in, scoped, expiring or revocable, separate from memory-approval permissions; the confirmer sees no memory content and can't initiate or confirm their own request); retraction is separate and restorable by a person for 30 days, erasure is final; restored backups are reconciled against erasures before serving; export needs its own accepted grant and is never stored on the server. See `docs/erasure.md` | Gate 2 deletion work |
| D-03 | Who may approve and who may verify | Only human actors may approve, and only the namespace owner and the founder at first. Agents may propose and may attach evidence; they may not approve or mark verified | Gate 2 trust layer |
| D-04 | Revising an approved memory | Decided Nov 4: an agent's revision is a proposal; the approved version stays current until a person approves the proposal, which then replaces it atomically. See `docs/approvals.md` | Gate 2 trust layer |
| D-05 | Permission to author deploy files and a setup script (files only) | Yes for files in a PR, with deploy kept as its own later decision | Gate 3 preparation |
| D-06 | Where the HTTP server runs | Compare Supabase Edge Functions, Cloud Run and Fly.io in a short doc before choosing | Gate 3 |
| D-07 | The old Cloud Run backend | Require authentication on it, then retire it once the Postgres store is live | Gate 3 |
| D-08 | npm releases | No release until Gate 3 passes; then a major version whose default store is Postgres | Gate 4 |
| D-09 | Memory write policy (what must never be stored); numbered D-04 until Nov 4 | Write the founder's never-store list as policy text first, enforce it later. Not approved yet | Gate 3 |

## 5. Dependency-ordered backlog

Each line is one small pull request unless it says otherwise. Nothing here runs against
the live project; every live step is in section 7 and needs its own yes.

### Gate 1: repository readiness

1. This document.
2. Default `ENGRAMPORT_STORE` to `postgres`.
3. Fix the package description (text only, no release).
4. Short note in `README` that the Dockerfile is for the old backend (until D-05).

### Gate 2: trust readiness

5. **Trust layer milestone 1** (section 8 below): claim, approval, verification and
   lifecycle as separate columns; expected-version supersede; approval only by reference to
   a server-recorded event.
6. Approval events table and a human-only approve path (needs D-03).
7. Verification by artifact reference (a commit, PR, test run or document), recorded by
   the server, never by the agent's own word.
8. Contradiction review: open, resolved, dismissed; `find_conflicts`.
9. `history` and as-of recall.
10. Export for one namespace (owner request).
11. Physical deletion with tombstone and a deletion report covering text, embeddings,
    graph rows and indexes (needs D-02).
12. Adversarial test pack from section 13 of the directive: cross-namespace reads, key
    confusion, forged provenance, forged approval, prompt injection in stored text.

### Gate 3: live service

13. Hosting comparison (D-06), then deploy artifacts and a setup script, files only (D-05).
14. Live steps in section 7, each on its own yes.
15. Non-content metrics: request counts, latency, errors, per namespace, never text.

### Gate 4: cross-model memory

16. Run the same task from Claude, ChatGPT, Grok and Codex against one test namespace and
    record what each client can and cannot do.
17. `context` and `prepare_handoff` with a token budget.
18. Release under D-08.

### Gate 5: AN2X integration

19. Supervisor adapter in shadow mode (section 6), reading only.
20. Promotion proposals from cell to tower (`propose_promotion`), approved by a human,
    copying a derived summary upward, never raw cell memory.
21. Convergence test between the memory pilot and the supervisor pilot.

## 6. Integration boundary with the cell supervisor

Defined here only. Nothing in this repository calls the supervisor, and nothing is built
on the supervisor's side.

- **EngramPort owns** memory, provenance, the graph, versions, contradictions, source
  references, promotion proposals, the audit trail and handoff packets.
- **The supervisor owns** task scheduling, pull request execution, deployments, workflow
  state, release authority, provisioning and transactions. EngramPort stores what was
  decided and where the evidence is; it never stores that a deploy "is running".
- **The interface** is the same MCP tools any agent uses, through a key scoped to the
  supervisor pilot's own cell. No shared tables, no direct database access, no wider key.
- **Shadow mode first.** The supervisor keeps its own local store. It may read from its
  EngramPort cell and write observations there, but its decisions do not depend on
  EngramPort until the memory pilot passes Gate 3.
- **The two pilots stay independent** until each passes its own gate.

## 7. Live steps, each needing its own yes

None of these has been done. They are listed in order so each can be asked for separately.

1. Apply migrations 0002 to 0013 to the live project.
2. Create the company city and the first memory pilot cell; mint their keys into a secrets manager.
3. Deploy the embedding Edge Function and set its secret.
4. Deploy the HTTP server (after D-06).
5. Connect one client and run the pilot checks with non-sensitive data.
6. Require authentication on the old Cloud Run service (D-07).
7. Turn on branch protection for `main`.
8. Publish to npm (D-08).

## 8. Proposed trust layer milestone 1

The smallest change that makes section 6 of the directive real, in one reviewable PR:

- A migration adding four independent columns to `memory.memories`: `claim_type`
  (observation, inference, hypothesis, proposal, decision, fact), `approval_state`
  (none, pending, approved, rejected), `verification_state` (unverified, verified,
  disputed) and keeping `status` as the lifecycle. Existing rows default to
  `observation / none / unverified`.
- `approval_state` and `verification_state` cannot be set by `remember`. Agents can only
  write `none` or `unverified`; only a future, human-only path changes them. A test proves
  an agent cannot write "approved" through any tool or through metadata.
- An optional `expected_version` on writes that reuse a `dedup_key`: if the active version
  is not the one named, the write is refused instead of silently superseding. A test runs
  two writers against the same key.
- `recall` and `fetch_memory` return the four fields, so agents can tell a hypothesis from
  an approved decision.

Not in milestone 1: the approval events table, verification artifacts, contradiction review,
export and deletion. Those follow as items 6 to 11.
