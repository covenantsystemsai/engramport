# Database

SQL migrations for EngramPort's memory store on Supabase Postgres.

- `migrations/`: forward-only, numbered files. Each runs in one transaction,
  so a file holds no `BEGIN` or `COMMIT`. Once applied, a file never changes;
  fix forward with a new file.
- `migrate.sh`: applies new files to `$DATABASE_URL` and records each file's
  SHA-256 in `engramport_meta.schema_migrations`. A changed file stops the run.
- `test/run.sh`: applies everything to a throwaway database and runs
  `test/rls_test.sql`, `test/admin_test.sql`, `test/graph_test.sql`,
  `test/company_test.sql`, `test/audit_test.sql`, `test/extraction_test.sql` and
  `test/index_test.sql`. CI runs it on every pull request.

Applying to a real project needs the owner's yes first.

## Access model (0001)

- The server connects as `engramport_app`, which cannot bypass row security.
  Its login and password are set at deploy time from the secrets manager.
- Each transaction sets `app.api_key_id` and `app.namespace_id` with
  `set_config(..., true)` after the server has checked the caller's key with
  `memory.authenticate(prefix, hmac)`. Policies read the namespace from an
  active, unexpired key whose actor is enabled, and it must match
  `app.namespace_id`, so a revoked key stops working on its next statement.
- Namespaces form a city, tower, cell tree. A namespace reads itself and its
  ancestors, never a sibling or a child, and writes only to itself.
- Writes go through `memory.remember(...)`, which records provenance (key,
  actor and namespace from the key; client, tool and transport from the
  request; self-reported labels kept apart in `claimed`) and the memory together.
- Memory text is never edited in place. Only `status` and `supersedes_id`
  change, so a retraction keeps the original.
- `anon`, `authenticated` and `service_role` get no access to schema `memory`,
  and the schema is not exposed through Supabase's REST API.

## Admin role (0002)

- `engramport_admin` is what `engramport admin` runs as. It creates
  namespaces and actors, mints keys (it writes the HMAC and can never read a
  stored one back), revokes keys and sets their expiry. It cannot read or
  write memories, embeddings or graph rows, and cannot delete anything. Since
  0006 it can read provenance metadata for the audit (below), never content.
- It has no login. Give an operator's login role the right to switch to it:

  ```
  GRANT engramport_admin TO <login role> WITH INHERIT FALSE, SET TRUE;
  ```

  `INHERIT FALSE` keeps the login itself powerless; the tool runs
  `SET LOCAL ROLE engramport_admin` in every transaction, so even a more
  powerful login is held to the admin role's limits.
- A trigger on `api_keys` stops anyone, the owner included, from changing a
  key's namespace, actor, prefix, hash or scopes, or restoring a revoked key.
  To change scopes, rotate.

## Knowledge graph (0004)

- `entities` (a type such as `person` or `project`, a name and an optional
  description), `entity_aliases`, `relations` (source, predicate, target,
  confidence and optional evidence from a memory), `entity_mentions` (which
  memories mention which entities) and `memory_links` (memory to memory:
  supports, contradicts, derived_from, synthesizes, related).
- The same walls as memories: every row sits in the writer's own namespace and
  is read down the tree only. A row may point at something the writer can
  read, so a cell can relate its project to a tower concept, but the row stays
  in the cell and the tower never sees it. Every uniqueness rule includes the
  namespace, so a write never collides with a row its writer can't see.
- Names match after `memory.norm_key` (case, spacing and Unicode width), which
  a trigger computes; the caller can't supply it.
- Every graph write carries a provenance row of the writer's own key, made with
  `memory.record_provenance(...)`. Only the `job` transport may label a row
  `extracted`, so an agent can't pass its claims off as the extractor's.
- Rows are never edited or deleted. Entities, relations and links can move
  from active to retracted once, for every role, the owner included. The
  admin role gets no access: the graph is client data.

## Company namespace (0005)

- Every namespace has a purpose: `client` (the default) or `company`, for the
  operator's own knowledge. A city picks its purpose when it is created; a
  tower or cell always has its parent's, so company and client namespaces never
  share an ancestor. Since reads only flow down from ancestors, neither side
  can read the other, and the graph can't point across either, because it only
  points at what its writer can read.
- A purpose never changes and a namespace never moves, for every role, the
  owner included. There is at most one company city.
- Nothing else changes: the company tree has the same cells, keys, provenance
  and admin limits as any client's. The admin role creates it and still can't
  read what is in it.

## Admin audit (0006)

- The admin role is "manage and audit only". It can read these provenance
  columns and no others: `id`, `namespace_id`, `api_key_id`, `actor_id`,
  `tool`, `client_name`, `client_version`, `transport`, `session_id`,
  `request_id`, `source_kind`, `log_event_id`, `created_at`. That answers who
  wrote, through which agent, client, tool and transport, where and when.
- It still can't read `content_sha256` (a hash can confirm a guessed text),
  `claimed` (free-form fields an agent sends), `source_ref` (it can name a
  document), or any memory, embedding or graph row, and it can't write,
  change or delete provenance.
- `engramport admin audit` reads this trail together with the key lifecycle
  (minted, revoked) it could already see.

## Extraction (0007)

- `extraction_runs` records that an extractor (named with its version, such
  as `claude-haiku/v1`) read a memory: finished once, or failed with a short
  error class such as `timeout`. It holds counts, never memory text or a
  provider's message. A memory is finished at most once per extractor, so it
  is never read into the graph twice, and a new version can read it again.
- A run sits in the memory's own namespace, on one of that namespace's own
  memories, under a `job` provenance of the writer's own key. It is read only
  in that namespace, never changed or deleted, and the admin role can't read
  it.
- `pg_trgm`, in the `extensions` schema, with trigram indexes on entity and
  alias names, so the job can match "Grok Bots" to an existing "Grok Bot".
  The match is made in the store, only among entities the key can read and of
  the same type, and only when one candidate is clearly ahead of the next.

## Search (0008)

- `memory.search(query, embedding, model, kind, from, to, limit, retrievers)`
  answers a recall in one round trip with three retrievers: vector (HNSW,
  same embedding model only), keyword (full-text, any word may match) and
  graph (entities the query names, a walk of up to two hops over active
  relations of confidence 0.5 or more, and the memories that mention what it
  reaches).
- A vector hit scores its cosine similarity, a keyword hit its full-text rank
  scaled against the best in that search, and a graph hit how closely the
  query names its entity, times 0.7 a hop. Relevance is 40% semantic and 25% lexical, a graph hit counting in both,
  and it multiplies a 65% base plus up to 20% recency (90-day decay), 10%
  kind and 5% provenance quality. Hits under 5% relevance are dropped, and a
  tie at four places goes to the nearest namespace.
- It runs with the caller's rights, so row security decides every row; only
  `engramport_app` may run it, and the admin and API roles can't.

## OAuth sign-in (0009)

- The database half of OAuth 2.1 for claude.ai and other MCP clients. The
  HTTP side is `src/oauth.ts` (see the README); it only carries values
  between the browser and these functions.
- `oauth_members`: a verified Google email that may connect to one
  namespace, as one actor, with read or read+write scopes. The admin role adds
  and revokes members; revoking one ends every grant made through it.
- `oauth_clients`: clients that registered themselves (RFC 7591). Redirects
  are https, or http to this machine only, five at most.
- `oauth_issue_code` checks, in the database, that the person signed in with
  Google through Supabase Auth in the last 15 minutes, with a verified email
  that is the member's. The session itself must be the Google sign-in
  (recorded as OAuth, with the Google identity signing in as it started), not
  a password or magic-link session on an account that also has Google. So the
  server's own credentials can't issue a code for anyone.
- A trade holds the member while it runs, so a membership revoked at the same
  moment either stops the trade or revokes what it made.
- `oauth_exchange_code` checks the PKCE verifier (S256) and spends the code,
  even on a failed try. A code used twice revokes what it was traded for.
- The access token is an ordinary key that expires in an hour, tagged with
  its grant, so row security, provenance and the audit work as for any key.
  The refresh token lasts 30 days, works once and is replaced each time;
  presenting a spent one revokes the whole grant.
- Codes and refresh tokens are stored only as the server's HMAC. The server
  role reaches these tables only through seven functions; the admin role sees
  members, clients and grants, can revoke a grant, and never sees a code or a
  token.

## Run the tests locally

Needs Postgres 17 with pgvector 0.7 or later, as a database you can throw away:

```
DATABASE_URL=postgresql://postgres@localhost:5432/postgres db/test/run.sh
```

The server's store tests run every store call as `engramport_app` against a
migrated throwaway database:

```
psql postgresql://postgres@localhost:5432/postgres -c 'CREATE DATABASE store_test'
DATABASE_URL=postgresql://postgres@localhost:5432/store_test db/migrate.sh
ENGRAMPORT_TEST_DATABASE_URL=postgresql://postgres@localhost:5432/store_test npm run test:store
```
