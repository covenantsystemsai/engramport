# Database

SQL migrations for EngramPort's memory store on Supabase Postgres.

- `migrations/`: forward-only, numbered files. Each runs in one transaction,
  so a file holds no `BEGIN` or `COMMIT`. Once applied, a file never changes;
  fix forward with a new file.
- `migrate.sh`: applies new files to `$DATABASE_URL` and records each file's
  SHA-256 in `engramport_meta.schema_migrations`. A changed file stops the run.
- `test/run.sh`: applies everything to a throwaway database and runs
  `test/rls_test.sql`, `test/admin_test.sql`, `test/graph_test.sql` and
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
  write memories, provenance or embeddings, and cannot delete anything.
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
