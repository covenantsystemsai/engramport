# Database

SQL migrations for EngramPort's memory store on Supabase Postgres.

- `migrations/`: forward-only, numbered files. Each runs in one transaction,
  so a file holds no `BEGIN` or `COMMIT`. Once applied, a file never changes;
  fix forward with a new file.
- `migrate.sh`: applies new files to `$DATABASE_URL` and records each file's
  SHA-256 in `engramport_meta.schema_migrations`. A changed file stops the run.
- `test/run.sh`: applies everything to a throwaway database and runs
  `test/rls_test.sql`. CI runs it on every pull request.

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

## Run the tests locally

Needs Postgres 17 with pgvector 0.7 or later, as a database you can throw away:

```
DATABASE_URL=postgresql://postgres@localhost:5432/postgres db/test/run.sh
```
