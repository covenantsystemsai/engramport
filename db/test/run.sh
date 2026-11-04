#!/usr/bin/env bash
# Runs the migrations and the row security tests against a throwaway database.
# DATABASE_URL must point at a database you can drop, connected as a superuser
# (CI uses a pgvector Postgres container). Never point it at a real project.
set -euo pipefail

: "${DATABASE_URL:?set DATABASE_URL to a throwaway database}"
here="$(cd "$(dirname "$0")" && pwd)"
psql_() { psql "$DATABASE_URL" -X -q -v ON_ERROR_STOP=1 "$@"; }

# Stand-ins for the roles Supabase creates, so the tests can prove they get nothing.
psql_ <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN CREATE ROLE anon NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN CREATE ROLE authenticated NOLOGIN; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN CREATE ROLE service_role NOLOGIN BYPASSRLS; END IF;
END
$$;
SQL

DATABASE_URL="$DATABASE_URL" "$here/../migrate.sh"
# Applying again must be a no-op that only confirms the checksums.
DATABASE_URL="$DATABASE_URL" "$here/../migrate.sh"

psql_ -o /dev/null -f "$here/rls_test.sql"
psql_ -o /dev/null -f "$here/admin_test.sql"
psql_ -o /dev/null -f "$here/graph_test.sql"
psql_ -o /dev/null -f "$here/company_test.sql"
psql_ -o /dev/null -f "$here/audit_test.sql"
psql_ -o /dev/null -f "$here/extraction_test.sql"
psql_ -o /dev/null -f "$here/search_test.sql"
psql_ -o /dev/null -f "$here/embedding_test.sql"
psql_ -o /dev/null -f "$here/oauth_test.sql"
psql_ -o /dev/null -f "$here/index_test.sql"
psql_ -o /dev/null -f "$here/trust_test.sql"
psql_ -o /dev/null -f "$here/authority_test.sql"
DATABASE_URL="$DATABASE_URL" "$here/sign_in_race_test.sh"
psql_ -o /dev/null -f "$here/approvals_test.sql"
psql_ -o /dev/null -f "$here/acceptance_test.sql"
psql_ -o /dev/null -f "$here/challenge_test.sql"
DATABASE_URL="$DATABASE_URL" "$here/challenge_race_test.sh"
psql_ -o /dev/null -f "$here/revision_test.sql"
DATABASE_URL="$DATABASE_URL" "$here/revision_race_test.sh"
psql_ -o /dev/null -f "$here/erasure_test.sql"
DATABASE_URL="$DATABASE_URL" "$here/erasure_race_test.sh"
psql_ -o /dev/null -f "$here/export_test.sql"
psql_ -o /dev/null -f "$here/grants_test.sql"
DATABASE_URL="$DATABASE_URL" "$here/grants_race_test.sh"
psql_ -o /dev/null -f "$here/restore_test.sql"
