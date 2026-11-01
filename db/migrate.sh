#!/usr/bin/env bash
# Applies db/migrations/*.sql in order to $DATABASE_URL, each in one
# transaction with its checksum recorded. A file that was applied before and has
# since changed stops the run: migrations are forward-only, so fix forward.
set -euo pipefail

: "${DATABASE_URL:?set DATABASE_URL to the target database}"
dir="$(cd "$(dirname "$0")/migrations" && pwd)"
psql_() { PGOPTIONS="-c client_min_messages=warning" psql "$DATABASE_URL" -X -q -v ON_ERROR_STOP=1 "$@"; }

psql_ <<'SQL'
CREATE SCHEMA IF NOT EXISTS engramport_meta;
REVOKE ALL ON SCHEMA engramport_meta FROM PUBLIC;
CREATE TABLE IF NOT EXISTS engramport_meta.schema_migrations (
  version text PRIMARY KEY,
  checksum_sha256 text NOT NULL CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
  applied_at timestamptz NOT NULL DEFAULT now()
);
SQL

for f in "$dir"/[0-9][0-9][0-9][0-9]_*.sql; do
  version="$(basename "$f" .sql)"
  sum="$(sha256sum "$f" | cut -d' ' -f1)"
  recorded="$(psql_ -At -c "SELECT checksum_sha256 FROM engramport_meta.schema_migrations WHERE version = '$version'")"
  if [ -n "$recorded" ]; then
    if [ "$recorded" != "$sum" ]; then
      echo "migration $version changed after it was applied (recorded $recorded, file $sum)" >&2
      exit 1
    fi
    echo "ok      $version"
    continue
  fi
  { cat "$f"; printf "\nINSERT INTO engramport_meta.schema_migrations (version, checksum_sha256) VALUES ('%s', '%s');\n" "$version" "$sum"; } \
    | psql_ --single-transaction
  echo "applied $version"
done
