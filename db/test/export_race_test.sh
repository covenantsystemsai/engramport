#!/usr/bin/env bash
# An export under a grant racing the end of that grant. The authority an
# export rests on is held while its rows are gathered, and checked again by
# the clock before any row leaves: a revocation made first stops the export, a
# revocation made during it waits for it, and a grant that runs out while the
# rows are gathered stops the whole export, which is then not recorded.
# Run by run.sh after grants_test.sql, whose fixtures and helpers it reuses.
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL to a throwaway database}"
q() { psql "$DATABASE_URL" -X -q -tA -v ON_ERROR_STOP=1 "$@"; }

c1=00000000-0000-7000-8000-000000000111
owner=er-owner@client.test
holder=gr-race@client.test

q -c "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'gr-race', 'Race helper')" \
  -c "INSERT INTO memory.oauth_members (email, namespace_id, actor_id) SELECT '$holder', '$c1', id FROM memory.actors WHERE slug = 'gr-race'" >/dev/null
helper=$(q -c "SELECT id FROM memory.actors WHERE slug = 'gr-race'")

signin() { q -F ' ' -c "SELECT user_id, session_id FROM t.sign_in('$1')"; }
app() { q -c "SET ROLE engramport_app" -c "$1" | { grep -E '^[^ ]' || true; }; }
# An accepted export grant for the helper, ending at the given interval from now.
grant() {
  local u s g sha
  read -r u s <<<"$(signin "$owner")"
  g=$(app "SELECT memory.grant_data_power('$u', '$s', '$c1', '$helper', 'export', now() + interval '$1')")
  read -r u s <<<"$(signin "$holder")"
  sha=$(app "SELECT grant_sha256 FROM memory.pending_data_grants('$u', '$s') WHERE grant_id = '$g'")
  read -r u s <<<"$(signin "$holder")"
  app "SELECT memory.decide_data_grant('$u', '$s', '$g', 'accept', '$sha')" >/dev/null
  echo "$g"
}
# A started export by the helper: "session export secret".
started() {
  local u s x sec
  read -r u s <<<"$(signin "$holder")"
  read -r x sec <<<"$(q -F ' ' -c "SET ROLE engramport_app" -c "SELECT export_id, secret FROM memory.issue_export_challenge('$u', '$s', '$c1')" | tail -1)"
  app "SELECT memory.start_export('$u', '$s', '$x', '$sec')" >/dev/null
  echo "$s $x $sec"
}
rows_sql() { echo "SELECT count(*) FROM memory.export_rows('$1', '$2', '$3')"; }
revoke_sql() { echo "SELECT memory.revoke_data_grant('$1', '$2', '$3', 'no_longer_needed')"; }
completed() { q -c "SELECT completed_at IS NOT NULL FROM memory.exports WHERE id = '$1'"; }
# Run SQL in the background inside a transaction held open, as the given role,
# until the given SQL sleep ends, and return once it is sleeping.
hold() {
  local role=$1 sleep=$2 app="race_$RANDOM"; shift 2
  PGAPPNAME=$app q -c "BEGIN" -c "SET ROLE $role" "$@" -c "$sleep" -c "COMMIT" >/dev/null &
  held=$!
  until [ "$(q -c "SELECT count(*) FROM pg_stat_activity WHERE application_name = '$app' AND query LIKE '%pg_sleep%'")" = 1 ]; do
    sleep 0.1
  done
}
expect() { [ "$2" = "$3" ] || { echo "FAIL $1: wanted $3, got $2"; exit 1; }; echo "pass $1"; }

echo '-- a revocation made first stops an export that started before it'
g=$(grant '7 days'); read -r s x sec <<<"$(started)"
read -r ou os <<<"$(signin "$owner")"
hold engramport_app "SELECT pg_sleep(2)" -c "$(revoke_sql "$ou" "$os" "$g")"
rc=0
out=$(q -c "SET ROLE engramport_app" -c "$(rows_sql "$s" "$x" "$sec")" 2>&1) || rc=$?
wait "$held"
case "$rc $out" in
  [1-9]*"no longer valid"*) echo "pass the export waits for the revocation and is refused" ;;
  *) echo "FAIL an export went through under a revoked grant: $rc $out"; exit 1 ;;
esac
expect "and is not recorded as delivered" "$(completed "$x")" f

echo '-- a revocation made during an export waits for it to finish'
g=$(grant '7 days'); read -r s x sec <<<"$(started)"
hold engramport_app "SELECT pg_sleep(3)" -c "$(rows_sql "$s" "$x" "$sec")"
read -r ou os <<<"$(signin "$owner")"
rc=0
out=$(q -c "SET ROLE engramport_app" -c "SET lock_timeout = '1s'" -c "$(revoke_sql "$ou" "$os" "$g")" 2>&1) || rc=$?
case "$rc $out" in
  [1-9]*"lock timeout"*) echo "pass the revocation waits while the export is in progress" ;;
  *) echo "FAIL a revocation slipped past an export in progress: $rc $out"; exit 1 ;;
esac
wait "$held"
expect "the export finished" "$(completed "$x")" t
read -r ou os <<<"$(signin "$owner")"
app "$(revoke_sql "$ou" "$os" "$g")" >/dev/null
expect "and the revocation then goes through" "$(q -c "SELECT revoked_at IS NOT NULL FROM memory.data_grants WHERE id = '$g'")" t

echo '-- a grant that runs out while the rows are gathered stops the export'
g=$(grant '5 seconds'); read -r s x sec <<<"$(started)"
# Keep a table the export reads busy until a second after the grant ends, so
# the export passes its first check and is still gathering when the grant ends.
hold NONE \
  "SELECT pg_sleep(greatest(extract(epoch FROM expires_at - clock_timestamp()), 0) + 1) FROM memory.data_grants WHERE id = '$g'" \
  -c "LOCK TABLE memory.erasures IN ACCESS EXCLUSIVE MODE"
rc=0
out=$(q -c "SET ROLE engramport_app" -c "$(rows_sql "$s" "$x" "$sec")" 2>&1) || rc=$?
wait "$held"
case "$rc $out" in
  [1-9]*"ended while it was being gathered"*) echo "pass the export is refused once the grant has run out" ;;
  *) echo "FAIL an export finished under a grant that ran out: $rc $out"; exit 1 ;;
esac
expect "and is not recorded as delivered" "$(completed "$x")" f
