#!/usr/bin/env bash
# Whole-cell erasure racing a write into the cell. A write under way when the
# owner starts the erasure finishes first, and is counted and erased with the
# rest; a write that starts while the request is open waits for it and is
# refused. Run by run.sh after cell_erasure_test.sql, whose fixtures and
# helpers it reuses (the cell-2 owner, the confirmer role, t.cell_challenge).
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL to a throwaway database}"
q() { psql "$DATABASE_URL" -X -q -tA -v ON_ERROR_STOP=1 "$@"; }

c2=00000000-0000-7000-8000-000000000112
k_c2=00000000-0000-7000-8000-0000000000f2
expect() { [ "$2" = "$3" ] || { echo "FAIL $1: wanted $3, got $2"; exit 1; }; echo "pass $1"; }
live() { q -c "SELECT count(*) FROM memory.memories WHERE namespace_id = '$c2' AND status <> 'erased'"; }

echo '-- a write under way when the erasure starts is erased with the cell'
app="race_$RANDOM"
PGAPPNAME=$app q -c "SET ROLE engramport_app" -c "BEGIN" -c "SELECT t.as_key('$k_c2', '$c2')" \
  -c "SELECT memory.remember('fact', 'cell race: written while the erasure started', 'remember', 'rest')" \
  -c "SELECT pg_sleep(3)" -c "COMMIT" >/dev/null &
held=$!
until [ "$(q -c "SELECT count(*) FROM pg_stat_activity WHERE application_name = '$app' AND query LIKE '%pg_sleep%'")" = 1 ]; do
  sleep 0.1
done
read -r u s <<<"$(q -F ' ' -c "SELECT user_id, session_id FROM t.sign_in('er-c2@client.test')")"
req=$(q -c "SET ROLE engramport_app" -c "SELECT memory.request_cell_erasure('$u', '$s', '$c2', 'owner_request')" | grep -E '^[0-9a-f-]{36}$')
wait "$held"
expect "the request waited for the write, and its preview counts it" \
  "$(q -c "SELECT (preview ->> 'memories')::int FROM memory.cell_erasure_requests WHERE id = '$req'")" "$(live)"
q -c "SELECT 1 FROM memory.memories WHERE content = 'cell race: written while the erasure started' AND status = 'active'" | grep -q 1 \
  || { echo "FAIL the write was lost"; exit 1; }

echo '-- a write that starts while the request is open is refused'
rc=0
out=$(q -c "SET ROLE engramport_app" -c "BEGIN" -c "SELECT t.as_key('$k_c2', '$c2')" \
        -c "SELECT memory.remember('fact', 'cell race: written too late', 'remember', 'rest')" -c "COMMIT" 2>&1) || rc=$?
case "$rc $out" in
  [1-9]*"waiting for whole-cell erasure"*) echo "pass the late write is refused" ;;
  *) echo "FAIL a write landed in a frozen cell: $rc $out"; exit 1 ;;
esac

echo '-- confirmed, the write that raced the request is gone too'
read -r cu cs ch sec <<<"$(q -F ' ' -c "SELECT user_id, session_id, challenge_id, secret FROM t.cell_challenge('ce-confirmer@an2b.test', '$req')")"
q -c "SET ROLE engramport_app" -c "SELECT memory.decide_cell_erasure_challenge('$cu', '$cs', '$ch', '$sec')" >/dev/null
expect "nothing of the cell is left" "$(live)" 0
expect "and nothing of that text" \
  "$(q -c "SELECT count(*) FROM memory.memories WHERE content LIKE 'cell race:%'")" 0
