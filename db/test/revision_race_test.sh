#!/usr/bin/env bash
# Two people approving competing revisions of one approved memory at the same
# moment: exactly one wins, the other is refused as stale, and the memory never
# has two current versions. The first decision is held open while the second
# runs. Run by run.sh after revision_test.sql, whose fixtures and helpers it reuses.
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL to a throwaway database}"
q() { psql "$DATABASE_URL" -X -q -tA -v ON_ERROR_STOP=1 "$@"; }

c1=00000000-0000-7000-8000-000000000111
k_c1=00000000-0000-7000-8000-0000000000f1

signin() { q -F ' ' -c "SELECT user_id, session_id FROM t.sign_in('rv-owner@client.test')"; }
as_agent() { q -c "SET ROLE engramport_app" -c "BEGIN" -c "SELECT t.as_key('$k_c1', '$c1')" -c "$1" -c "COMMIT" | grep -E '^[0-9a-f-]{36}$'; }

base=$(as_agent "SELECT memory.remember('decision', 'race check: deliveries on Mondays', 'remember', 'rest', p_claim_type => 'decision')")
read -r u s <<<"$(signin)"
q -c "SET ROLE engramport_app" -c "SELECT t.decide('$u', '$s', '$base', 'approve')" >/dev/null
pa=$(as_agent "SELECT memory.propose_revision('$base', 'decision', 'race check: deliveries on Tuesdays', 'supersede_memory', 'rest', 'decision')")
pb=$(as_agent "SELECT memory.propose_revision('$base', 'decision', 'race check: deliveries on Fridays', 'supersede_memory', 'rest', 'decision')")

read -r ua sa <<<"$(signin)"
read -r ub sb <<<"$(signin)"
read -r cha seca <<<"$(q -F ' ' -c "SET ROLE engramport_app" -c "SELECT challenge_id, secret FROM t.challenge('$ua', '$sa', '$pa', 'approve')" | tail -1)"
read -r chb secb <<<"$(q -F ' ' -c "SET ROLE engramport_app" -c "SELECT challenge_id, secret FROM t.challenge('$ub', '$sb', '$pb', 'approve')" | tail -1)"

app="race_$RANDOM"
PGAPPNAME=$app q -c "BEGIN" -c "SET ROLE engramport_app" \
  -c "SELECT memory.decide_approval_challenge('$ua', '$sa', '$cha', '$seca')" -c "SELECT pg_sleep(3)" -c "COMMIT" >/dev/null &
first=$!
until [ "$(q -c "SELECT count(*) FROM pg_stat_activity WHERE application_name = '$app' AND query LIKE '%pg_sleep%'")" = 1 ]; do
  sleep 0.1
done
rc=0
out=$(q -c "SET ROLE engramport_app" -c "SELECT memory.decide_approval_challenge('$ub', '$sb', '$chb', '$secb')" 2>&1) || rc=$?
wait "$first"

case "$rc $out" in
  [1-9]*"has changed"*) echo "pass a competing approval racing another waits for it and is refused as stale" ;;
  *) echo "FAIL a competing approval went through: $rc $out"; exit 1 ;;
esac
state() { q -c "SELECT status || '/' || approval_state FROM memory.memories WHERE id = '$1'"; }
[ "$(state "$pa")" = active/approved ] || { echo "FAIL the first proposal is $(state "$pa")"; exit 1; }
[ "$(state "$pb")" = proposed/pending ] || { echo "FAIL the second proposal is $(state "$pb")"; exit 1; }
[ "$(state "$base")" = superseded/approved ] || { echo "FAIL the base is $(state "$base")"; exit 1; }
[ "$(q -c "SELECT count(*) FROM memory.memories WHERE supersedes_id = '$base' AND status = 'active'")" = 1 ] \
  || { echo "FAIL more than one current version"; exit 1; }
echo "pass the memory has exactly one current version"
