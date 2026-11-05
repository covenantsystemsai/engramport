#!/usr/bin/env bash
# A restoration whose challenge expires while it waits for a lock. The
# decision holds the memory and the authority, then checks the challenge's
# deadline again by the wall clock, so it is refused rather than restoring on
# an expired challenge.
# Run by run.sh after restore_test.sql, whose fixtures and helpers it reuses.
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL to a throwaway database}"
q() { psql "$DATABASE_URL" -X -q -tA -v ON_ERROR_STOP=1 "$@"; }

c1=00000000-0000-7000-8000-000000000111
k_c1=00000000-0000-7000-8000-0000000000f1

echo '-- a challenge that expires while the decision waits is refused'
m=$(q -c "SET ROLE engramport_app" -c "BEGIN" -c "SELECT t.as_key('$k_c1', '$c1')" \
      -c "SELECT memory.remember('fact', 'restore race: waited too long', 'remember', 'rest', p_claim_type => 'fact')" \
      -c "COMMIT" | grep -E '^[0-9a-f-]{36}$')
q -c "SET ROLE engramport_app" -c "BEGIN" -c "SELECT t.as_key('$k_c1', '$c1')" \
  -c "UPDATE memory.memories SET status = 'retracted' WHERE id = '$m'" -c "COMMIT" >/dev/null
read -r u s <<<"$(q -F ' ' -c "SELECT user_id, session_id FROM t.sign_in('er-owner@client.test')")"
read -r ch sec <<<"$(q -F ' ' -c "SET ROLE engramport_app" -c "SELECT challenge_id, secret FROM t.restore_challenge('$u', '$s', '$m')" | tail -1)"
# Bring the challenge's deadline to two seconds from now, as only a test may.
q -c "ALTER TABLE memory.restore_challenges DISABLE TRIGGER restore_challenges_kept" \
  -c "UPDATE memory.restore_challenges SET expires_at = clock_timestamp() + interval '2 seconds' WHERE id = '$ch'" \
  -c "ALTER TABLE memory.restore_challenges ENABLE TRIGGER restore_challenges_kept" >/dev/null
app="race_$RANDOM"
PGAPPNAME=$app q -c "BEGIN" -c "SELECT 1 FROM memory.memories WHERE id = '$m' FOR UPDATE" -c "SELECT pg_sleep(3)" -c "COMMIT" >/dev/null &
held=$!
until [ "$(q -c "SELECT count(*) FROM pg_stat_activity WHERE application_name = '$app' AND query LIKE '%pg_sleep%'")" = 1 ]; do
  sleep 0.1
done
rc=0
out=$(q -c "SET ROLE engramport_app" -c "SELECT memory.decide_restore_challenge('$u', '$s', '$ch', '$sec')" 2>&1) || rc=$?
wait "$held"
case "$rc $out" in
  [1-9]*"challenge has expired"*) echo "pass the decision waits, then sees the challenge expired" ;;
  *) echo "FAIL a restoration went through on an expired challenge: $rc $out"; exit 1 ;;
esac
[ "$(q -c "SELECT status FROM memory.memories WHERE id = '$m'")" = retracted ] || { echo "FAIL the memory came back"; exit 1; }
echo "pass the memory stays retracted"
