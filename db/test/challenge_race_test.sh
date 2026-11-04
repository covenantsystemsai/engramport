#!/usr/bin/env bash
# A decision racing a revocation, or a disabled approver, must not slip
# through. The first session holds the revocation (or the disabling) open while
# the second tries to decide; the decision must wait and then be refused.
# Run by run.sh after challenge_test.sql, whose fixtures and helpers it reuses.
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL to a throwaway database}"
q() { psql "$DATABASE_URL" -X -q -tA -v ON_ERROR_STOP=1 "$@"; }

c1=00000000-0000-7000-8000-000000000111
k_c1=00000000-0000-7000-8000-0000000000f1

# A fresh approver with an accepted authority, and a memory to decide on.
setup() { # slug
  q -c "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', '$1', 'Racing approver')" \
    -c "INSERT INTO memory.oauth_members (email, namespace_id, actor_id)
        SELECT '$1@client.test', '$c1', id FROM memory.actors WHERE slug = '$1'" >/dev/null
  local a
  a=$(q -c "SET ROLE engramport_admin" -c "INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
            SELECT id, '$c1', 'cell_knowledge' FROM memory.actors WHERE slug = '$1' RETURNING id" | tail -1)
  q -c "SELECT t.accept('$a', '$1@client.test')" >/dev/null
  local m
  m=$(q -c "SET ROLE engramport_app" -c "BEGIN" -c "SELECT t.as_key('$k_c1', '$c1')" \
        -c "SELECT memory.remember('decision', 'race check: $1', 'remember', 'rest', p_claim_type => 'decision')" \
        -c "COMMIT" | grep -E '^[0-9a-f-]{36}$')
  local u s
  read -r u s <<<"$(q -F ' ' -c "SELECT user_id, session_id FROM t.sign_in('$1@client.test')")"
  local ch sec
  read -r ch sec <<<"$(q -F ' ' -c "SET ROLE engramport_app" -c "SELECT challenge_id, secret FROM t.challenge('$u', '$s', '$m', 'approve')" | tail -1)"
  echo "$a $m $u $s $ch $sec"
}

# Holds $2 open in an admin or superuser transaction, then runs the decision.
race() { # first-sql user session challenge secret [role]
  local app="race_$RANDOM"
  PGAPPNAME=$app q -c "BEGIN" ${6:+-c "SET ROLE $6"} -c "$1" -c "SELECT pg_sleep(3)" -c "COMMIT" >/dev/null &
  local first=$!
  until [ "$(q -c "SELECT count(*) FROM pg_stat_activity WHERE application_name = '$app' AND query LIKE '%pg_sleep%'")" = 1 ]; do
    sleep 0.1
  done
  local out rc=0
  out=$(q -c "SET ROLE engramport_app" -c "SELECT memory.decide_approval_challenge('$2', '$3', '$4', '$5')" 2>&1) || rc=$?
  wait "$first"
  echo "$rc $out"
}

read -r a m u s ch sec <<<"$(setup race-revoked)"
got=$(race "UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'owner_left' WHERE id = '$a'" \
           "$u" "$s" "$ch" "$sec" engramport_admin)
case "$got" in
  [1-9]*"no longer valid"*) echo "pass a decision racing a revocation waits for it and is refused" ;;
  *) echo "FAIL a decision racing a revocation went through: $got"; exit 1 ;;
esac
[ "$(q -c "SELECT count(*) FROM memory.approvals WHERE memory_id = '$m'")" = 0 ] || { echo "FAIL an approval was recorded"; exit 1; }

read -r a m u s ch sec <<<"$(setup race-disabled)"
got=$(race "UPDATE memory.actors SET disabled_at = now() WHERE slug = 'race-disabled'" "$u" "$s" "$ch" "$sec")
case "$got" in
  [1-9]*"no longer valid"*|[1-9]*"not one enabled person"*) echo "pass a decision racing a disabled approver is refused" ;;
  *) echo "FAIL a decision racing a disabled approver went through: $got"; exit 1 ;;
esac
[ "$(q -c "SELECT count(*) FROM memory.approvals WHERE memory_id = '$m'")" = 0 ] || { echo "FAIL an approval was recorded"; exit 1; }
