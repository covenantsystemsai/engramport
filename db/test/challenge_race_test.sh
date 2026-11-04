#!/usr/bin/env bash
# A decision racing a revocation, or a disabled approver, must not slip
# through. The first session holds the revocation (or the disabling) open while
# the second tries to decide; the decision must wait and then be refused.
# The last cases are a challenge, then an authority, that expire while the
# decision waits on a lock.
# Run by run.sh after challenge_test.sql, whose fixtures and helpers it reuses.
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL to a throwaway database}"
q() { psql "$DATABASE_URL" -X -q -tA -v ON_ERROR_STOP=1 "$@"; }

c1=00000000-0000-7000-8000-000000000111
k_c1=00000000-0000-7000-8000-0000000000f1

# A fresh approver with an accepted authority, and a memory to decide on.
setup() { # slug [authority lifetime]
  q -c "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', '$1', 'Racing approver')" \
    -c "INSERT INTO memory.oauth_members (email, namespace_id, actor_id)
        SELECT '$1@client.test', '$c1', id FROM memory.actors WHERE slug = '$1'" >/dev/null
  local a
  a=$(q -c "SET ROLE engramport_admin" -c "INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, expires_at)
            SELECT id, '$c1', 'cell_knowledge', clock_timestamp() + interval '${2:-1 day}'
            FROM memory.actors WHERE slug = '$1' RETURNING id" | tail -1)
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

# A challenge that expires while its decision waits on a lock must be refused:
# the decision checks the wall clock again once it holds every lock.
read -r a m u s ch sec <<<"$(setup race-expiring)"
read -r u2 s2 <<<"$(q -F ' ' -c "SELECT user_id, session_id FROM t.sign_in('race-expiring@client.test')")"
late=$(q -c "INSERT INTO memory.approval_challenges (actor_id, namespace_id, memory_id, memory_version, content_sha256,
               action, authority_id, secret_sha256, sign_in_hash, expires_at)
             SELECT x.id, '$c1', mm.id, 1, mm.content_sha256, 'approve', '$a', sha256(decode(repeat('d', 64), 'hex')),
                    sha256(uuid_send('$s2'::uuid)), clock_timestamp() + interval '2 seconds'
             FROM memory.memories mm, memory.actors x WHERE mm.id = '$m' AND x.slug = 'race-expiring'
             RETURNING id")
got=$(race "SELECT 1 FROM memory.approval_authorities WHERE id = '$a' FOR UPDATE" "$u2" "$s2" "$late" "$(printf 'd%.0s' {1..64})")
case "$got" in
  [1-9]*"expired"*) echo "pass a challenge that expires while its decision waits on a lock is refused" ;;
  *) echo "FAIL a challenge that expired during a lock wait went through: $got"; exit 1 ;;
esac
[ "$(q -c "SELECT count(*) FROM memory.approvals WHERE memory_id = '$m'")" = 0 ] || { echo "FAIL an approval was recorded"; exit 1; }

# The same for an authority that expires while the decision waits on a lock.
read -r a m u s ch sec <<<"$(setup race-lapsing '6 seconds')"
got=$(race "SELECT 1 FROM memory.approval_authorities WHERE id = '$a' FOR UPDATE; SELECT pg_sleep(4)" "$u" "$s" "$ch" "$sec")
case "$got" in
  [1-9]*"no longer valid"*) echo "pass an authority that expires while its decision waits on a lock is refused" ;;
  *) echo "FAIL an authority that expired during a lock wait went through: $got"; exit 1 ;;
esac
[ "$(q -c "SELECT count(*) FROM memory.approvals WHERE memory_id = '$m'")" = 0 ] || { echo "FAIL an approval was recorded"; exit 1; }
