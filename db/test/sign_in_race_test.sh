#!/usr/bin/env bash
# One sign-in, used at the same moment to connect a client and for an authority
# act, must succeed at most once. Two sessions race on purpose: the first holds
# its use of the sign-in open while the second tries the other kind of use.
# Run by run.sh after authority_test.sql, whose fixtures it reuses.
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL to a throwaway database}"
q() { psql "$DATABASE_URL" -X -q -tA -v ON_ERROR_STOP=1 "$@"; }

authority=$(q -c "SELECT a.id FROM memory.approval_authorities a JOIN memory.actors h ON h.id = a.actor_id
                  WHERE h.slug = 'auth-other' AND a.can_delegate AND a.parent_id IS NULL
                    AND memory.approval_authority_valid(a.id) LIMIT 1")
helper=$(q -c "SELECT id FROM memory.actors WHERE slug = 'auth-helper'")
member=$(q -c "SELECT id FROM memory.oauth_members WHERE email = 'other@client.test' AND revoked_at IS NULL")
[ -n "$authority" ] && [ -n "$helper" ] && [ -n "$member" ] || { echo "FAIL sign-in race: fixtures missing"; exit 1; }

connect_sql() { # user session code-name
  echo "SELECT memory.oauth_issue_code('$1', '$2', 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', '$member',
    'https://claude.ai/api/mcp/auth_callback', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    'https://mcp.example/mcp', '{read}', sha256('$3'))"
}
delegate_sql() { echo "SELECT memory.delegate_approval_authority('$1', '$2', '$authority', '$helper') IS NOT NULL"; }

# Starts $2 in a transaction held open, waits until it is holding, runs $3 against it.
race() { # name first-sql second-sql
  local app="race_$RANDOM"
  PGAPPNAME=$app q -c "BEGIN" -c "SET ROLE engramport_app" -c "$2" -c "SELECT pg_sleep(3)" -c "COMMIT" >/dev/null &
  local first=$!
  until [ "$(q -c "SELECT count(*) FROM pg_stat_activity WHERE application_name = '$app' AND query LIKE '%pg_sleep%'")" = 1 ]; do
    sleep 0.1
  done
  local out rc=0
  out=$(q -c "SET ROLE engramport_app" -c "$3" 2>&1) || rc=$?
  wait "$first"
  echo "$rc $out"
}

read -r u s <<<"$(q -F ' ' -c "SELECT user_id, session_id FROM t.sign_in('other@client.test')")"
got=$(race one "$(delegate_sql "$u" "$s")" "$(connect_sql "$u" "$s" race-connect-1)")
[ "$got" = "0 f" ] || { echo "FAIL a sign-in being spent on a delegation still connected a client: $got"; exit 1; }
[ "$(q -c "SELECT count(*) FROM memory.oauth_codes WHERE code_hash = sha256('race-connect-1')")" = 0 ] \
  || { echo "FAIL a code was issued"; exit 1; }
echo "pass a sign-in being spent on a delegation cannot connect a client at the same moment"

read -r u s <<<"$(q -F ' ' -c "SELECT user_id, session_id FROM t.sign_in('other@client.test')")"
got=$(race two "$(connect_sql "$u" "$s" race-connect-2)" "$(delegate_sql "$u" "$s")")
case "$got" in
  [1-9]*"already used"*) echo "pass a sign-in being used to connect cannot delegate at the same moment" ;;
  *) echo "FAIL a sign-in being used to connect also delegated: $got"; exit 1 ;;
esac
