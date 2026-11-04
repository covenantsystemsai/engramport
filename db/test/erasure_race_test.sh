#!/usr/bin/env bash
# Erasure racing other work on the same memory. Each case holds one side open
# while the other runs, and checks that the second waits and then does the
# right thing: nothing is indexed into an erased memory, an index written first
# is erased with it, a revision approved first is erased with it, a revision
# proposed during it is refused, and a revocation made first stops it.
# Run by run.sh after erasure_test.sql, whose fixtures and helpers it reuses.
set -euo pipefail
: "${DATABASE_URL:?set DATABASE_URL to a throwaway database}"
q() { psql "$DATABASE_URL" -X -q -tA -v ON_ERROR_STOP=1 "$@"; }

c1=00000000-0000-7000-8000-000000000111
k_c1=00000000-0000-7000-8000-0000000000f1

signin() { q -F ' ' -c "SELECT user_id, session_id FROM t.sign_in('${1:-er-owner@client.test}')"; }
as_agent() { q -c "SET ROLE engramport_app" -c "BEGIN" -c "SELECT t.as_key('$k_c1', '$c1')" -c "$1" -c "COMMIT" | grep -E '^[0-9a-f-]{36}$'; }
remember() { as_agent "SELECT memory.remember('fact', 'erasure race: $1', 'remember', 'rest', p_claim_type => 'fact')"; }
request() { as_agent "SELECT memory.request_erasure(ARRAY['$1']::uuid[], 'owner_request')"; }
# A challenge for the request, from a fresh sign-in: "user session challenge secret".
confirm() {
  local u s
  read -r u s <<<"$(signin "${2:-}")"
  echo "$u $s $(q -F ' ' -c "SET ROLE engramport_app" -c "SELECT challenge_id, secret FROM t.erase_challenge('$u', '$s', '$1')" | tail -1)"
}
decide_sql() { echo "SELECT memory.decide_erasure_challenge('$1', '$2', '$3', '$4')"; }
# Run SQL in the background inside a transaction held open for 3 seconds, and
# return once it is sleeping.
hold() {
  local app="race_$RANDOM"
  PGAPPNAME=$app q -c "BEGIN" -c "SET ROLE engramport_app" "$@" -c "SELECT pg_sleep(3)" -c "COMMIT" >/dev/null &
  held=$!
  until [ "$(q -c "SELECT count(*) FROM pg_stat_activity WHERE application_name = '$app' AND query LIKE '%pg_sleep%'")" = 1 ]; do
    sleep 0.1
  done
}
state() { q -c "SELECT status FROM memory.memories WHERE id = '$1'"; }
embeddings() { q -c "SELECT count(*) FROM memory.memory_embeddings WHERE memory_id = '$1'"; }
expect() { [ "$2" = "$3" ] || { echo "FAIL $1: wanted $3, got $2"; exit 1; }; echo "pass $1"; }

echo '-- indexing that starts during an erasure waits for it, then is refused'
m=$(remember "indexed too late"); r=$(request "$m"); read -r u s ch sec <<<"$(confirm "$r")"
hold -c "$(decide_sql "$u" "$s" "$ch" "$sec")"
rc=0
out=$(q -c "SET ROLE engramport_app" -c "BEGIN" -c "SELECT t.as_key('$k_c1', '$c1')" -c "SELECT t.embed('$m')" -c "COMMIT" 2>&1) || rc=$?
wait "$held"
case "$rc $out" in
  [1-9]*"was erased"*) echo "pass the late embedding is refused" ;;
  *) echo "FAIL a late embedding: $rc $out"; exit 1 ;;
esac
expect "the memory is erased" "$(state "$m")" erased
expect "and has no embedding" "$(embeddings "$m")" 0

echo '-- indexing that started first is erased with the memory'
m=$(remember "indexed just before"); r=$(request "$m"); read -r u s ch sec <<<"$(confirm "$r")"
hold -c "SELECT t.as_key('$k_c1', '$c1')" -c "SELECT t.embed('$m')"
q -c "SET ROLE engramport_app" -c "$(decide_sql "$u" "$s" "$ch" "$sec")" >/dev/null
wait "$held"
expect "the memory is erased" "$(state "$m")" erased
expect "and the embedding written first is gone" "$(embeddings "$m")" 0
expect "the erasure was verified" "$(q -c "SELECT evidence ->> 'verified' FROM memory.erasure_requests WHERE id = '$r'")" true

echo '-- a revision approved first is erased with the memory'
m=$(remember "approved then revised"); read -r u s <<<"$(signin)"
q -c "SET ROLE engramport_app" -c "SELECT t.decide('$u', '$s', '$m', 'approve')" >/dev/null
p=$(as_agent "SELECT memory.propose_revision('$m', 'fact', 'erasure race: the revision', 'supersede_memory', 'rest', 'fact')")
r=$(request "$m"); read -r eu es ech esec <<<"$(confirm "$r")"
read -r u s <<<"$(signin)"
read -r ach asec <<<"$(q -F ' ' -c "SET ROLE engramport_app" -c "SELECT challenge_id, secret FROM t.challenge('$u', '$s', '$p', 'approve')" | tail -1)"
hold -c "SELECT memory.decide_approval_challenge('$u', '$s', '$ach', '$asec')"
q -c "SET ROLE engramport_app" -c "$(decide_sql "$eu" "$es" "$ech" "$esec")" >/dev/null
wait "$held"
expect "the version it named is erased" "$(state "$m")" erased
expect "and so is the revision approved while it waited" "$(state "$p")" erased
expect "with a tombstone each" "$(q -c "SELECT count(*) FROM memory.erasures WHERE request_id = '$r'")" 2

echo '-- a revision proposed just before is erased too'
m=$(remember "revised just before"); read -r u s <<<"$(signin)"
q -c "SET ROLE engramport_app" -c "SELECT t.decide('$u', '$s', '$m', 'approve')" >/dev/null
r=$(request "$m"); read -r u s ch sec <<<"$(confirm "$r")"
hold -c "SELECT t.as_key('$k_c1', '$c1')" \
  -c "SELECT memory.propose_revision('$m', 'fact', 'erasure race: proposed just before', 'supersede_memory', 'rest', 'fact')"
q -c "SET ROLE engramport_app" -c "$(decide_sql "$u" "$s" "$ch" "$sec")" >/dev/null
wait "$held"
expect "the version it named is erased" "$(state "$m")" erased
expect "and so is the revision that arrived while it waited" \
  "$(q -c "SELECT string_agg(status::text, ',') FROM memory.memories WHERE supersedes_id = '$m'")" erased
expect "nothing of either text is left" "$(q -c "SELECT count(*) FROM memory.memories WHERE content LIKE 'erasure race: %just before'")" 0

echo '-- a revision proposed during an erasure waits for it, then is refused'
m=$(remember "revised too late"); read -r u s <<<"$(signin)"
q -c "SET ROLE engramport_app" -c "SELECT t.decide('$u', '$s', '$m', 'approve')" >/dev/null
r=$(request "$m"); read -r u s ch sec <<<"$(confirm "$r")"
hold -c "$(decide_sql "$u" "$s" "$ch" "$sec")"
rc=0
out=$(q -c "SET ROLE engramport_app" -c "BEGIN" -c "SELECT t.as_key('$k_c1', '$c1')" \
        -c "SELECT memory.propose_revision('$m', 'fact', 'erasure race: too late', 'supersede_memory', 'rest', 'fact')" -c "COMMIT" 2>&1) || rc=$?
wait "$held"
[ "$rc" != 0 ] || { echo "FAIL a revision was proposed for an erased memory: $out"; exit 1; }
echo "pass the late revision is refused"
expect "nothing follows the erased memory" "$(q -c "SELECT count(*) FROM memory.memories WHERE supersedes_id = '$m'")" 0

echo '-- a revocation made first stops the erasure'
q -c "INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'er-race', 'Race owner')" \
  -c "INSERT INTO memory.oauth_members (email, namespace_id, actor_id) SELECT 'er-race@client.test', '$c1', id FROM memory.actors WHERE slug = 'er-race'" >/dev/null
a=$(q -c "SET ROLE engramport_admin" -c "INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope) SELECT id, '$c1', 'cell_knowledge' FROM memory.actors WHERE slug = 'er-race' RETURNING id" | grep -E '^[0-9a-f-]{36}$')
q -c "SELECT t.accept('$a', 'er-race@client.test')" >/dev/null
m=$(remember "revoked while deciding"); r=$(request "$m"); read -r u s ch sec <<<"$(confirm "$r" er-race@client.test)"
app="race_$RANDOM"
PGAPPNAME=$app q -c "BEGIN" -c "SET ROLE engramport_admin" \
  -c "UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'owner_left' WHERE id = '$a'" \
  -c "SELECT pg_sleep(3)" -c "COMMIT" >/dev/null &
held=$!
until [ "$(q -c "SELECT count(*) FROM pg_stat_activity WHERE application_name = '$app' AND query LIKE '%pg_sleep%'")" = 1 ]; do
  sleep 0.1
done
rc=0
out=$(q -c "SET ROLE engramport_app" -c "$(decide_sql "$u" "$s" "$ch" "$sec")" 2>&1) || rc=$?
wait "$held"
case "$rc $out" in
  [1-9]*"no longer valid"*) echo "pass the erasure racing a revocation waits for it and is refused" ;;
  *) echo "FAIL an erasure went through under a revoked owner: $rc $out"; exit 1 ;;
esac
expect "the memory is untouched" "$(state "$m")" active
