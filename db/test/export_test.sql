-- Tests for 0023_export (founder decision D-02.4): a person with an owner's
-- grant exports a namespace with their own sign-in; nothing is stored. Run by
-- db/test/run.sh after erasure_race_test.sh, on the fixtures and helpers of
-- rls_test, authority_test, challenge_test and erasure_test.
\set ON_ERROR_STOP on
\set QUIET on
\set c1    '00000000-0000-7000-8000-000000000111'
\set c2    '00000000-0000-7000-8000-000000000112'
\set k_c1  '00000000-0000-7000-8000-0000000000f1'

SELECT id AS owner FROM memory.actors WHERE slug = 'er-owner' \gset
SELECT id AS a_owner FROM memory.approval_authorities WHERE actor_id = :'owner' AND parent_id IS NULL \gset
SELECT * FROM t.sign_in('er-owner@client.test') \gset x1_
SELECT * FROM t.sign_in('er-owner@client.test') \gset x2_
SELECT * FROM t.sign_in('er-owner@client.test') \gset x3_
SELECT * FROM t.sign_in('er-owner@client.test') \gset x4_
SELECT * FROM t.sign_in('er-owner@client.test') \gset x5_
SELECT * FROM t.sign_in('er-del@client.test') \gset d1_
SELECT * FROM t.sign_in('er-obs@client.test') \gset b1_
SELECT * FROM t.sign_in('er-c2@client.test') \gset q1_

\echo '-- who may export what'
SET ROLE engramport_app;
SELECT t.expect_count('the owner is offered their own cell, and nothing else',
  format($$SELECT 1 FROM memory.export_namespaces(%L, %L) WHERE namespace_id = %L$$, :'x1_user_id', :'x1_session_id', :'c1'), 1);
SELECT t.expect_count('and only that',
  format($$SELECT 1 FROM memory.export_namespaces(%L, %L)$$, :'x1_user_id', :'x1_session_id'), 1);
SELECT t.expect_count('a delegate is offered nothing',
  format($$SELECT 1 FROM memory.export_namespaces(%L, %L)$$, :'d1_user_id', :'d1_session_id'), 0);
SELECT t.expect_count('nor an owner whose grant covers only some claim types',
  format($$SELECT 1 FROM memory.export_namespaces(%L, %L)$$, :'b1_user_id', :'b1_session_id'), 0);
SELECT t.expect_error('the owner cannot export another cell',
  format($$SELECT * FROM memory.issue_export_challenge(%L, %L, %L)$$, :'x1_user_id', :'x1_session_id', :'c2'),
  '%no authority to export%');
SELECT t.expect_error('nor can a delegate export this one',
  format($$SELECT * FROM memory.issue_export_challenge(%L, %L, %L)$$, :'d1_user_id', :'d1_session_id', :'c1'),
  '%no authority to export%');
SELECT t.expect_error('and an agent has no sign-in to export with',
  format($$SELECT * FROM memory.issue_export_challenge(gen_random_uuid(), gen_random_uuid(), %L)$$, :'c1'), '%fresh Google sign-in%');
RESET ROLE;

\echo '-- the owner exports: started, then the rows, then recorded as delivered'
SET ROLE engramport_app;
SELECT * FROM memory.issue_export_challenge(:'x1_user_id', :'x1_session_id', :'c1') \gset ex_
SELECT t.expect_error('the rows need the export started first',
  format($$SELECT * FROM memory.export_rows(%L, %L, %L)$$, :'x1_session_id', :'ex_export_id', :'ex_secret'),
  '%not started%');
SELECT memory.start_export(:'x1_user_id', :'x1_session_id', :'ex_export_id', :'ex_secret');
SELECT t.expect_error('another sign-in''s session cannot stream it',
  format($$SELECT * FROM memory.export_rows(%L, %L, %L)$$, :'x2_session_id', :'ex_export_id', :'ex_secret'),
  '%no such export%');
SELECT t.expect_error('nor can a wrong secret',
  format($$SELECT * FROM memory.export_rows(%L, %L, %L)$$, :'x1_session_id', :'ex_export_id', repeat('0', 64)),
  '%no such export%');
RESET ROLE;
SELECT t.expect_count('the start is recorded on its own, not yet delivered',
  format($$SELECT 1 FROM memory.exports WHERE id = %L AND started_at IS NOT NULL AND completed_at IS NULL$$, :'ex_export_id'), 1);
SELECT t.expect_count('and the sign-in is spent for exporting',
  format($$SELECT 1 FROM memory.human_sign_ins_used WHERE session_hash = sha256(uuid_send(%L::uuid)) AND purpose = 'export'$$,
         :'x1_session_id'), 1);

-- A download that breaks off is rolled back, and can be tried again.
SET ROLE engramport_app;
BEGIN;
  SELECT count(*) > 0 FROM memory.export_rows(:'x1_session_id', :'ex_export_id', :'ex_secret');
ROLLBACK;
RESET ROLE;
SELECT t.expect_count('a broken-off download is not recorded as delivered',
  format($$SELECT 1 FROM memory.exports WHERE id = %L AND completed_at IS NULL$$, :'ex_export_id'), 1);

SET ROLE engramport_app;
CREATE TEMP TABLE got AS SELECT r FROM memory.export_rows(:'x1_session_id', :'ex_export_id', :'ex_secret') r;
RESET ROLE;
SELECT t.expect_count('the first row says what this is, for whom and how much',
  format($$SELECT 1 FROM (SELECT r FROM got LIMIT 1) h
           WHERE h.r ->> 'type' = 'export' AND h.r ->> 'format' = 'engramport-export-v1'
             AND h.r ->> 'namespace' = (SELECT path FROM memory.namespaces WHERE id = %L)
             AND h.r ->> 'exported_by' = 'er-owner'
             AND (h.r -> 'counts' ->> 'memories')::int = (SELECT count(*) FROM memory.memories WHERE namespace_id = %L)$$,
         :'c1', :'c1'), 1);
SELECT t.expect_count('every memory in the cell, every version, with who wrote it',
  format($$SELECT 1 FROM got WHERE r ->> 'type' = 'memory' AND r -> 'provenance' ->> 'written_by' IS NOT NULL$$),
  (SELECT count(*) FROM memory.memories WHERE namespace_id = :'c1'));
SELECT t.expect_count('an approved memory carries its text and approval state',
  $$SELECT 1 FROM got WHERE r ->> 'type' = 'memory' AND r ->> 'approval_state' = 'approved' AND r ->> 'content' <> ''$$,
  (SELECT count(*) FROM memory.memories WHERE namespace_id = :'c1' AND approval_state = 'approved' AND status <> 'erased'));
SELECT t.expect_count('erased memories come as tombstones with no text',
  $$SELECT 1 FROM got WHERE r ->> 'type' = 'memory' AND r ->> 'status' = 'erased' AND r ->> 'content' = ''
      AND r ->> 'content_sha256' IS NULL$$,
  (SELECT count(*) FROM memory.memories WHERE namespace_id = :'c1' AND status = 'erased'));
SELECT t.expect_count('with their erasure records',
  $$SELECT 1 FROM got WHERE r ->> 'type' = 'erasure'$$, (SELECT count(*) FROM memory.erasures WHERE namespace_id = :'c1'));
SELECT t.expect_count('the graph and the approval trail come too',
  $$SELECT DISTINCT r ->> 'type' FROM got WHERE r ->> 'type' IN ('entity', 'relation', 'mention', 'link', 'approval', 'approval_request')$$, 6);
SELECT t.expect_count('nothing from another namespace',
  format($$SELECT 1 FROM got WHERE r ->> 'type' = 'memory'
           AND (r ->> 'id')::uuid IN (SELECT id FROM memory.memories WHERE namespace_id <> %L)$$, :'c1'), 0);
SELECT t.expect_count('no embeddings, sign-in hashes or secrets',
  $$SELECT 1 FROM got WHERE r::text ~ '(embedding"|sign_in_hash|secret_sha256)'$$, 0);
SELECT t.expect_count('the export is recorded as delivered, with counts only',
  format($$SELECT 1 FROM memory.exports WHERE id = %L AND completed_at IS NOT NULL
             AND (counts ->> 'memories')::int = (SELECT count(*) FROM memory.memories WHERE namespace_id = %L)$$,
         :'ex_export_id', :'c1'), 1);
DROP TABLE got;

\echo '-- an export cannot be replayed'
SET ROLE engramport_app;
SELECT t.expect_error('the rows again',
  format($$SELECT * FROM memory.export_rows(%L, %L, %L)$$, :'x1_session_id', :'ex_export_id', :'ex_secret'),
  '%already delivered%');
SELECT t.expect_error('the start again',
  format($$SELECT memory.start_export(%L, %L, %L, %L)$$, :'x1_user_id', :'x1_session_id', :'ex_export_id', :'ex_secret'),
  '%already used%');
SELECT t.expect_error('or from a fresh sign-in',
  format($$SELECT memory.start_export(%L, %L, %L, %L)$$, :'x2_user_id', :'x2_session_id', :'ex_export_id', :'ex_secret'),
  '%no such export%');
RESET ROLE;

\echo '-- a revoked grant exports nothing, and a stale start streams nothing'
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'ex-owner', 'Export owner') RETURNING id AS xo \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ('ex-owner@client.test', :'c1', :'xo');
SET ROLE engramport_admin;
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
  VALUES (:'xo', :'c1', 'cell_knowledge') RETURNING id AS a_xo \gset
RESET ROLE;
SELECT t.accept(:'a_xo', 'ex-owner@client.test');
SELECT * FROM t.sign_in('ex-owner@client.test') \gset y1_
SET ROLE engramport_app;
SELECT * FROM memory.issue_export_challenge(:'y1_user_id', :'y1_session_id', :'c1') \gset ey_
RESET ROLE;
SET ROLE engramport_admin;
UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'owner_left' WHERE id = :'a_xo';
RESET ROLE;
SET ROLE engramport_app;
SELECT t.expect_error('the revoked owner''s export',
  format($$SELECT memory.start_export(%L, %L, %L, %L)$$, :'y1_user_id', :'y1_session_id', :'ey_export_id', :'ey_secret'),
  '%no longer valid%');
RESET ROLE;
SELECT t.expect_count('nothing started',
  format($$SELECT 1 FROM memory.exports WHERE id = %L AND started_at IS NULL$$, :'ey_export_id'), 1);
INSERT INTO memory.exports (namespace_id, actor_id, authority_id, secret_sha256, sign_in_hash, issued_at, expires_at, started_at)
  VALUES (:'c1', :'owner', :'a_owner', sha256(decode(repeat('c', 64), 'hex')), sha256(uuid_send(:'x3_session_id'::uuid)),
          now() - interval '30 minutes', now() - interval '20 minutes', now() - interval '25 minutes')
  RETURNING id AS stale \gset
SET ROLE engramport_app;
SELECT t.expect_error('rows for an export started too long ago',
  format($$SELECT * FROM memory.export_rows(%L, %L, %L)$$, :'x3_session_id', :'stale', repeat('c', 64)), '%expired%');
RESET ROLE;

\echo '-- the record is kept, and the admin sees it without content or secrets'
SELECT t.expect_denied('an export record cannot be changed',
  format($$UPDATE memory.exports SET counts = '{}' WHERE id = %L$$, :'ex_export_id'));
SELECT t.expect_denied('or deleted', format($$DELETE FROM memory.exports WHERE id = %L$$, :'ex_export_id'));
SET ROLE engramport_app;
SELECT t.expect_denied('the app cannot read export records', 'SELECT 1 FROM memory.exports');
RESET ROLE;
SET ROLE engramport_admin;
SELECT t.expect_count('the admin sees who exported what and how much',
  format($$SELECT id, namespace_id, actor_id, authority_id, issued_at, started_at, completed_at, counts
           FROM memory.exports WHERE id = %L$$, :'ex_export_id'), 1);
SELECT t.expect_denied('not the secret', 'SELECT secret_sha256 FROM memory.exports');
SELECT t.expect_denied('or the sign-in', 'SELECT sign_in_hash FROM memory.exports');
SELECT t.expect_denied('and cannot export',
  format($$SELECT * FROM memory.export_rows(%L, %L, %L)$$, :'x1_session_id', :'ex_export_id', :'ex_secret'));
RESET ROLE;
SELECT t.expect_count('no API role reaches any export function',
  $$SELECT 1 FROM pg_roles r CROSS JOIN pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE r.rolname IN ('anon', 'authenticated', 'service_role') AND n.nspname = 'memory'
      AND p.proname LIKE '%export%' AND has_function_privilege(r.oid, p.oid, 'EXECUTE')$$, 0);

\echo 'all export tests passed'
