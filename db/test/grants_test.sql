-- Tests for 0024_data_grants (founder decision D-02, item 2 and D-02.4): an
-- owner gives one person the power to erase in or export one namespace, that
-- person accepts it with their own sign-in, and it counts only while it holds.
-- Run by db/test/run.sh after export_test.sql, on the fixtures and helpers of
-- rls_test, authority_test, challenge_test, revision_test and erasure_test.
\set ON_ERROR_STOP on
\set QUIET on
\set c1    '00000000-0000-7000-8000-000000000111'
\set c2    '00000000-0000-7000-8000-000000000112'
\set k_c1  '00000000-0000-7000-8000-0000000000f1'

SELECT id AS owner FROM memory.actors WHERE slug = 'er-owner' \gset
SELECT id AS a_owner FROM memory.approval_authorities WHERE actor_id = :'owner' AND parent_id IS NULL \gset
SELECT id AS obs FROM memory.actors WHERE slug = 'er-obs' \gset
SELECT id AS c2owner FROM memory.actors WHERE slug = 'er-c2' \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'gr-helper', 'Helper') RETURNING id AS helper \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', 'gr-bot', 'Bot') RETURNING id AS bot \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ('gr-helper@client.test', :'c1', :'helper');

-- Fresh sign-ins taken ahead of a statement, by name, so the statement can use them.
CREATE TABLE t.sg (k text PRIMARY KEY, u uuid NOT NULL, s uuid NOT NULL);
GRANT SELECT ON t.sg TO engramport_app;

\echo '-- giving a grant'
SELECT * FROM t.sign_in('er-owner@client.test') \gset g1_
SELECT * FROM t.sign_in('er-owner@client.test') \gset g2_
SELECT * FROM t.sign_in('er-owner@client.test') \gset g3_
SELECT * FROM t.sign_in('er-owner@client.test') \gset g4_
SELECT * FROM t.sign_in('er-owner@client.test') \gset g5_
SELECT * FROM t.sign_in('er-owner@client.test') \gset g6_
SELECT * FROM t.sign_in('er-obs@client.test') \gset ob_
SELECT * FROM t.sign_in('er-del@client.test') \gset dl_
SET ROLE engramport_app;
SELECT t.expect_error('a grant ends within 90 days',
  format($$SELECT memory.grant_data_power(%L, %L, %L, %L, 'erase', now() + interval '91 days')$$,
         :'g1_user_id', :'g1_session_id', :'c1', :'helper'), '%within 90 days%');
SELECT t.expect_error('and has an end',
  format($$SELECT memory.grant_data_power(%L, %L, %L, %L, 'erase', NULL)$$,
         :'g1_user_id', :'g1_session_id', :'c1', :'helper'), '%within 90 days%');
SELECT t.expect_error('not to oneself',
  format($$SELECT memory.grant_data_power(%L, %L, %L, %L, 'erase', now() + interval '30 days')$$,
         :'g1_user_id', :'g1_session_id', :'c1', :'owner'), '%another enabled person%');
RESET ROLE;
SELECT * FROM t.sign_in('er-owner@client.test') \gset g1_
SET ROLE engramport_app;
SELECT t.expect_error('not to an agent',
  format($$SELECT memory.grant_data_power(%L, %L, %L, %L, 'erase', now() + interval '30 days')$$,
         :'g1_user_id', :'g1_session_id', :'c1', :'bot'), '%another enabled person%');
RESET ROLE;
SELECT * FROM t.sign_in('er-owner@client.test') \gset g1_
SET ROLE engramport_app;
SELECT t.expect_error('not to someone outside the namespace',
  format($$SELECT memory.grant_data_power(%L, %L, %L, %L, 'erase', now() + interval '30 days')$$,
         :'g1_user_id', :'g1_session_id', :'c1', :'c2owner'), '%member of this namespace%');
SELECT t.expect_error('an owner whose grant is limited and can''t delegate gives nothing',
  format($$SELECT memory.grant_data_power(%L, %L, %L, %L, 'erase', now() + interval '30 days')$$,
         :'ob_user_id', :'ob_session_id', :'c1', :'helper'), '%may delegate%');
SELECT t.expect_error('nor does an approval delegate',
  format($$SELECT memory.grant_data_power(%L, %L, %L, %L, 'erase', now() + interval '30 days')$$,
         :'dl_user_id', :'dl_session_id', :'c1', :'helper'), '%may delegate%');
RESET ROLE;
SELECT * FROM t.sign_in('er-owner@client.test') \gset g1_
SET ROLE engramport_app;
SELECT t.expect_error('nor over another namespace',
  format($$SELECT memory.grant_data_power(%L, %L, %L, %L, 'erase', now() + interval '30 days')$$,
         :'g1_user_id', :'g1_session_id', :'c2', :'helper'), '%may delegate%');
RESET ROLE;
SELECT * FROM t.sign_in('er-owner@client.test') \gset g1_
SET ROLE engramport_app;
SELECT memory.grant_data_power(:'g1_user_id', :'g1_session_id', :'c1', :'helper', 'erase', now() + interval '30 days')
  AS erase_grant \gset
RESET ROLE;
SELECT t.expect_count('the grant rests on the owner''s authority, waiting for the helper',
  format($$SELECT 1 FROM memory.data_grants WHERE id = %L AND parent_authority_id = %L AND granted_by_actor_id = %L
             AND accepted_at IS NULL AND NOT memory.data_grant_valid(id)$$, :'erase_grant', :'a_owner', :'owner'), 1);
SELECT t.expect_count('the owner''s sign-in was spent for granting',
  format($$SELECT 1 FROM memory.human_sign_ins_used WHERE session_hash = sha256(uuid_send(%L::uuid)) AND purpose = 'grant'$$,
         :'g1_session_id'), 1);

\echo '-- nothing counts until the helper accepts it'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('note', 'grant check: erase me under a grant', 'remember', 'rest') AS gm \gset
  SELECT memory.request_erasure(ARRAY[:'gm']::uuid[], 'owner_request') AS greq \gset
COMMIT;
RESET ROLE; INSERT INTO t.sg SELECT 'sg1', user_id, session_id FROM t.sign_in('gr-helper@client.test');
SET ROLE engramport_app;
SELECT t.expect_error('the helper can''t review before accepting',
  format($$SELECT r.* FROM (SELECT u, s FROM t.sg WHERE k = 'sg1') x, LATERAL memory.erasure_review(x.u, x.s, %L) r$$, :'greq'),
  '%no authority%');
RESET ROLE;
SELECT * FROM t.sign_in('gr-helper@client.test') \gset h1_
SET ROLE engramport_app;
SELECT t.expect_count('the helper sees what is offered, with its fingerprint',
  format($$SELECT 1 FROM memory.pending_data_grants(%L, %L) WHERE grant_id = %L AND power = 'erase'
             AND granted_by = 'er-owner' AND grant_sha256 ~ '^[0-9a-f]{64}$'$$, :'h1_user_id', :'h1_session_id', :'erase_grant'), 1);
SELECT grant_sha256 AS erase_sha FROM memory.pending_data_grants(:'h1_user_id', :'h1_session_id') WHERE grant_id = :'erase_grant' \gset
RESET ROLE; INSERT INTO t.sg SELECT 'sg2', user_id, session_id FROM t.sign_in('er-del@client.test');
SET ROLE engramport_app;
SELECT t.expect_count('nobody else is offered it',
  format($$SELECT 1 FROM (SELECT u, s FROM t.sg WHERE k = 'sg2') x, LATERAL memory.pending_data_grants(x.u, x.s) p WHERE p.grant_id = %L$$, :'erase_grant'), 0);
RESET ROLE; INSERT INTO t.sg SELECT 'sg3', user_id, session_id FROM t.sign_in('er-del@client.test');
SET ROLE engramport_app;
SELECT t.expect_error('someone else can''t accept it',
  format($$SELECT memory.decide_data_grant(u, s, %L, 'accept', %L) FROM (SELECT u, s FROM t.sg WHERE k = 'sg3')$$, :'erase_grant', :'erase_sha'),
  '%no such grant was offered%');
SELECT t.expect_error('the helper accepts only the terms they were shown',
  format($$SELECT memory.decide_data_grant(%L, %L, %L, 'accept', %L)$$, :'h1_user_id', :'h1_session_id', :'erase_grant', repeat('0', 64)),
  '%not the grant you were shown%');
RESET ROLE;
SELECT * FROM t.sign_in('gr-helper@client.test') \gset h1_
SET ROLE engramport_app;
SELECT memory.decide_data_grant(:'h1_user_id', :'h1_session_id', :'erase_grant', 'accept', :'erase_sha');
RESET ROLE; INSERT INTO t.sg SELECT 'sg4', user_id, session_id FROM t.sign_in('gr-helper@client.test');
SET ROLE engramport_app;
SELECT t.expect_error('a grant is decided once',
  format($$SELECT memory.decide_data_grant(u, s, %L, 'reject', %L) FROM (SELECT u, s FROM t.sg WHERE k = 'sg4')$$, :'erase_grant', :'erase_sha'),
  '%already decided%');
RESET ROLE;
SELECT t.expect_count('accepted, it counts',
  format($$SELECT 1 FROM memory.data_grants WHERE id = %L AND accepted_at IS NOT NULL AND memory.data_grant_valid(id)$$, :'erase_grant'), 1);

\echo '-- the helper erases under the grant, and the record says so'
SELECT * FROM t.sign_in('gr-helper@client.test') \gset h2_
SET ROLE engramport_app;
SELECT t.erase(:'h2_user_id', :'h2_session_id', :'greq') ->> 'versions' AS gv \gset
RESET ROLE;
SELECT t.expect_count('erased, decided by the helper, on the owner''s authority, under the grant',
  format($$SELECT 1 FROM memory.erasure_requests r JOIN memory.erasure_challenges c ON c.id = r.challenge_id
           WHERE r.id = %L AND r.state = 'completed' AND r.decided_by_actor_id = %L AND r.authority_id = %L
             AND r.grant_id = %L AND c.grant_id = %L$$, :'greq', :'helper', :'a_owner', :'erase_grant', :'erase_grant'), 1);
SELECT t.expect_state('the memory is erased', :'gm', 'erased/none');

\echo '-- an erase grant is not an export grant'
SET ROLE engramport_app;
RESET ROLE; INSERT INTO t.sg SELECT 'sg5', user_id, session_id FROM t.sign_in('gr-helper@client.test');
SET ROLE engramport_app;
SELECT t.expect_count('the helper is offered nothing to export',
  $$SELECT 1 FROM (SELECT u, s FROM t.sg WHERE k = 'sg5') x, LATERAL memory.export_namespaces(x.u, x.s) n$$, 0);
RESET ROLE;
SELECT * FROM t.sign_in('er-owner@client.test') \gset g2_
SET ROLE engramport_app;
SELECT memory.grant_data_power(:'g2_user_id', :'g2_session_id', :'c1', :'helper', 'export', now() + interval '7 days')
  AS export_grant \gset
RESET ROLE; INSERT INTO t.sg SELECT 'sg6', user_id, session_id FROM t.sign_in('gr-helper@client.test');
SET ROLE engramport_app;
SELECT p.grant_sha256 AS export_sha
  FROM (SELECT u, s FROM t.sg WHERE k = 'sg6') x, LATERAL memory.pending_data_grants(x.u, x.s) p WHERE p.grant_id = :'export_grant' \gset
RESET ROLE; INSERT INTO t.sg SELECT 'sg7', user_id, session_id FROM t.sign_in('gr-helper@client.test');
SET ROLE engramport_app;
SELECT memory.decide_data_grant(u, s, :'export_grant', 'accept', :'export_sha') FROM (SELECT u, s FROM t.sg WHERE k = 'sg7');
RESET ROLE;

\echo '-- the helper exports under the export grant'
SELECT * FROM t.sign_in('gr-helper@client.test') \gset h3_
SET ROLE engramport_app;
SELECT t.expect_count('the helper is offered this namespace only',
  format($$SELECT 1 FROM memory.export_namespaces(%L, %L) WHERE namespace_id = %L$$, :'h3_user_id', :'h3_session_id', :'c1'), 1);
SELECT * FROM memory.issue_export_challenge(:'h3_user_id', :'h3_session_id', :'c1') \gset hx_
SELECT memory.start_export(:'h3_user_id', :'h3_session_id', :'hx_export_id', :'hx_secret');
SELECT t.expect_count('the rows stream',
  format($$SELECT 1 FROM memory.export_rows(%L, %L, %L) r WHERE r ->> 'type' = 'export' AND r ->> 'exported_by' = 'gr-helper'$$,
         :'h3_session_id', :'hx_export_id', :'hx_secret'), 1);
RESET ROLE;
SELECT t.expect_count('the export records the grant and the owner''s authority',
  format($$SELECT 1 FROM memory.exports WHERE id = %L AND grant_id = %L AND authority_id = %L AND completed_at IS NOT NULL$$,
         :'hx_export_id', :'export_grant', :'a_owner'), 1);

\echo '-- a revoked grant stops at once, even mid-decision'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('note', 'grant check: survives a revocation', 'remember', 'rest') AS gm2 \gset
  SELECT memory.request_erasure(ARRAY[:'gm2']::uuid[], 'owner_request') AS greq2 \gset
COMMIT;
RESET ROLE;
SELECT * FROM t.sign_in('gr-helper@client.test') \gset h4_
SET ROLE engramport_app;
RESET ROLE; INSERT INTO t.sg SELECT 'sg8', user_id, session_id FROM t.sign_in('gr-helper@client.test');
SET ROLE engramport_app;
SELECT * FROM t.erase_challenge(:'h4_user_id', :'h4_session_id', :'greq2') \gset hc_
SELECT t.expect_error('the helper can''t revoke it',
  format($$SELECT memory.revoke_data_grant(u, s, %L, 'not_needed') FROM (SELECT u, s FROM t.sg WHERE k = 'sg8')$$, :'erase_grant'),
  '%that you may revoke%');
RESET ROLE; INSERT INTO t.sg SELECT 'sg9', user_id, session_id FROM t.sign_in('er-owner@client.test');
SET ROLE engramport_app;
SELECT t.expect_error('a revocation gives a reason code',
  format($$SELECT memory.revoke_data_grant(u, s, %L, 'Because!') FROM (SELECT u, s FROM t.sg WHERE k = 'sg9')$$, :'erase_grant'),
  '%reason code%');
RESET ROLE; INSERT INTO t.sg SELECT 'sg10', user_id, session_id FROM t.sign_in('er-owner@client.test');
SET ROLE engramport_app;
SELECT memory.revoke_data_grant(u, s, :'erase_grant', 'no_longer_needed') FROM (SELECT u, s FROM t.sg WHERE k = 'sg10');
SELECT t.expect_error('the challenge taken before the revocation',
  format($$SELECT memory.decide_erasure_challenge(%L, %L, %L, %L)$$, :'h4_user_id', :'h4_session_id', :'hc_challenge_id', :'hc_secret'),
  '%no longer valid%');
RESET ROLE; INSERT INTO t.sg SELECT 'sg11', user_id, session_id FROM t.sign_in('gr-helper@client.test');
SET ROLE engramport_app;
SELECT t.expect_error('and a new review',
  format($$SELECT r.* FROM (SELECT u, s FROM t.sg WHERE k = 'sg11') x, LATERAL memory.erasure_review(x.u, x.s, %L) r$$, :'greq2'), '%no authority%');
RESET ROLE; INSERT INTO t.sg SELECT 'sg12', user_id, session_id FROM t.sign_in('er-owner@client.test');
SET ROLE engramport_app;
SELECT t.expect_error('a grant is revoked once',
  format($$SELECT memory.revoke_data_grant(u, s, %L, 'again') FROM (SELECT u, s FROM t.sg WHERE k = 'sg12')$$, :'erase_grant'),
  '%already revoked%');
RESET ROLE;
SELECT t.expect_state('the memory is untouched', :'gm2', 'active/none');
SELECT t.expect_count('the revocation records who, when and why',
  format($$SELECT 1 FROM memory.data_grants WHERE id = %L AND revoked_by_actor_id = %L AND revoke_reason = 'no_longer_needed'$$,
         :'erase_grant', :'owner'), 1);

\echo '-- a grant stops counting when the owner''s own authority goes'
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'gr-owner2', 'Second owner') RETURNING id AS o2 \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ('gr-owner2@client.test', :'c1', :'o2');
SET ROLE engramport_admin;
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, can_delegate)
  VALUES (:'o2', :'c1', 'cell_knowledge', true) RETURNING id AS a_o2 \gset
RESET ROLE;
SELECT t.accept(:'a_o2', 'gr-owner2@client.test');
SET ROLE engramport_app;
RESET ROLE; INSERT INTO t.sg SELECT 'sg13', user_id, session_id FROM t.sign_in('gr-owner2@client.test');
SET ROLE engramport_app;
SELECT memory.grant_data_power(u, s, :'c1', :'helper', 'erase', now() + interval '3 days') AS g_o2
  FROM (SELECT u, s FROM t.sg WHERE k = 'sg13') \gset
RESET ROLE; INSERT INTO t.sg SELECT 'sg14', user_id, session_id FROM t.sign_in('gr-helper@client.test');
SET ROLE engramport_app;
SELECT p.grant_sha256 AS g_o2_sha
  FROM (SELECT u, s FROM t.sg WHERE k = 'sg14') x, LATERAL memory.pending_data_grants(x.u, x.s) p WHERE p.grant_id = :'g_o2' \gset
RESET ROLE; INSERT INTO t.sg SELECT 'sg15', user_id, session_id FROM t.sign_in('gr-helper@client.test');
SET ROLE engramport_app;
SELECT memory.decide_data_grant(u, s, :'g_o2', 'accept', :'g_o2_sha') FROM (SELECT u, s FROM t.sg WHERE k = 'sg15');
RESET ROLE;
SELECT t.expect_count('it counts while the second owner does',
  format($$SELECT 1 FROM memory.data_grants WHERE id = %L AND memory.data_grant_valid(id)$$, :'g_o2'), 1);
SET ROLE engramport_admin;
UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'owner_left' WHERE id = :'a_o2';
RESET ROLE;
SELECT t.expect_count('and stops when their authority is revoked',
  format($$SELECT 1 FROM memory.data_grants WHERE id = %L AND NOT memory.data_grant_valid(id)$$, :'g_o2'), 1);

\echo '-- a grant stops counting when its holder leaves the namespace, or it expires'
UPDATE memory.oauth_members SET revoked_at = now() WHERE actor_id = :'helper' AND namespace_id = :'c1';
SELECT t.expect_count('the export grant no longer counts for someone no longer a member',
  format($$SELECT 1 FROM memory.data_grants WHERE id = %L AND NOT memory.data_grant_valid(id)$$, :'export_grant'), 1);
INSERT INTO memory.data_grants (namespace_id, power, actor_id, granted_by_actor_id, parent_authority_id, created_at, expires_at,
    accepted_at, decision_sign_in_hash)
  VALUES (:'c1', 'export', :'helper', :'owner', :'a_owner', now() - interval '40 days', now() - interval '1 day',
          now() - interval '39 days', sha256('x'::bytea)) RETURNING id AS old_grant \gset
SELECT t.expect_count('an expired grant counts for nothing',
  format($$SELECT 1 FROM memory.data_grants WHERE id = %L AND NOT memory.data_grant_valid(id)$$, :'old_grant'), 1);

\echo '-- grants are records; the admin sees and revokes them, nothing more'
SELECT t.expect_denied('terms never change',
  format($$UPDATE memory.data_grants SET power = 'erase' WHERE id = %L$$, :'export_grant'));
SELECT t.expect_denied('nor the end date',
  format($$UPDATE memory.data_grants SET expires_at = now() + interval '80 days' WHERE id = %L$$, :'export_grant'));
SELECT t.expect_denied('a grant can''t be accepted by hand',
  format($$UPDATE memory.data_grants SET accepted_at = now(), decision_sign_in_hash = sha256('y'::bytea) WHERE id = %L$$, :'g_o2'));
SELECT t.expect_denied('or deleted', format($$DELETE FROM memory.data_grants WHERE id = %L$$, :'export_grant'));
SET ROLE engramport_app;
SELECT t.expect_denied('the app can''t read grants', 'SELECT 1 FROM memory.data_grants');
SELECT t.expect_denied('or write one',
  format($$INSERT INTO memory.data_grants (namespace_id, power, actor_id, granted_by_actor_id, parent_authority_id, expires_at)
           VALUES (%L, 'erase', %L, %L, %L, now() + interval '1 day')$$, :'c1', :'helper', :'owner', :'a_owner'));
RESET ROLE;
SET ROLE engramport_admin;
SELECT t.expect_count('the admin sees every grant and whether it counts',
  format($$SELECT 1 FROM memory.data_grants WHERE id IN (%L, %L) AND memory.data_grant_valid(id) IS NOT NULL$$,
         :'erase_grant', :'export_grant'), 2);
SELECT t.expect_denied('not the sign-in a decision used', 'SELECT decision_sign_in_hash FROM memory.data_grants');
SELECT t.expect_denied('the admin can''t accept a grant',
  format($$UPDATE memory.data_grants SET accepted_at = now() WHERE id = %L$$, :'g_o2'));
SELECT t.expect_rows('the admin revokes one',
  format($$UPDATE memory.data_grants SET revoked_at = now(), revoke_reason = 'audit_finding' WHERE id = %L$$, :'export_grant'), 1);
SELECT t.expect_denied('and the admin cannot grant',
  format($$SELECT memory.grant_data_power(gen_random_uuid(), gen_random_uuid(), %L, %L, 'erase', now() + interval '1 day')$$,
         :'c1', :'helper'));
RESET ROLE;
SELECT t.expect_count('the admin''s revocation names no person',
  format($$SELECT 1 FROM memory.data_grants WHERE id = %L AND revoked_at IS NOT NULL AND revoked_by_actor_id IS NULL
             AND NOT memory.data_grant_valid(id)$$, :'export_grant'), 1);
SELECT t.expect_count('no API role reaches any grant function',
  $$SELECT 1 FROM pg_roles r CROSS JOIN pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE r.rolname IN ('anon', 'authenticated', 'service_role') AND n.nspname = 'memory'
      AND p.proname LIKE '%grant%' AND has_function_privilege(r.oid, p.oid, 'EXECUTE')$$, 0);

\echo 'all grant tests passed'
