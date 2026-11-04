-- Tests for 0017_authority_acceptance (founder decision D-03A). Run by
-- db/test/run.sh after approvals_test.sql, on the rls_test namespaces and the
-- helpers from authority_test (t.sign_in, t.accept).
\set ON_ERROR_STOP on
\set QUIET on
\set c1   '00000000-0000-7000-8000-000000000111'
\set agent '00000000-0000-7000-8000-00000000a001'

INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'acc-owner', 'Accepting owner') RETURNING id AS owner \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'acc-staff', 'Accepting staff') RETURNING id AS staff \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'acc-other', 'Someone else') RETURNING id AS other \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES
  ('acc-owner@client.test', :'c1', :'owner'),
  ('acc-staff@client.test', :'c1', :'staff'),
  ('acc-other@client.test', :'c1', :'other'),
  ('acc-agent@client.test', :'c1', :'agent');

\echo '-- a grant is only an offer until its holder accepts it'
SET ROLE engramport_admin;
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, claim_types, can_delegate, expires_at)
  VALUES (:'owner', :'c1', 'cell_knowledge', '{decision,fact}', true, now() + interval '30 days') RETURNING id AS g_main \gset
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, claim_types, expires_at)
  VALUES (:'owner', :'c1', 'cell_knowledge', '{decision}', now() + interval '30 days') RETURNING id AS g_reject \gset
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
  VALUES (:'owner', :'c1', 'cell_knowledge') RETURNING id AS g_revoked \gset
SELECT t.expect_count('the admin sees a new grant as not valid',
  format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'g_main'), 0);
UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'offered_in_error' WHERE id = :'g_revoked';
RESET ROLE;
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, created_at, expires_at)
  VALUES (:'owner', :'c1', 'cell_knowledge', now() - interval '2 days', now() - interval '1 day') RETURNING id AS g_expired \gset

SELECT * FROM t.sign_in('acc-owner@client.test') \gset o1_
SELECT * FROM t.sign_in('acc-owner@client.test') \gset o2_
SELECT * FROM t.sign_in('acc-owner@client.test') \gset o3_
SELECT * FROM t.sign_in('acc-owner@client.test') \gset o4_
SELECT * FROM t.sign_in('acc-owner@client.test') \gset o5_
SELECT * FROM t.sign_in('acc-owner@client.test') \gset o6_
SELECT * FROM t.sign_in('acc-other@client.test') \gset x1_
SELECT * FROM t.sign_in('acc-agent@client.test') \gset bot_
SELECT path AS c1_path FROM memory.namespaces WHERE id = :'c1' \gset
SELECT memory.approval_authority_grant_sha256(:'g_main') AS fp_main \gset
SELECT memory.approval_authority_grant_sha256(:'g_reject') AS fp_reject \gset
SELECT memory.approval_authority_grant_sha256(:'g_revoked') AS fp_revoked \gset
SELECT memory.approval_authority_grant_sha256(:'g_expired') AS fp_expired \gset

SET ROLE engramport_app;
SELECT t.expect_count('the holder sees the grants still open to them, with their terms and fingerprint',
  format($$SELECT 1 FROM memory.pending_authority_grants(%L, %L) p
           WHERE (p.authority_id = %L AND p.claim_types = '{decision,fact}' AND p.can_delegate AND p.grant_sha256 = %L
                  AND p.namespace_path = %L)
              OR p.authority_id = %L$$,
         :'o1_user_id', :'o1_session_id', :'g_main', :'fp_main', :'c1_path', :'g_reject'), 2);
SELECT t.expect_count('but not a revoked or expired one',
  format($$SELECT 1 FROM memory.pending_authority_grants(%L, %L) WHERE authority_id IN (%L, %L)$$,
         :'o1_user_id', :'o1_session_id', :'g_revoked', :'g_expired'), 0);
SELECT t.expect_count('looking does not spend the sign-in',
  format($$SELECT 1 FROM memory.pending_authority_grants(%L, %L)$$, :'o1_user_id', :'o1_session_id'), 2);
SELECT t.expect_count('someone else sees none of them',
  format($$SELECT 1 FROM memory.pending_authority_grants(%L, %L)$$, :'x1_user_id', :'x1_session_id'), 0);
SELECT t.expect_count('nor does a sign-in that maps to an agent',
  format($$SELECT 1 FROM memory.pending_authority_grants(%L, %L)$$, :'bot_user_id', :'bot_session_id'), 0);
SELECT t.expect_count('nor no sign-in',
  format($$SELECT 1 FROM memory.pending_authority_grants(%L, gen_random_uuid())$$, :'o1_user_id'), 0);
SELECT t.expect_denied('a pending grant cannot be delegated',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'o1_user_id', :'o1_session_id', :'g_main', :'staff'));
RESET ROLE;

\echo '-- accepting binds to the exact grant, through the holder''s own sign-in, once'
SET ROLE engramport_app;
SELECT t.expect_denied('not with another grant''s fingerprint',
  format($$SELECT memory.decide_approval_authority(%L, %L, %L, 'accept', %L)$$, :'o2_user_id', :'o2_session_id', :'g_main', :'fp_reject'));
SELECT t.expect_denied('not with a malformed fingerprint',
  format($$SELECT memory.decide_approval_authority(%L, %L, %L, 'accept', 'not-a-digest')$$, :'o2_user_id', :'o2_session_id', :'g_main'));
SELECT t.expect_denied('not with a made-up decision',
  format($$SELECT memory.decide_approval_authority(%L, %L, %L, 'approve', %L)$$, :'o2_user_id', :'o2_session_id', :'g_main', :'fp_main'));
SELECT t.expect_denied('not by someone else',
  format($$SELECT memory.decide_approval_authority(%L, %L, %L, 'accept', %L)$$, :'x1_user_id', :'x1_session_id', :'g_main', :'fp_main'));
SELECT t.expect_denied('not by a sign-in that maps to an agent',
  format($$SELECT memory.decide_approval_authority(%L, %L, %L, 'accept', %L)$$, :'bot_user_id', :'bot_session_id', :'g_main', :'fp_main'));
SELECT t.expect_denied('not with no sign-in',
  format($$SELECT memory.decide_approval_authority(%L, gen_random_uuid(), %L, 'accept', %L)$$, :'o2_user_id', :'g_main', :'fp_main'));
SELECT t.expect_denied('a revoked grant cannot be accepted',
  format($$SELECT memory.decide_approval_authority(%L, %L, %L, 'accept', %L)$$, :'o2_user_id', :'o2_session_id', :'g_revoked', :'fp_revoked'));
SELECT t.expect_denied('nor an expired one',
  format($$SELECT memory.decide_approval_authority(%L, %L, %L, 'accept', %L)$$, :'o2_user_id', :'o2_session_id', :'g_expired', :'fp_expired'));
SELECT t.expect_denied('an unknown grant gives the same answer as someone else''s',
  format($$SELECT memory.decide_approval_authority(%L, %L, gen_random_uuid(), 'accept', %L)$$, :'o2_user_id', :'o2_session_id', :'fp_main'));
SELECT memory.decide_approval_authority(:'o2_user_id', :'o2_session_id', :'g_main', 'accept', :'fp_main');
SELECT t.expect_denied('a grant is decided once',
  format($$SELECT memory.decide_approval_authority(%L, %L, %L, 'reject', %L)$$, :'o3_user_id', :'o3_session_id', :'g_main', :'fp_main'));
SELECT t.expect_denied('and the sign-in that accepted it is spent',
  format($$SELECT memory.decide_approval_authority(%L, %L, %L, 'reject', %L)$$, :'o2_user_id', :'o2_session_id', :'g_reject', :'fp_reject'));
RESET ROLE;
SELECT t.expect_count('the accepted grant is valid',
  format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'g_main'), 1);
SELECT t.expect_count('the acceptance records the fingerprint and the spent sign-in',
  format($$SELECT 1 FROM memory.approval_authority_decisions d JOIN memory.human_sign_ins_used u ON u.session_hash = d.sign_in_hash
           WHERE d.authority_id = %L AND d.actor_id = %L AND d.decision = 'accept' AND d.grant_sha256 = %L
             AND u.purpose = 'accept' AND u.session_hash = sha256(uuid_send(%L::uuid))$$,
         :'g_main', :'owner', :'fp_main', :'o2_session_id'), 1);
SET timezone = 'Pacific/Kiritimati';
SELECT t.expect_count('the fingerprint does not depend on the session''s time zone',
  format($$SELECT 1 WHERE memory.approval_authority_grant_sha256(%L) = %L$$, :'g_main', :'fp_main'), 1);
RESET timezone;
SELECT t.expect_count('two grants that differ only in their terms have different fingerprints',
  format($$SELECT 1 WHERE %L <> %L$$, :'fp_main', :'fp_reject'), 1);

\echo '-- a rejected grant confers nothing, and stays rejected'
SET ROLE engramport_app;
SELECT memory.decide_approval_authority(:'o4_user_id', :'o4_session_id', :'g_reject', 'reject', :'fp_reject');
SELECT t.expect_denied('it cannot be accepted afterwards',
  format($$SELECT memory.decide_approval_authority(%L, %L, %L, 'accept', %L)$$, :'o5_user_id', :'o5_session_id', :'g_reject', :'fp_reject'));
SELECT t.expect_count('and it no longer shows as open',
  format($$SELECT 1 FROM memory.pending_authority_grants(%L, %L)$$, :'o5_user_id', :'o5_session_id'), 0);
RESET ROLE;
SELECT t.expect_count('a rejected grant is not valid', format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'g_reject'), 0);

\echo '-- a delegation is accepted by its delegate, not its grantor'
SELECT * FROM t.sign_in('acc-staff@client.test') \gset s1_
SELECT * FROM t.sign_in('acc-staff@client.test') \gset s2_
SET ROLE engramport_app;
SELECT memory.delegate_approval_authority(:'o6_user_id', :'o6_session_id', :'g_main', :'staff', '{decision}') AS g_staff \gset
RESET ROLE;
SELECT memory.approval_authority_grant_sha256(:'g_staff') AS fp_staff \gset
SELECT t.expect_count('the delegation is not valid until the delegate accepts',
  format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'g_staff'), 0);
SELECT * FROM t.sign_in('acc-owner@client.test') \gset o7_
SET ROLE engramport_app;
SELECT t.expect_denied('the grantor cannot accept for the delegate',
  format($$SELECT memory.decide_approval_authority(%L, %L, %L, 'accept', %L)$$, :'o7_user_id', :'o7_session_id', :'g_staff', :'fp_staff'));
SELECT t.expect_count('the delegate sees the offer, naming what it was delegated from',
  format($$SELECT 1 FROM memory.pending_authority_grants(%L, %L) WHERE authority_id = %L AND delegated_from = %L AND NOT can_delegate$$,
         :'s1_user_id', :'s1_session_id', :'g_staff', :'g_main'), 1);
SELECT memory.decide_approval_authority(:'s1_user_id', :'s1_session_id', :'g_staff', 'accept', :'fp_staff');
RESET ROLE;
SELECT t.expect_count('and then it is valid', format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'g_staff'), 1);

\echo '-- revoking the authority above ends it, and a pending delegation under it cannot be accepted'
SELECT * FROM t.sign_in('acc-owner@client.test') \gset o8_
SET ROLE engramport_app;
SELECT memory.delegate_approval_authority(:'o8_user_id', :'o8_session_id', :'g_main', :'other') AS g_other \gset
RESET ROLE;
SELECT memory.approval_authority_grant_sha256(:'g_other') AS fp_other \gset
SET ROLE engramport_admin;
UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'owner_left' WHERE id = :'g_main';
RESET ROLE;
SELECT t.expect_count('the accepted delegation is no longer valid',
  format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'g_staff'), 0);
SELECT * FROM t.sign_in('acc-other@client.test') \gset x2_
SET ROLE engramport_app;
SELECT t.expect_count('the pending one no longer shows as open',
  format($$SELECT 1 FROM memory.pending_authority_grants(%L, %L)$$, :'x2_user_id', :'x2_session_id'), 0);
SELECT t.expect_denied('and cannot be accepted',
  format($$SELECT memory.decide_approval_authority(%L, %L, %L, 'accept', %L)$$, :'x2_user_id', :'x2_session_id', :'g_other', :'fp_other'));
RESET ROLE;

\echo '-- decisions are a record, and only the holder makes them'
SELECT t.expect_denied('a decision cannot be changed',
  format($$UPDATE memory.approval_authority_decisions SET decision = 'accept' WHERE authority_id = %L$$, :'g_reject'));
SELECT t.expect_denied('or deleted', format($$DELETE FROM memory.approval_authority_decisions WHERE authority_id = %L$$, :'g_main'));
SELECT t.expect_denied('or emptied', 'TRUNCATE memory.approval_authority_decisions CASCADE');
SET ROLE engramport_admin;
SELECT t.expect_count('the admin sees whether and when each grant was decided',
  format($$SELECT 1 FROM memory.approval_authority_decisions WHERE authority_id IN (%L, %L, %L)$$, :'g_main', :'g_reject', :'g_staff'), 3);
SELECT t.expect_denied('but not the sign-in behind it', 'SELECT sign_in_hash FROM memory.approval_authority_decisions');
SELECT t.expect_denied('and cannot decide for anyone',
  format($$SELECT memory.decide_approval_authority(gen_random_uuid(), gen_random_uuid(), %L, 'accept', %L)$$, :'g_other', :'fp_other'));
SELECT t.expect_denied('or write a decision',
  format($$INSERT INTO memory.approval_authority_decisions (authority_id, actor_id, decision, grant_sha256, sign_in_hash)
           VALUES (%L, %L, 'accept', %L, sha256('x'))$$, :'g_other', :'other', :'fp_other'));
RESET ROLE;
SET ROLE engramport_app;
SELECT t.expect_denied('the server cannot read decisions directly', 'SELECT 1 FROM memory.approval_authority_decisions');
SELECT t.expect_denied('or write one',
  format($$INSERT INTO memory.approval_authority_decisions (authority_id, actor_id, decision, grant_sha256, sign_in_hash)
           VALUES (%L, %L, 'accept', %L, sha256('x'))$$, :'g_other', :'other', :'fp_other'));
SELECT t.expect_denied('or look up a person behind a sign-in directly',
  format($$SELECT memory.signed_in_human(%L, %L)$$, :'x2_user_id', :'x2_session_id'));
RESET ROLE;
SELECT t.expect_count('no API role can see or decide grants',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) r
    WHERE has_table_privilege(r, 'memory.approval_authority_decisions', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE')
       OR has_function_privilege(r, 'memory.decide_approval_authority(uuid, uuid, uuid, text, text)', 'EXECUTE')
       OR has_function_privilege(r, 'memory.pending_authority_grants(uuid, uuid)', 'EXECUTE')
       OR has_function_privilege(r, 'memory.signed_in_human(uuid, uuid)', 'EXECUTE')
       OR has_function_privilege(r, 'memory.approval_authority_grant_sha256(uuid)', 'EXECUTE')$$, 0);
