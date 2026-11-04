-- Tests for 0016_approval_events. Run by db/test/run.sh after authority_test.sql,
-- on the rls_test namespaces and keys, the company city and its key from
-- company_test, and t.sign_in from authority_test.
\set ON_ERROR_STOP on
\set QUIET on
\set city '00000000-0000-7000-8000-000000000001'
\set ta   '00000000-0000-7000-8000-000000000011'
\set c1   '00000000-0000-7000-8000-000000000111'
\set c2   '00000000-0000-7000-8000-000000000112'
\set k_c1 '00000000-0000-7000-8000-0000000000f1'
\set k_c1_ro '00000000-0000-7000-8000-0000000000e1'
\set k_c2 '00000000-0000-7000-8000-0000000000f2'
\set k_ta '00000000-0000-7000-8000-0000000000a0'
\set k_co_hq '00000000-0000-7000-8000-0000000000f9'
\set agent '00000000-0000-7000-8000-00000000a001'

-- A whole decision the way the approval page makes one (0018): review the
-- memory, take a challenge for the action, then confirm it, all with the one
-- sign-in. The checks 0016 made are now made along this path.
CREATE FUNCTION t.record_approval(p_user uuid, p_session uuid, p_memory uuid,
                                  p_action memory.approval_action, p_sha text) RETURNS uuid
LANGUAGE plpgsql AS $$
DECLARE
  v integer;
  c record;
BEGIN
  SELECT r.memory_version INTO v FROM memory.approval_review(p_user, p_session, p_memory) r;
  SELECT * INTO c FROM memory.issue_approval_challenge(p_user, p_session, p_memory, p_action, p_sha, v);
  RETURN memory.decide_approval_challenge(p_user, p_session, c.challenge_id, c.secret);
END
$$;

SELECT id AS co_hq FROM memory.namespaces WHERE purpose = 'company' AND level = 'cell' AND slug = 'hq' \gset
SELECT id AS co_city FROM memory.namespaces WHERE purpose = 'company' AND parent_id IS NULL \gset

INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'appr-owner', 'Cell owner') RETURNING id AS owner \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'appr-staff', 'Staff') RETURNING id AS staff \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'appr-gov', 'Governance') RETURNING id AS gov \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'appr-none', 'No authority') RETURNING id AS nobody \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES
  ('appr-owner@client.test', :'c1', :'owner'),
  ('appr-staff@client.test', :'c1', :'staff'),
  ('appr-gov@an2b.test', :'co_hq', :'gov'),
  ('appr-none@client.test', :'c1', :'nobody'),
  ('appr-agent@client.test', :'c1', :'agent');

SET ROLE engramport_admin;
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, can_delegate)
  VALUES (:'owner', :'c1', 'cell_knowledge', true) RETURNING id AS a_owner \gset
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
  VALUES (:'gov', :'co_city', 'company_governance') RETURNING id AS a_gov \gset
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
  VALUES (:'gov', :'city', 'promotion') RETURNING id AS a_promo \gset
RESET ROLE;
SELECT t.accept(:'a_owner', 'appr-owner@client.test');
SELECT t.accept(:'a_gov', 'appr-gov@an2b.test');
SELECT t.accept(:'a_promo', 'appr-gov@an2b.test');
SELECT * FROM t.sign_in('appr-owner@client.test') \gset d_
SET ROLE engramport_app;
SELECT memory.delegate_approval_authority(:'d_user_id', :'d_session_id', :'a_owner', :'staff', '{decision}') AS a_staff \gset
RESET ROLE;
SELECT t.accept(:'a_staff', 'appr-staff@client.test');

-- Memories the agent wrote.
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('decision', 'approval check: ship on Fridays', 'remember', 'rest',
                         p_claim_type => 'decision') AS m_dec \gset
  SELECT memory.remember('fact', 'approval check: an observation', 'remember', 'rest') AS m_obs \gset
  SELECT memory.remember('fact', 'approval check: to be rejected', 'remember', 'rest',
                         p_claim_type => 'proposal') AS m_rej \gset
  SELECT memory.remember('fact', 'approval check: to be retracted', 'remember', 'rest') AS m_ret \gset
COMMIT;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT memory.remember('fact', 'approval check: cell 2 only', 'remember', 'rest') AS m_c2 \gset
COMMIT;
BEGIN; SELECT t.as_key(:'k_ta', :'ta');
  SELECT memory.remember('principle', 'approval check: tower pattern', 'remember', 'rest') AS m_tower \gset
COMMIT;
BEGIN; SELECT t.as_key(:'k_co_hq', :'co_hq');
  SELECT memory.remember('decision', 'approval check: company rule', 'remember', 'rest',
                         p_claim_type => 'decision') AS m_co \gset
COMMIT;
RESET ROLE;
SELECT content_sha256 AS h_dec FROM memory.memories WHERE id = :'m_dec' \gset
SELECT content_sha256 AS h_obs FROM memory.memories WHERE id = :'m_obs' \gset
SELECT content_sha256 AS h_rej FROM memory.memories WHERE id = :'m_rej' \gset
SELECT content_sha256 AS h_ret FROM memory.memories WHERE id = :'m_ret' \gset
SELECT content_sha256 AS h_tower FROM memory.memories WHERE id = :'m_tower' \gset
SELECT content_sha256 AS h_co FROM memory.memories WHERE id = :'m_co' \gset

\echo '-- an agent asks; asking approves nothing'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.request_approval(:'m_dec') AS r_dec \gset
  SELECT t.expect_count('asking makes the memory pending',
    format($$SELECT 1 FROM memory.memories WHERE id = %L AND approval_state = 'pending'$$, :'m_dec'), 1);
  SELECT t.expect_count('asking twice returns the same request',
    format($$SELECT 1 WHERE memory.request_approval(%L) = %L$$, :'m_dec', :'r_dec'), 1);
  SELECT t.expect_count('the request records who asked, with which key',
    format($$SELECT 1 FROM memory.approval_requests WHERE id = %L AND requested_by_actor_id = %L$$, :'r_dec', :'agent'), 1);
  SELECT t.expect_denied('a memory the key cannot read',
    format($$SELECT memory.request_approval(%L)$$, :'m_c2'));
  SELECT t.expect_denied('a memory above the key''s namespace',
    format($$SELECT memory.request_approval(%L)$$, :'m_tower'));
  SELECT t.expect_denied('the app cannot write a request itself',
    format($$INSERT INTO memory.approval_requests (memory_id, namespace_id, requested_by_actor_id, api_key_id)
             VALUES (%L, %L, %L, %L)$$, :'m_obs', :'c1', :'agent', :'k_c1'));
  SELECT t.expect_denied('the app cannot write a decision itself',
    format($$INSERT INTO memory.approvals (memory_id, namespace_id, action, scope, claim_type, content_sha256,
             decided_by_actor_id, authority_id, sign_in_hash)
             VALUES (%L, %L, 'approve', 'cell_knowledge', 'decision', %L, %L, %L, '\x00')$$,
             :'m_dec', :'c1', :'h_dec', :'owner', :'a_owner'));
  SELECT t.expect_denied('nor set the state, even right after asking',
    format($$UPDATE memory.memories SET approval_state = 'approved' WHERE id = %L$$, :'m_dec'));
COMMIT;
BEGIN; SELECT t.as_key(:'k_c1_ro', :'c1');
  SELECT t.expect_denied('a read-only key cannot ask',
    format($$SELECT memory.request_approval(%L)$$, :'m_obs'));
ROLLBACK;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.request_approval(:'m_rej') IS NOT NULL;
COMMIT;
RESET ROLE;

\echo '-- an agent cannot approve, not even with a person''s sign-in on its own actor'
SELECT * FROM t.sign_in('appr-agent@client.test') \gset ag_
SET ROLE engramport_app;
SELECT t.expect_denied('a sign-in that maps to an agent actor',
  format($$SELECT t.record_approval(%L, %L, %L, 'approve', %L)$$, :'ag_user_id', :'ag_session_id', :'m_dec', :'h_dec'));
RESET ROLE;

\echo '-- a person without authority learns nothing about the memory'
SELECT * FROM t.sign_in('appr-none@client.test') \gset n1_
SELECT * FROM t.sign_in('appr-none@client.test') \gset n2_
SELECT set_config('t.n1_user', :'n1_user_id', false), set_config('t.n1_session', :'n1_session_id', false),
       set_config('t.n2_user', :'n2_user_id', false), set_config('t.n2_session', :'n2_session_id', false),
       set_config('t.m_dec', :'m_dec', false), set_config('t.h_dec', :'h_dec', false) \g /dev/null
SET ROLE engramport_app;
DO $$
DECLARE e1 text; e2 text;
BEGIN
  BEGIN
    PERFORM t.record_approval(current_setting('t.n1_user')::uuid, current_setting('t.n1_session')::uuid,
                                   current_setting('t.m_dec')::uuid, 'approve', current_setting('t.h_dec'));
  EXCEPTION WHEN OTHERS THEN e1 := SQLSTATE || ' ' || SQLERRM;
  END;
  BEGIN
    PERFORM t.record_approval(current_setting('t.n2_user')::uuid, current_setting('t.n2_session')::uuid,
                                   gen_random_uuid(), 'approve', current_setting('t.h_dec'));
  EXCEPTION WHEN OTHERS THEN e2 := SQLSTATE || ' ' || SQLERRM;
  END;
  IF e1 IS NULL OR e1 IS DISTINCT FROM e2 THEN
    RAISE EXCEPTION 'FAIL no authority and no memory must look the same: % / %', e1, e2;
  END IF;
  RAISE NOTICE 'pass no authority and no memory give the same answer';
END
$$;
RESET ROLE;

\echo '-- the owner approves the exact text they were shown'
SELECT * FROM t.sign_in('appr-owner@client.test') \gset o1_
SELECT * FROM t.sign_in('appr-owner@client.test') \gset o2_
SELECT * FROM t.sign_in('appr-owner@client.test') \gset o3_
SET ROLE engramport_app;
SELECT t.expect_denied('a digest that is not the memory''s',
  format($$SELECT t.record_approval(%L, %L, %L, 'approve', %L)$$, :'o1_user_id', :'o1_session_id', :'m_dec', :'h_obs'));
SELECT t.expect_denied('a digest that is not a digest',
  format($$SELECT t.record_approval(%L, %L, %L, 'approve', 'APPROVED')$$, :'o1_user_id', :'o1_session_id', :'m_dec'));
SELECT t.record_approval(:'o1_user_id', :'o1_session_id', :'m_dec', 'approve', :'h_dec') AS ap_dec \gset
SELECT t.expect_denied('the same sign-in cannot decide again',
  format($$SELECT t.record_approval(%L, %L, %L, 'reject', %L)$$, :'o1_user_id', :'o1_session_id', :'m_rej', :'h_rej'));
SELECT t.expect_denied('a decided memory is not decided again',
  format($$SELECT t.record_approval(%L, %L, %L, 'reject', %L)$$, :'o2_user_id', :'o2_session_id', :'m_dec', :'h_dec'));
SELECT t.record_approval(:'o3_user_id', :'o3_session_id', :'m_rej', 'reject', :'h_rej') IS NOT NULL;
RESET ROLE;
SELECT t.expect_count('the memory is approved',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND approval_state = 'approved'$$, :'m_dec'), 1);
SELECT t.expect_count('the rejected one is rejected',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND approval_state = 'rejected'$$, :'m_rej'), 1);
SELECT t.expect_count('the decision binds id, digest, action, namespace, person, authority and request',
  format($$SELECT 1 FROM memory.approvals WHERE id = %L AND memory_id = %L AND content_sha256 = %L AND action = 'approve'
           AND namespace_id = %L AND decided_by_actor_id = %L AND authority_id = %L AND request_id = %L
           AND scope = 'cell_knowledge' AND claim_type = 'decision'$$,
         :'ap_dec', :'m_dec', :'h_dec', :'c1', :'owner', :'a_owner', :'r_dec'), 1);
SELECT t.expect_denied('a decision is never edited',
  format($$UPDATE memory.approvals SET action = 'reject' WHERE id = %L$$, :'ap_dec'));
SELECT t.expect_denied('or deleted',
  format($$DELETE FROM memory.approvals WHERE id = %L$$, :'ap_dec'));
SELECT t.expect_denied('nor is a request',
  format($$DELETE FROM memory.approval_requests WHERE id = %L$$, :'r_dec'));
SELECT t.expect_denied('neither table can be emptied', 'TRUNCATE memory.approvals CASCADE');
SELECT t.expect_denied('either one', 'TRUNCATE memory.approval_requests CASCADE');
SELECT t.expect_denied('and not even the table owner can flip the state',
  format($$UPDATE memory.memories SET approval_state = 'rejected' WHERE id = %L$$, :'m_dec'));

\echo '-- a person can decide without a request; superseded and retracted versions cannot be decided'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  UPDATE memory.memories SET status = 'retracted' WHERE id = :'m_ret';
COMMIT;
RESET ROLE;
SELECT * FROM t.sign_in('appr-owner@client.test') \gset o4_
SELECT * FROM t.sign_in('appr-owner@client.test') \gset o5_
SET ROLE engramport_app;
SELECT t.expect_denied('a retracted memory',
  format($$SELECT t.record_approval(%L, %L, %L, 'approve', %L)$$, :'o4_user_id', :'o4_session_id', :'m_ret', :'h_ret'));
SELECT t.record_approval(:'o5_user_id', :'o5_session_id', :'m_obs', 'approve', :'h_obs') AS ap_obs \gset
RESET ROLE;
SELECT t.expect_count('a decision with no request records none',
  format($$SELECT 1 FROM memory.approvals WHERE id = %L AND request_id IS NULL$$, :'ap_obs'), 1);

\echo '-- a changed memory starts over, as a proposal the approved one waits on (D-04)'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT t.expect_denied('an agent cannot supersede an approved memory',
    format($$UPDATE memory.memories SET status = 'superseded' WHERE id = %L$$, :'m_dec'));
  SELECT memory.propose_revision(:'m_dec', 'decision', 'approval check: ship on Thursdays', 'remember', 'rest',
                                 'decision') AS m_dec2 \gset
COMMIT;
RESET ROLE;
SELECT content_sha256 AS h_dec2 FROM memory.memories WHERE id = :'m_dec2' \gset
SELECT t.expect_count('the new version is a pending proposal, not approved',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND approval_state = 'pending' AND status = 'proposed'$$, :'m_dec2'), 1);
SELECT t.expect_count('the old version stays current and approved',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND approval_state = 'approved' AND status = 'active'$$, :'m_dec'), 1);

\echo '-- a delegate decides only what was delegated'
SELECT * FROM t.sign_in('appr-staff@client.test') \gset s1_
SELECT * FROM t.sign_in('appr-staff@client.test') \gset s2_
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('fact', 'approval check: staff cannot approve facts', 'remember', 'rest',
                         p_claim_type => 'fact') AS m_fact \gset
COMMIT;
RESET ROLE;
SELECT content_sha256 AS h_fact FROM memory.memories WHERE id = :'m_fact' \gset
SET ROLE engramport_app;
SELECT t.expect_denied('a claim type the delegation leaves out',
  format($$SELECT t.record_approval(%L, %L, %L, 'approve', %L)$$, :'s1_user_id', :'s1_session_id', :'m_fact', :'h_fact'));
SELECT t.record_approval(:'s2_user_id', :'s2_session_id', :'m_dec2', 'approve', :'h_dec2') AS ap_dec2 \gset
RESET ROLE;
SELECT t.expect_count('the delegate''s decision names the delegated authority',
  format($$SELECT 1 FROM memory.approvals WHERE id = %L AND authority_id = %L AND decided_by_actor_id = %L$$,
         :'ap_dec2', :'a_staff', :'staff'), 1);
SELECT t.expect_count('approving the proposal supersedes the old version in the same step',
  format($$SELECT 1 FROM memory.memories o JOIN memory.memories n ON n.supersedes_id = o.id
           WHERE o.id = %L AND o.status = 'superseded' AND o.approval_state = 'approved'
             AND n.id = %L AND n.status = 'active' AND n.approval_state = 'approved'$$, :'m_dec', :'m_dec2'), 1);

\echo '-- revoking the owner stops the delegate from then on'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('decision', 'approval check: after the revoke', 'remember', 'rest',
                         p_claim_type => 'decision') AS m_late \gset
COMMIT;
RESET ROLE;
SELECT content_sha256 AS h_late FROM memory.memories WHERE id = :'m_late' \gset
SET ROLE engramport_admin;
UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'owner_left' WHERE id = :'a_owner';
RESET ROLE;
SELECT * FROM t.sign_in('appr-staff@client.test') \gset s3_
SELECT * FROM t.sign_in('appr-owner@client.test') \gset o6_
SET ROLE engramport_app;
SELECT t.expect_denied('the delegate, once the owner is revoked',
  format($$SELECT t.record_approval(%L, %L, %L, 'approve', %L)$$, :'s3_user_id', :'s3_session_id', :'m_late', :'h_late'));
SELECT t.expect_denied('the revoked owner',
  format($$SELECT t.record_approval(%L, %L, %L, 'approve', %L)$$, :'o6_user_id', :'o6_session_id', :'m_late', :'h_late'));
RESET ROLE;
SELECT t.expect_count('decisions made before the revoke stay on the record',
  format($$SELECT 1 FROM memory.approvals WHERE id IN (%L, %L)$$, :'ap_dec', :'ap_dec2'), 2);

\echo '-- company and promotion scopes are kept apart'
SELECT * FROM t.sign_in('appr-gov@an2b.test') \gset g1_
SELECT * FROM t.sign_in('appr-gov@an2b.test') \gset g2_
SET ROLE engramport_app;
SELECT t.record_approval(:'g1_user_id', :'g1_session_id', :'m_co', 'approve', :'h_co') AS ap_co \gset
SELECT t.record_approval(:'g2_user_id', :'g2_session_id', :'m_tower', 'approve', :'h_tower') AS ap_tower \gset
RESET ROLE;
SELECT t.expect_count('governance approves the company cell',
  format($$SELECT 1 FROM memory.approvals WHERE id = %L AND scope = 'company_governance' AND authority_id = %L$$, :'ap_co', :'a_gov'), 1);
SELECT t.expect_count('the tower memory needs and uses promotion authority',
  format($$SELECT 1 FROM memory.approvals WHERE id = %L AND scope = 'promotion' AND authority_id = %L$$, :'ap_tower', :'a_promo'), 1);
SET ROLE engramport_admin;
UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'test_done' WHERE id = :'a_promo';
RESET ROLE;
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_ta', :'ta');
  SELECT memory.remember('principle', 'approval check: second tower pattern', 'remember', 'rest') AS m_tower2 \gset
COMMIT;
RESET ROLE;
SELECT content_sha256 AS h_tower2 FROM memory.memories WHERE id = :'m_tower2' \gset
SELECT * FROM t.sign_in('appr-gov@an2b.test') \gset g3_
SET ROLE engramport_app;
SELECT t.expect_denied('company governance alone cannot promote',
  format($$SELECT t.record_approval(%L, %L, %L, 'approve', %L)$$, :'g3_user_id', :'g3_session_id', :'m_tower2', :'h_tower2'));
RESET ROLE;

\echo '-- the server sees the trail for what its key can read; the admin sees it all without text or digest'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT t.expect_count('cell 1 sees its own decisions',
    format($$SELECT 1 FROM memory.approvals WHERE id IN (%L, %L)$$, :'ap_dec', :'ap_obs'), 2);
  SELECT t.expect_count('and the tower decision it inherits',
    format($$SELECT 1 FROM memory.approvals WHERE id = %L$$, :'ap_tower'), 1);
  SELECT t.expect_count('but not the company''s',
    format($$SELECT 1 FROM memory.approvals WHERE id = %L$$, :'ap_co'), 0);
  SELECT t.expect_denied('nor the digest or the sign-in',
    $$SELECT content_sha256 FROM memory.approvals$$);
COMMIT;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT t.expect_count('a sibling cell sees none of cell 1''s',
    format($$SELECT 1 FROM memory.approvals WHERE id IN (%L, %L)$$, :'ap_dec', :'ap_obs'), 0);
COMMIT;
RESET ROLE;
SET ROLE engramport_admin;
SELECT t.expect_count('the admin sees who decided what, where and under which authority',
  format($$SELECT 1 FROM memory.approvals WHERE id IN (%L, %L, %L) AND authority_id IS NOT NULL$$, :'ap_dec', :'ap_co', :'ap_tower'), 3);
SELECT t.expect_count('and who asked',
  format($$SELECT 1 FROM memory.approval_requests WHERE id = %L AND api_key_id = %L$$, :'r_dec', :'k_c1'), 1);
SELECT t.expect_denied('but never the digest', $$SELECT content_sha256 FROM memory.approvals$$);
SELECT t.expect_denied('or the sign-in', $$SELECT sign_in_hash FROM memory.approvals$$);
SELECT t.expect_denied('and still no memory text', $$SELECT content FROM memory.memories$$);
SELECT t.expect_denied('the admin cannot decide',
  format($$SELECT t.record_approval(%L, %L, %L, 'approve', %L)$$, :'g3_user_id', :'g3_session_id', :'m_late', :'h_late'));
RESET ROLE;

\echo '-- Supabase''s API roles get nothing'
SELECT t.expect_count('no API role can ask, decide or read the trail',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) r
    WHERE has_table_privilege(r, 'memory.approvals', 'SELECT')
       OR has_table_privilege(r, 'memory.approval_requests', 'SELECT')
       OR has_function_privilege(r, 'memory.request_approval(uuid)', 'EXECUTE')
       OR has_function_privilege(r, 'memory.approval_review(uuid, uuid, uuid)', 'EXECUTE')
       OR has_function_privilege(r, 'memory.issue_approval_challenge(uuid, uuid, uuid, memory.approval_action, text, integer)', 'EXECUTE')
       OR has_function_privilege(r, 'memory.decide_approval_challenge(uuid, uuid, uuid, text)', 'EXECUTE')$$, 0);
