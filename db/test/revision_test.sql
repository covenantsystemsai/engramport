-- Tests for 0020_revision_proposals (founder decision D-04): agents propose,
-- people approve, history is kept. Run by db/test/run.sh after
-- challenge_test.sql, on the rls_test namespaces and keys and the helpers from
-- rls_test (t.as_key, t.expect_count, t.expect_denied), authority_test
-- (t.sign_in, t.accept) and challenge_test (t.expect_error, t.challenge).
\set ON_ERROR_STOP on
\set QUIET on
\set c1    '00000000-0000-7000-8000-000000000111'
\set c2    '00000000-0000-7000-8000-000000000112'
\set k_c1  '00000000-0000-7000-8000-0000000000f1'
\set k_c1b '00000000-0000-7000-8000-0000000000f4'
\set k_c2  '00000000-0000-7000-8000-0000000000f2'

-- Review, take a challenge and decide, the way the page does. Returns the decision.
CREATE FUNCTION t.decide(p_user uuid, p_session uuid, p_memory uuid, p_action memory.approval_action)
RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE c record;
BEGIN
  SELECT * INTO c FROM t.challenge(p_user, p_session, p_memory, p_action);
  RETURN memory.decide_approval_challenge(p_user, p_session, c.challenge_id, c.secret);
END $$;
-- The state of one memory, as one comparable string.
CREATE FUNCTION t.state(p_memory uuid) RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT status || '/' || approval_state FROM memory.memories WHERE id = p_memory
$$;
CREATE FUNCTION t.expect_state(p_name text, p_memory uuid, p_want text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE got text := t.state(p_memory);
BEGIN
  IF got IS DISTINCT FROM p_want THEN
    RAISE EXCEPTION 'FAIL %: wanted %, got %', p_name, p_want, got;
  END IF;
  RAISE NOTICE 'pass %', p_name;
END $$;

INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'rv-owner', 'Revision owner') RETURNING id AS owner \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'rv-owner2', 'Second owner') RETURNING id AS owner2 \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'rv-c2owner', 'Cell two owner') RETURNING id AS c2owner \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES
  ('rv-owner@client.test', :'c1', :'owner'),
  ('rv-owner2@client.test', :'c1', :'owner2'),
  ('rv-c2owner@client.test', :'c2', :'c2owner');
SET ROLE engramport_admin;
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
  VALUES (:'owner', :'c1', 'cell_knowledge') RETURNING id AS a_owner \gset
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
  VALUES (:'owner2', :'c1', 'cell_knowledge') RETURNING id AS a_owner2 \gset
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
  VALUES (:'c2owner', :'c2', 'cell_knowledge') RETURNING id AS a_c2 \gset
RESET ROLE;
SELECT t.accept(:'a_owner', 'rv-owner@client.test');
SELECT t.accept(:'a_owner2', 'rv-owner2@client.test');
SELECT t.accept(:'a_c2', 'rv-c2owner@client.test');
SELECT * FROM t.sign_in('rv-owner@client.test') \gset o1_
SELECT * FROM t.sign_in('rv-owner@client.test') \gset o2_
SELECT * FROM t.sign_in('rv-owner@client.test') \gset o3_
SELECT * FROM t.sign_in('rv-owner@client.test') \gset o4_
SELECT * FROM t.sign_in('rv-owner@client.test') \gset o5_
SELECT * FROM t.sign_in('rv-owner@client.test') \gset o6_
SELECT * FROM t.sign_in('rv-owner@client.test') \gset o7_
SELECT * FROM t.sign_in('rv-owner@client.test') \gset o8_
SELECT * FROM t.sign_in('rv-owner@client.test') \gset o9_
SELECT * FROM t.sign_in('rv-owner@client.test') \gset o10_
SELECT * FROM t.sign_in('rv-owner@client.test') \gset o11_
SELECT * FROM t.sign_in('rv-owner2@client.test') \gset p1_
SELECT * FROM t.sign_in('rv-c2owner@client.test') \gset q1_

\echo '-- an approved memory, and what an agent can no longer do to it'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('decision', 'revision check: invoices due in 30 days', 'remember', 'rest',
                         p_claim_type => 'decision', p_dedup_key => 'rv-terms') AS b1 \gset
COMMIT;
SELECT t.decide(:'o1_user_id', :'o1_session_id', :'b1', 'approve') IS NOT NULL;
RESET ROLE;
SELECT t.expect_state('the base is current and approved', :'b1', 'active/approved');
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT t.expect_denied('an agent cannot supersede an approved memory',
    format($$UPDATE memory.memories SET status = 'superseded' WHERE id = %L$$, :'b1'));
  SELECT t.expect_denied('or retract it',
    format($$UPDATE memory.memories SET status = 'retracted' WHERE id = %L$$, :'b1'));
COMMIT;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('note', 'revision check: a loose note', 'remember', 'rest') AS loose \gset
  SELECT t.expect_denied('or point an active memory at it',
    format($$UPDATE memory.memories SET supersedes_id = %L WHERE id = %L$$, :'b1', :'loose'));
  SELECT t.expect_denied('or write a new active version that follows it',
    format($$INSERT INTO memory.memories (namespace_id, kind, content, provenance_id, supersedes_id)
             SELECT namespace_id, kind, content, provenance_id, %L FROM memory.memories WHERE id = %L$$, :'b1', :'loose'));
COMMIT;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT t.expect_denied('another cell cannot propose a revision of it',
    format($$SELECT memory.propose_revision(%L, 'decision', 'x', 'remember', 'rest', 'decision')$$, :'b1'));
COMMIT;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('note', 'revision check: not approved', 'remember', 'rest') AS plain \gset
  SELECT t.expect_denied('a revision is proposed only for an approved memory',
    format($$SELECT memory.propose_revision(%L, 'note', 'x', 'remember', 'rest', 'observation')$$, :'plain'));
  SELECT t.expect_denied('a write cannot be born proposed with no base',
    format($$INSERT INTO memory.memories (namespace_id, kind, content, provenance_id, status)
             SELECT namespace_id, kind, content, provenance_id, 'proposed' FROM memory.memories WHERE id = %L$$, :'plain'));
COMMIT;
RESET ROLE;

\echo '-- competing proposals stay separate, and the approved one stays current'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.propose_revision(:'b1', 'decision', 'revision check: invoices due in 14 days', 'supersede_memory',
                                 'rest', 'decision', p_dedup_key => 'rv-terms') AS p1 \gset
COMMIT;
BEGIN; SELECT t.as_key(:'k_c1b', :'c1');
  SELECT memory.propose_revision(:'b1', 'decision', 'revision check: invoices due in 45 days', 'supersede_memory',
                                 'rest', 'decision', p_dedup_key => 'rv-terms') AS p2 \gset
COMMIT;
RESET ROLE;
SELECT t.expect_state('the first proposal is pending', :'p1', 'proposed/pending');
SELECT t.expect_state('so is the second', :'p2', 'proposed/pending');
SELECT t.expect_state('the base is unchanged', :'b1', 'active/approved');
SELECT t.expect_count('each proposal is its own row, pointing at the base, with its own provenance',
  format($$SELECT 1 FROM memory.memories m JOIN memory.provenance p ON p.id = m.provenance_id
           WHERE m.id IN (%L, %L) AND m.supersedes_id = %L AND p.content_sha256 = m.content_sha256$$,
         :'p1', :'p2', :'b1'), 2);
SELECT t.expect_count('two provenance rows, from two agents',
  format($$SELECT DISTINCT p.actor_id FROM memory.memories m JOIN memory.provenance p ON p.id = m.provenance_id
           WHERE m.id IN (%L, %L)$$, :'p1', :'p2'), 2);
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT t.expect_count('the agent still reads one active version under the key',
    $$SELECT 1 FROM memory.memories WHERE dedup_key = 'rv-terms' AND status = 'active'$$, 1);
  SELECT t.expect_denied('an agent cannot make its proposal current',
    format($$UPDATE memory.memories SET status = 'active' WHERE id = %L$$, :'p1'));
  SELECT t.expect_denied('or move what it proposes to replace',
    format($$UPDATE memory.memories SET supersedes_id = %L WHERE id = %L$$, :'plain', :'p1'));
  SELECT t.expect_denied('or approve it',
    format($$UPDATE memory.memories SET approval_state = 'approved' WHERE id = %L$$, :'p1'));
COMMIT;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT t.expect_count('another cell cannot see the proposals',
    format($$SELECT 1 FROM memory.memories WHERE id IN (%L, %L)$$, :'p1', :'p2'), 0);
COMMIT;

\echo '-- the person sees the proposal and the approved text it would replace'
SELECT t.expect_count('review shows both texts',
  format($$SELECT 1 FROM memory.approval_review(%L, %L, %L)
           WHERE status = 'proposed' AND replaces_memory_id = %L AND replaces_current
             AND replaces_content = 'revision check: invoices due in 30 days'
             AND content = 'revision check: invoices due in 14 days'$$,
         :'o2_user_id', :'o2_session_id', :'p1', :'b1'), 1);
SELECT t.expect_error('a person with no authority over the cell sees nothing',
  format($$SELECT * FROM memory.approval_review(%L, %L, %L)$$, :'q1_user_id', :'q1_session_id', :'p1'),
  '%no valid authority%');

\echo '-- approving one swaps it in, in one step; the other is now stale'
SELECT * FROM t.challenge(:'o2_user_id', :'o2_session_id', :'p1', 'approve') \gset c1_
SELECT * FROM t.challenge(:'o3_user_id', :'o3_session_id', :'p2', 'approve') \gset c2_
RESET ROLE;
SELECT t.expect_count('the challenge is bound to the approved version it replaces',
  format($$SELECT 1 FROM memory.approval_challenges WHERE id IN (%L, %L) AND base_memory_id = %L$$,
         :'c1_challenge_id', :'c2_challenge_id', :'b1'), 2);
SET ROLE engramport_app;
SELECT memory.decide_approval_challenge(:'o2_user_id', :'o2_session_id', :'c1_challenge_id', :'c1_secret') IS NOT NULL;
RESET ROLE;
SELECT t.expect_state('the approved proposal is current', :'p1', 'active/approved');
SELECT t.expect_state('the old version is superseded and keeps its approval', :'b1', 'superseded/approved');
SELECT t.expect_count('one decision, recorded for the proposal',
  format($$SELECT 1 FROM memory.approvals WHERE memory_id = %L AND action = 'approve'$$, :'p1'), 1);
SET ROLE engramport_app;
SELECT t.expect_error('the competing proposal is refused as stale',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o3_user_id', :'o3_session_id', :'c2_challenge_id', :'c2_secret'),
  '%has changed%');
SELECT t.expect_error('and cannot be put up again against the old base',
  format($$SELECT * FROM t.challenge(%L, %L, %L, 'approve')$$, :'o4_user_id', :'o4_session_id', :'p2'),
  '%has changed%');
RESET ROLE;
SELECT t.expect_state('the stale proposal stays on record, undecided', :'p2', 'proposed/pending');

\echo '-- an approval cannot be replayed'
SET ROLE engramport_app;
SELECT t.expect_error('the same challenge again',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o2_user_id', :'o2_session_id', :'c1_challenge_id', :'c1_secret'),
  '%already used%');
SELECT t.expect_error('the same challenge from a fresh sign-in',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o5_user_id', :'o5_session_id', :'c1_challenge_id', :'c1_secret'),
  '%no such challenge%');
RESET ROLE;

\echo '-- a rejected revision changes nothing and stays traceable'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.propose_revision(:'p1', 'decision', 'revision check: invoices due on receipt', 'supersede_memory',
                                 'rest', 'decision', p_dedup_key => 'rv-terms') AS p3 \gset
COMMIT;
SELECT t.decide(:'o5_user_id', :'o5_session_id', :'p3', 'reject') IS NOT NULL;
SELECT t.expect_error('a rejected revision cannot then be approved',
  format($$SELECT * FROM t.challenge(%L, %L, %L, 'approve')$$, :'o6_user_id', :'o6_session_id', :'p3'),
  '%already rejected%');
RESET ROLE;
SELECT t.expect_state('the rejected revision is on record', :'p3', 'proposed/rejected');
SELECT t.expect_state('the approved version is untouched', :'p1', 'active/approved');
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  UPDATE memory.memories SET status = 'retracted' WHERE id = :'p3';
  SELECT t.expect_denied('a withdrawn revision stays withdrawn',
    format($$UPDATE memory.memories SET status = 'proposed' WHERE id = %L$$, :'p3'));
COMMIT;
RESET ROLE;
SELECT t.expect_state('its writer can withdraw it, and the text is kept', :'p3', 'retracted/rejected');
SELECT t.expect_count('the text is still there',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND content = 'revision check: invoices due on receipt'$$, :'p3'), 1);

\echo '-- a revoked approver decides nothing'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.propose_revision(:'p1', 'decision', 'revision check: invoices due in 21 days', 'supersede_memory',
                                 'rest', 'decision', p_dedup_key => 'rv-terms') AS p4 \gset
COMMIT;
SELECT * FROM t.challenge(:'p1_user_id', :'p1_session_id', :'p4', 'approve') \gset rv_
RESET ROLE;
SET ROLE engramport_admin;
UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'owner_left' WHERE id = :'a_owner2';
RESET ROLE;
SET ROLE engramport_app;
SELECT t.expect_error('the revoked approver''s challenge',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'p1_user_id', :'p1_session_id', :'rv_challenge_id', :'rv_secret'),
  '%no longer valid%');
RESET ROLE;
SELECT t.expect_state('the proposal is still pending', :'p4', 'proposed/pending');
SELECT t.expect_state('and the approved version still current', :'p1', 'active/approved');

\echo '-- a grant limited to some claim types cannot replace a memory of another type'
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'rv-obs', 'Observation approver') RETURNING id AS obs \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ('rv-obs@client.test', :'c1', :'obs');
SET ROLE engramport_admin;
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, claim_types)
  VALUES (:'obs', :'c1', 'cell_knowledge', '{observation}') RETURNING id AS a_obs \gset
RESET ROLE;
SELECT t.accept(:'a_obs', 'rv-obs@client.test');
SELECT * FROM t.sign_in('rv-obs@client.test') \gset ob1_
SELECT * FROM t.sign_in('rv-obs@client.test') \gset ob2_
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.propose_revision(:'p1', 'decision', 'revision check: it was only ever an observation', 'supersede_memory',
                                 'rest', 'observation', p_dedup_key => 'rv-terms') AS p_obs \gset
COMMIT;
SELECT t.expect_error('an observation-only approver cannot review a revision of a decision',
  format($$SELECT * FROM memory.approval_review(%L, %L, %L)$$, :'ob1_user_id', :'ob1_session_id', :'p_obs'),
  '%no valid authority%');
SELECT t.expect_error('or take a challenge for it',
  format($$SELECT * FROM t.challenge(%L, %L, %L, 'approve')$$, :'ob2_user_id', :'ob2_session_id', :'p_obs'),
  '%no valid authority%');
RESET ROLE;
-- Even a challenge written directly under that authority is refused when deciding.
SELECT * FROM t.sign_in('rv-obs@client.test') \gset ob3_
INSERT INTO memory.approval_challenges (actor_id, namespace_id, memory_id, memory_version, content_sha256, action,
    authority_id, secret_sha256, sign_in_hash, expires_at, base_memory_id)
  SELECT :'obs', :'c1', id, memory.memory_version(id), content_sha256, 'approve', :'a_obs',
         sha256(decode(repeat('e', 64), 'hex')), sha256(uuid_send(:'ob3_session_id'::uuid)),
         now() + interval '10 minutes', :'p1'
  FROM memory.memories WHERE id = :'p_obs' RETURNING id AS ch_obs \gset
SET ROLE engramport_app;
SELECT t.expect_error('and so is a challenge under it',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'ob3_user_id', :'ob3_session_id', :'ch_obs', repeat('e', 64)),
  '%does not cover the version it would replace%');
RESET ROLE;
SELECT t.expect_state('the approved decision is untouched', :'p1', 'active/approved');
SELECT t.expect_state('and the revision still pending', :'p_obs', 'proposed/pending');
SELECT t.expect_count('an approver covering both can still review it',
  format($$SELECT 1 FROM memory.approval_review(%L, %L, %L)$$, :'o11_user_id', :'o11_session_id', :'p_obs'), 1);

\echo '-- cross-namespace: the other cell''s approver and keys reach nothing'
SET ROLE engramport_app;
SELECT t.expect_error('another cell''s approver cannot take a challenge',
  format($$SELECT * FROM t.challenge(%L, %L, %L, 'approve')$$, :'q1_user_id', :'q1_session_id', :'p4'),
  '%no valid authority%');
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT t.expect_denied('another cell''s key cannot withdraw it',
    format($$UPDATE memory.memories SET status = 'retracted' WHERE id = %L$$, :'p4'), true);
COMMIT;
RESET ROLE;
SELECT t.expect_state('nothing changed', :'p4', 'proposed/pending');

\echo '-- a decision is all or nothing'
SET ROLE engramport_app;
-- Rolled back after it succeeded: nothing of it stays, and the same challenge then works.
SELECT * FROM t.challenge(:'o6_user_id', :'o6_session_id', :'p4', 'approve') \gset rb_
BEGIN;
  SELECT memory.decide_approval_challenge(:'o6_user_id', :'o6_session_id', :'rb_challenge_id', :'rb_secret') IS NOT NULL;
  SELECT t.expect_state('inside the transaction the swap happened', :'p4', 'active/approved');
ROLLBACK;
RESET ROLE;
SELECT t.expect_state('rolled back, the proposal is pending again', :'p4', 'proposed/pending');
SELECT t.expect_state('and the approved version current again', :'p1', 'active/approved');
SELECT t.expect_count('no decision was kept',
  format($$SELECT 1 FROM memory.approvals WHERE challenge_id = %L$$, :'rb_challenge_id'), 0);
-- A failure in the last step undoes the decision too.
CREATE FUNCTION t.boom() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.id::text = current_setting('t.boom_id', true) AND NEW.status = 'superseded' THEN
    RAISE EXCEPTION 'boom';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER zz_boom BEFORE UPDATE ON memory.memories FOR EACH ROW EXECUTE FUNCTION t.boom();
SELECT set_config('t.boom_id', :'p1', false) \g /dev/null
SET ROLE engramport_app;
SELECT t.expect_error('a failure while superseding the old version',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o6_user_id', :'o6_session_id', :'rb_challenge_id', :'rb_secret'),
  'boom');
RESET ROLE;
DROP TRIGGER zz_boom ON memory.memories;
SELECT set_config('t.boom_id', '', false) \g /dev/null
SELECT t.expect_state('leaves the proposal pending', :'p4', 'proposed/pending');
SELECT t.expect_state('and the approved version current', :'p1', 'active/approved');
SELECT t.expect_count('and records no decision',
  format($$SELECT 1 FROM memory.approvals WHERE memory_id = %L$$, :'p4'), 0);
SET ROLE engramport_app;
SELECT memory.decide_approval_challenge(:'o6_user_id', :'o6_session_id', :'rb_challenge_id', :'rb_secret') IS NOT NULL;
RESET ROLE;
SELECT t.expect_state('then the same challenge goes through once', :'p4', 'active/approved');
SELECT t.expect_state('and supersedes the version it was bound to', :'p1', 'superseded/approved');

\echo '-- history is final'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT t.expect_denied('a superseded approved version cannot be brought back',
    format($$UPDATE memory.memories SET status = 'active' WHERE id = %L$$, :'b1'));
  SELECT t.expect_denied('or retracted',
    format($$UPDATE memory.memories SET status = 'retracted' WHERE id = %L$$, :'b1'));
COMMIT;
RESET ROLE;

\echo '-- only the app reaches proposing; the API roles reach nothing'
SELECT t.expect_count('no API role can propose',
  $$SELECT 1 FROM pg_roles r WHERE r.rolname IN ('anon', 'authenticated', 'service_role')
      AND has_function_privilege(r.oid, 'memory.propose_revision(uuid, memory.memory_kind, text, text, memory.transport, memory.claim_type, real, jsonb, text, text, text, text, jsonb)', 'EXECUTE')$$, 0);
SELECT t.expect_count('the admin sees which version a challenge was bound to, never its digest',
  $$SELECT 1 WHERE has_column_privilege('engramport_admin', 'memory.approval_challenges', 'base_memory_id', 'SELECT')
              AND NOT has_column_privilege('engramport_admin', 'memory.approval_challenges', 'content_sha256', 'SELECT')$$, 1);
