-- Tests for 0025_retraction_restore (founder decision D-02.3): a retracted
-- memory can be brought back by a person with authority over it for 30 days,
-- and after that the retraction is final. Run by db/test/run.sh after
-- grants_race_test.sh, on the fixtures and helpers of rls_test,
-- authority_test, challenge_test, revision_test and erasure_test.
\set ON_ERROR_STOP on
\set QUIET on
\set c1    '00000000-0000-7000-8000-000000000111'
\set c2    '00000000-0000-7000-8000-000000000112'
\set k_c1  '00000000-0000-7000-8000-0000000000f1'

-- Review, take a challenge and decide, the way the page will.
CREATE FUNCTION t.restore_challenge(p_user uuid, p_session uuid, p_memory uuid, OUT challenge_id uuid, OUT secret text)
LANGUAGE plpgsql AS $$
DECLARE v timestamptz;
BEGIN
  SELECT r.retracted_at INTO v FROM memory.restore_review(p_user, p_session, p_memory) r;
  SELECT x.challenge_id, x.secret INTO challenge_id, secret
  FROM memory.issue_restore_challenge(p_user, p_session, p_memory, v) x;
END $$;
CREATE FUNCTION t.restore(p_user uuid, p_session uuid, p_memory uuid) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE c record;
BEGIN
  SELECT * INTO c FROM t.restore_challenge(p_user, p_session, p_memory);
  RETURN memory.decide_restore_challenge(p_user, p_session, c.challenge_id, c.secret);
END $$;
-- Move a retraction's stamp, as only a test may: the stamp trigger keeps it
-- otherwise.
CREATE FUNCTION t.set_retracted_at(p_memory uuid, p_at timestamptz, p_from memory.memory_status) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  ALTER TABLE memory.memories DISABLE TRIGGER memories_retraction_stamp;
  UPDATE memory.memories SET retracted_at = p_at, retracted_from = p_from WHERE id = p_memory;
  ALTER TABLE memory.memories ENABLE TRIGGER memories_retraction_stamp;
END $$;
GRANT EXECUTE ON FUNCTION t.restore_challenge(uuid, uuid, uuid), t.restore(uuid, uuid, uuid) TO engramport_app;

SELECT id AS owner FROM memory.actors WHERE slug = 'er-owner' \gset
SELECT id AS a_owner FROM memory.approval_authorities WHERE actor_id = :'owner' AND parent_id IS NULL \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'rs-owner3', 'Third owner') RETURNING id AS owner3 \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ('rs-owner3@client.test', :'c1', :'owner3');
SET ROLE engramport_admin;
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
  VALUES (:'owner3', :'c1', 'cell_knowledge') RETURNING id AS a_owner3 \gset
RESET ROLE;
SELECT t.accept(:'a_owner3', 'rs-owner3@client.test');
SELECT id AS del FROM memory.actors WHERE slug = 'er-del' \gset

\echo '-- a retraction is stamped by the database'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('fact', 'restore check: the office opens at eight', 'remember', 'rest',
                         p_claim_type => 'fact', p_dedup_key => 'rs-hours') AS m1 \gset
  UPDATE memory.memories SET status = 'retracted' WHERE id = :'m1';
COMMIT;
RESET ROLE;
SELECT t.expect_count('retracted, with when and from what',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND status = 'retracted' AND retracted_from = 'active'
           AND retracted_at > now() - interval '1 minute'$$, :'m1'), 1);
SELECT retracted_at AS m1_at FROM memory.memories WHERE id = :'m1' \gset
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT t.expect_denied('an agent can''t move the stamp',
    format($$UPDATE memory.memories SET retracted_at = now() + interval '1 year' WHERE id = %L$$, :'m1'));
  SELECT t.expect_error('nor bring the memory back itself',
    format($$UPDATE memory.memories SET status = 'active' WHERE id = %L$$, :'m1'), '%retracted version stays that way%');
ROLLBACK;
RESET ROLE;
UPDATE memory.memories SET retracted_at = now() + interval '1 year', retracted_from = 'proposed' WHERE id = :'m1';
SELECT t.expect_count('and a direct write to the stamp is ignored',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND retracted_at = %L AND retracted_from = 'active'$$, :'m1', :'m1_at'), 1);

\echo '-- who may see it to restore it'
SELECT * FROM t.sign_in('er-owner@client.test') \gset o1_
SELECT * FROM t.sign_in('er-c2@client.test') \gset q1_
SELECT * FROM t.sign_in('er-obs@client.test') \gset b1_
SELECT * FROM t.sign_in('er-del@client.test') \gset d1_
SET ROLE engramport_app;
SELECT t.expect_count('the owner sees it, restorable for 30 days',
  format($$SELECT 1 FROM memory.restore_review(%L, %L, %L)
           WHERE retracted_from = 'active' AND refusal IS NULL AND restorable_until = retracted_at + interval '30 days'
             AND content = 'restore check: the office opens at eight'$$, :'o1_user_id', :'o1_session_id', :'m1'), 1);
SELECT t.expect_error('another cell''s owner does not',
  format($$SELECT * FROM memory.restore_review(%L, %L, %L)$$, :'q1_user_id', :'q1_session_id', :'m1'),
  '%no authority to restore%');
SELECT t.expect_error('nor does an owner limited to other claim types',
  format($$SELECT * FROM memory.restore_review(%L, %L, %L)$$, :'b1_user_id', :'b1_session_id', :'m1'),
  '%no authority to restore%');
SELECT t.expect_count('an approval delegate may, as they may approve it',
  format($$SELECT 1 FROM memory.restore_review(%L, %L, %L)$$, :'d1_user_id', :'d1_session_id', :'m1'), 1);
SELECT t.expect_error('a challenge is for the retraction that was shown',
  format($$SELECT * FROM memory.issue_restore_challenge(%L, %L, %L, now())$$, :'o1_user_id', :'o1_session_id', :'m1'),
  '%not the retraction you were shown%');
RESET ROLE;

\echo '-- a person restores it'
SELECT * FROM t.sign_in('er-owner@client.test') \gset o2_
SET ROLE engramport_app;
SELECT * FROM t.restore_challenge(:'o2_user_id', :'o2_session_id', :'m1') \gset ch1_
SELECT t.expect_error('no other sign-in can use the challenge',
  format($$SELECT memory.decide_restore_challenge(%L, %L, %L, %L)$$, :'o1_user_id', :'o1_session_id', :'ch1_challenge_id', :'ch1_secret'),
  '%no such challenge%');
RESET ROLE;
SELECT * FROM t.sign_in('er-owner@client.test') \gset o2b_
SET ROLE engramport_app;
SELECT t.expect_error('nor a wrong secret',
  format($$SELECT memory.decide_restore_challenge(%L, %L, %L, %L)$$, :'o2_user_id', :'o2_session_id', :'ch1_challenge_id',
         repeat('0', 64)), '%no such challenge%');
RESET ROLE;
SELECT * FROM t.sign_in('er-owner@client.test') \gset o3_
SET ROLE engramport_app;
SELECT * FROM t.restore_challenge(:'o3_user_id', :'o3_session_id', :'m1') \gset ch2_
SELECT memory.decide_restore_challenge(:'o3_user_id', :'o3_session_id', :'ch2_challenge_id', :'ch2_secret') ->> 'restored_to' AS restored_to \gset
RESET ROLE;
SELECT t.expect_count('it comes back as it was',
  format($$SELECT 1 WHERE %L = 'active'$$, :'restored_to'), 1);
SELECT t.expect_state('current again, approval unchanged', :'m1', 'active/none');
SELECT t.expect_count('and unstamped',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND retracted_at IS NULL AND retracted_from IS NULL$$, :'m1'), 1);
SELECT t.expect_count('recorded: who, under which authority, which challenge, which retraction',
  format($$SELECT 1 FROM memory.restorations WHERE memory_id = %L AND restored_by_actor_id = %L AND authority_id = %L
           AND challenge_id = %L AND retracted_at = %L AND restored_to = 'active'$$,
         :'m1', :'owner', :'a_owner', :'ch2_challenge_id', :'m1_at'), 1);
SET ROLE engramport_app;
SELECT t.expect_error('its sign-in is spent',
  format($$SELECT memory.decide_restore_challenge(%L, %L, %L, %L)$$, :'o3_user_id', :'o3_session_id', :'ch2_challenge_id', :'ch2_secret'),
  '%already used%');
RESET ROLE;
SELECT * FROM t.sign_in('er-owner@client.test') \gset o4_
SET ROLE engramport_app;
SELECT t.expect_error('the earlier challenge, for the same retraction, no longer fits',
  format($$SELECT memory.decide_restore_challenge(%L, %L, %L, %L)$$, :'o2b_user_id', :'o2b_session_id', :'ch1_challenge_id', :'ch1_secret'),
  '%no such challenge%');
SELECT t.expect_error('and a memory that is not retracted is not restored',
  format($$SELECT * FROM memory.issue_restore_challenge(%L, %L, %L, %L)$$, :'o4_user_id', :'o4_session_id', :'m1', :'m1_at'),
  '%not retracted%');
RESET ROLE;

\echo '-- retracted again, an old challenge does not fit the new retraction'
SELECT * FROM t.sign_in('er-owner@client.test') \gset o5_
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  UPDATE memory.memories SET status = 'retracted' WHERE id = :'m1';
COMMIT;
SELECT * FROM t.restore_challenge(:'o5_user_id', :'o5_session_id', :'m1') \gset ch3_
RESET ROLE;
SELECT t.set_retracted_at(:'m1', clock_timestamp() - interval '1 day', 'active');
SELECT * FROM t.sign_in('er-owner@client.test') \gset o6_
SET ROLE engramport_app;
SELECT t.expect_error('a challenge taken for another retraction is refused',
  format($$SELECT memory.decide_restore_challenge(%L, %L, %L, %L)$$, :'o5_user_id', :'o5_session_id', :'ch3_challenge_id', :'ch3_secret'),
  '%changed since you reviewed it%');
RESET ROLE;
SELECT t.expect_state('and the memory stays retracted', :'m1', 'retracted/none');

\echo '-- after 30 days the retraction is final'
SELECT t.set_retracted_at(:'m1', clock_timestamp() - interval '30 days 1 second', 'active');
SET ROLE engramport_app;
SELECT t.expect_count('the page says it is final',
  format($$SELECT 1 FROM memory.restore_review(%L, %L, %L) WHERE refusal LIKE '%%30 days to restore it have passed%%'$$,
         :'o6_user_id', :'o6_session_id', :'m1'), 1);
SELECT t.expect_error('and no challenge is issued',
  format($$SELECT * FROM memory.issue_restore_challenge(%L, %L, %L, (SELECT retracted_at FROM memory.restore_review(%L, %L, %L)))$$,
         :'o6_user_id', :'o6_session_id', :'m1', :'o6_user_id', :'o6_session_id', :'m1'),
  '%30 days to restore it have passed%');
RESET ROLE;
SELECT * FROM t.sign_in('er-owner@client.test') \gset o7_
SELECT t.set_retracted_at(:'m1', clock_timestamp() - interval '30 days' + interval '2 seconds', 'active');
SET ROLE engramport_app;
SELECT * FROM t.restore_challenge(:'o7_user_id', :'o7_session_id', :'m1') \gset ch4_
SELECT pg_sleep(2.5);
SELECT t.expect_error('a challenge taken just inside the window is refused once it has passed',
  format($$SELECT memory.decide_restore_challenge(%L, %L, %L, %L)$$, :'o7_user_id', :'o7_session_id', :'ch4_challenge_id', :'ch4_secret'),
  '%30 days to restore it have passed%');
RESET ROLE;
SELECT t.expect_state('it stays retracted', :'m1', 'retracted/none');
SELECT t.set_retracted_at(:'m1', NULL, NULL);
SELECT * FROM t.sign_in('er-owner@client.test') \gset o8_
SET ROLE engramport_app;
SELECT t.expect_count('a retraction made before restoring existed is final too',
  format($$SELECT 1 FROM memory.restore_review(%L, %L, %L) WHERE refusal LIKE '%%made before restoring was possible%%'$$,
         :'o8_user_id', :'o8_session_id', :'m1'), 1);
RESET ROLE;

\echo '-- what can come back, and to what'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('fact', 'restore check: a version later replaced', 'remember', 'rest', p_claim_type => 'fact') AS old \gset
  UPDATE memory.memories SET status = 'superseded' WHERE id = :'old';
  UPDATE memory.memories SET status = 'retracted' WHERE id = :'old';
  SELECT memory.remember('fact', 'restore check: the first holder of a key', 'remember', 'rest',
                         p_claim_type => 'fact', p_dedup_key => 'rs-dup') AS dup1 \gset
  UPDATE memory.memories SET status = 'retracted' WHERE id = :'dup1';
  SELECT memory.remember('fact', 'restore check: the next holder of the key', 'remember', 'rest',
                         p_claim_type => 'fact', p_dedup_key => 'rs-dup') AS dup2 \gset
COMMIT;
RESET ROLE;
SELECT * FROM t.sign_in('er-owner@client.test') \gset o9_
SET ROLE engramport_app;
SELECT t.expect_count('a version already replaced has nothing to come back to',
  format($$SELECT 1 FROM memory.restore_review(%L, %L, %L) WHERE retracted_from = 'superseded' AND refusal LIKE '%%nothing to restore it to%%'$$,
         :'o9_user_id', :'o9_session_id', :'old'), 1);
SELECT t.expect_count('a memory whose key another current memory now holds stays retracted',
  format($$SELECT 1 FROM memory.restore_review(%L, %L, %L) WHERE refusal LIKE '%%another current memory now holds%%'$$,
         :'o9_user_id', :'o9_session_id', :'dup1'), 1);
RESET ROLE;

\echo '-- a withdrawn revision comes back as a proposal, while what it revises is current'
SELECT * FROM t.sign_in('er-owner@client.test') \gset p1_
SELECT * FROM t.sign_in('er-owner@client.test') \gset p3_
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('fact', 'restore check: the approved version', 'remember', 'rest', p_claim_type => 'fact') AS base \gset
COMMIT;
SELECT t.decide(:'p1_user_id', :'p1_session_id', :'base', 'approve') IS NOT NULL;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.propose_revision(:'base', 'fact', 'restore check: a revision that was withdrawn', 'supersede_memory',
                                 'rest', 'fact') AS rev \gset
  UPDATE memory.memories SET status = 'retracted' WHERE id = :'rev';
COMMIT;
RESET ROLE;
SELECT t.expect_count('withdrawn, it was retracted from proposed',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND status = 'retracted' AND retracted_from = 'proposed'$$, :'rev'), 1);
SET ROLE engramport_app;
SELECT t.restore(:'p3_user_id', :'p3_session_id', :'rev') ->> 'restored_to' AS rev_to \gset
RESET ROLE;
SELECT t.expect_count('restored, it is a proposal again',
  format($$SELECT 1 WHERE %L = 'proposed'$$, :'rev_to'), 1);
SELECT t.expect_state('waiting on a person, as before', :'rev', 'proposed/pending');
SELECT t.expect_state('and the approved version is untouched', :'base', 'active/approved');
SELECT * FROM t.sign_in('er-owner@client.test') \gset p5_
SELECT * FROM t.sign_in('er-owner@client.test') \gset p6_
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  UPDATE memory.memories SET status = 'retracted' WHERE id = :'rev';
  SELECT memory.propose_revision(:'base', 'fact', 'restore check: the revision that was approved', 'supersede_memory',
                                 'rest', 'fact') AS rev2 \gset
COMMIT;
SELECT t.decide(:'p5_user_id', :'p5_session_id', :'rev2', 'approve') IS NOT NULL;
SELECT t.expect_count('once another revision replaced that version, the old proposal stays retracted',
  format($$SELECT 1 FROM memory.restore_review(%L, %L, %L) WHERE refusal LIKE '%%no longer the current approved one%%'$$,
         :'p6_user_id', :'p6_session_id', :'rev'), 1);
RESET ROLE;

\echo '-- an authority revoked between the challenge and the decision stops it'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('fact', 'restore check: restored too late by a revoked owner', 'remember', 'rest',
                         p_claim_type => 'fact') AS m4 \gset
  UPDATE memory.memories SET status = 'retracted' WHERE id = :'m4';
COMMIT;
RESET ROLE;
SELECT * FROM t.sign_in('rs-owner3@client.test') \gset w1_
SET ROLE engramport_app;
SELECT * FROM t.restore_challenge(:'w1_user_id', :'w1_session_id', :'m4') \gset ch5_
RESET ROLE;
SET ROLE engramport_admin;
UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'owner_left' WHERE id = :'a_owner3';
RESET ROLE;
SET ROLE engramport_app;
SELECT t.expect_error('the revoked owner''s challenge is refused',
  format($$SELECT memory.decide_restore_challenge(%L, %L, %L, %L)$$, :'w1_user_id', :'w1_session_id', :'ch5_challenge_id', :'ch5_secret'),
  '%no longer valid%');
RESET ROLE;
SELECT t.expect_state('and the memory stays retracted', :'m4', 'retracted/none');

\echo '-- an erased memory is never restored'
SELECT * FROM t.sign_in('er-owner@client.test') \gset e1_
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.request_erasure(ARRAY[:'m4']::uuid[], 'owner_request') AS ereq \gset
COMMIT;
SELECT t.erase(:'e1_user_id', :'e1_session_id', :'ereq') IS NOT NULL;
RESET ROLE;
SELECT * FROM t.sign_in('er-owner@client.test') \gset e2_
SET ROLE engramport_app;
SELECT t.expect_error('it is not found',
  format($$SELECT * FROM memory.restore_review(%L, %L, %L)$$, :'e2_user_id', :'e2_session_id', :'m4'),
  '%not found%');
RESET ROLE;
SELECT t.expect_count('the stamp outlives the erasure, holding nothing of the text',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND status = 'erased' AND retracted_at IS NOT NULL$$, :'m4'), 1);

\echo '-- the records'
SET ROLE engramport_app;
SELECT t.expect_denied('the server writes no restoration itself',
  format($$INSERT INTO memory.restorations (memory_id, namespace_id, restored_by_actor_id, authority_id, challenge_id,
           retracted_at, restored_to) SELECT memory_id, namespace_id, restored_by_actor_id, authority_id, challenge_id,
           retracted_at, restored_to FROM memory.restorations LIMIT 1$$));
SELECT t.expect_denied('nor reads one', $$SELECT * FROM memory.restorations$$);
SELECT t.expect_denied('nor any challenge', $$SELECT * FROM memory.restore_challenges$$);
RESET ROLE;
SELECT t.expect_error('a restoration is never changed',
  $$UPDATE memory.restorations SET restored_at = now()$$, '%is a record%');
SELECT t.expect_error('nor deleted', $$DELETE FROM memory.restorations$$, '%is a record%');
SELECT t.expect_error('nor is a challenge', $$DELETE FROM memory.restore_challenges$$, '%is a record%');
SET ROLE engramport_admin;
SELECT t.expect_count('the admin sees who restored what, and when',
  $$SELECT 1 FROM memory.restorations$$, 2);
SELECT t.expect_count('and the challenges, without secrets or sign-ins',
  $$SELECT id, memory_id, actor_id, authority_id, retracted_at, issued_at, expires_at FROM memory.restore_challenges$$, 6);
SELECT t.expect_denied('never a secret', $$SELECT secret_sha256 FROM memory.restore_challenges$$);
SELECT t.expect_denied('nor a sign-in', $$SELECT sign_in_hash FROM memory.restore_challenges$$);
RESET ROLE;
SELECT t.expect_count('no API role reaches a restore function',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) r(role),
           unnest(ARRAY['memory.restore_review(uuid,uuid,uuid)', 'memory.issue_restore_challenge(uuid,uuid,uuid,timestamptz)',
                        'memory.decide_restore_challenge(uuid,uuid,uuid,text)']) f(fn)
    WHERE has_function_privilege(r.role, f.fn, 'EXECUTE')$$, 0);

\echo 'all restore tests passed'
