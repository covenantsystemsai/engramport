-- Tests for 0018_approval_challenges (founder decision D-03B). Run by
-- db/test/run.sh after acceptance_test.sql, on the rls_test namespaces and
-- keys and the helpers from authority_test (t.sign_in, t.accept).
\set ON_ERROR_STOP on
\set QUIET on
\set c1   '00000000-0000-7000-8000-000000000111'
\set k_c1 '00000000-0000-7000-8000-0000000000f1'
\set agent '00000000-0000-7000-8000-00000000a001'

-- The statement must fail with a message matching p_like.
CREATE FUNCTION t.expect_error(p_name text, p_sql text, p_like text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  BEGIN
    EXECUTE p_sql;
  EXCEPTION WHEN OTHERS THEN
    IF SQLERRM NOT LIKE p_like THEN
      RAISE EXCEPTION 'FAIL %: wanted an error like "%", got "%" (%)', p_name, p_like, SQLERRM, SQLSTATE;
    END IF;
    RAISE NOTICE 'pass % (%)', p_name, SQLSTATE;
    RETURN;
  END;
  RAISE EXCEPTION 'FAIL %: statement succeeded', p_name;
END $$;

-- Review then take a challenge, the way the page does before it asks the
-- person to confirm.
CREATE FUNCTION t.challenge(p_user uuid, p_session uuid, p_memory uuid, p_action memory.approval_action,
                            OUT challenge_id uuid, OUT secret text) LANGUAGE plpgsql AS $$
DECLARE r record;
BEGIN
  SELECT * INTO r FROM memory.approval_review(p_user, p_session, p_memory);
  SELECT c.challenge_id, c.secret INTO challenge_id, secret
  FROM memory.issue_approval_challenge(p_user, p_session, p_memory, p_action, r.content_sha256, r.memory_version) c;
END $$;

INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'ch-owner', 'Challenge owner') RETURNING id AS owner \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'ch-owner2', 'Second owner') RETURNING id AS owner2 \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'ch-staff', 'Staff') RETURNING id AS staff \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'ch-other', 'No authority') RETURNING id AS other \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES
  ('ch-owner@client.test', :'c1', :'owner'),
  ('ch-owner2@client.test', :'c1', :'owner2'),
  ('ch-staff@client.test', :'c1', :'staff'),
  ('ch-other@client.test', :'c1', :'other'),
  ('ch-agent@client.test', :'c1', :'agent');

SET ROLE engramport_admin;
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
  VALUES (:'owner', :'c1', 'cell_knowledge') RETURNING id AS a_owner \gset
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, can_delegate)
  VALUES (:'owner2', :'c1', 'cell_knowledge', true) RETURNING id AS a_owner2 \gset
RESET ROLE;
SELECT t.accept(:'a_owner', 'ch-owner@client.test');
SELECT t.accept(:'a_owner2', 'ch-owner2@client.test');
SELECT * FROM t.sign_in('ch-owner2@client.test') \gset d_
SET ROLE engramport_app;
SELECT memory.delegate_approval_authority(:'d_user_id', :'d_session_id', :'a_owner2', :'staff', '{decision}') AS a_staff \gset
RESET ROLE;
SELECT t.accept(:'a_staff', 'ch-staff@client.test');

SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('decision', 'challenge check: one', 'remember', 'rest', p_claim_type => 'decision') AS m1 \gset
  SELECT memory.remember('decision', 'challenge check: rejected', 'remember', 'rest', p_claim_type => 'decision') AS m_rej \gset
  SELECT memory.remember('decision', 'challenge check: superseded', 'remember', 'rest', p_claim_type => 'decision') AS m_sup \gset
  SELECT memory.remember('decision', 'challenge check: retracted', 'remember', 'rest', p_claim_type => 'decision') AS m_ret \gset
  SELECT memory.remember('decision', 'challenge check: re-versioned', 'remember', 'rest', p_claim_type => 'decision') AS m_ver \gset
  SELECT memory.remember('decision', 'challenge check: older', 'remember', 'rest', p_claim_type => 'decision') AS m_old \gset
  SELECT memory.remember('decision', 'challenge check: two approvers', 'remember', 'rest', p_claim_type => 'decision') AS m_two \gset
  SELECT memory.remember('decision', 'challenge check: revoked', 'remember', 'rest', p_claim_type => 'decision') AS m_rev \gset
  SELECT memory.remember('decision', 'challenge check: expired', 'remember', 'rest', p_claim_type => 'decision') AS m_exp \gset
  SELECT memory.remember('fact', 'challenge check: a fact', 'remember', 'rest', p_claim_type => 'fact') AS m_fact \gset
COMMIT;
RESET ROLE;
SELECT content_sha256 AS h1 FROM memory.memories WHERE id = :'m1' \gset
SELECT path AS c1_path FROM memory.namespaces WHERE id = :'c1' \gset

SELECT * FROM t.sign_in('ch-owner@client.test') \gset o1_
SELECT * FROM t.sign_in('ch-owner@client.test') \gset o2_
SELECT * FROM t.sign_in('ch-owner@client.test') \gset o3_
SELECT * FROM t.sign_in('ch-owner@client.test') \gset o4_
SELECT * FROM t.sign_in('ch-owner@client.test') \gset o5_
SELECT * FROM t.sign_in('ch-owner@client.test') \gset o6_
SELECT * FROM t.sign_in('ch-owner@client.test') \gset o7_
SELECT * FROM t.sign_in('ch-owner@client.test') \gset o8_
SELECT * FROM t.sign_in('ch-owner2@client.test') \gset p1_
SELECT * FROM t.sign_in('ch-staff@client.test') \gset s1_
SELECT * FROM t.sign_in('ch-staff@client.test') \gset s2_
SELECT * FROM t.sign_in('ch-owner@client.test') \gset o9_
SELECT * FROM t.sign_in('ch-other@client.test') \gset x1_
SELECT * FROM t.sign_in('ch-agent@client.test') \gset bot_

SELECT set_config('t.o1u', :'o1_user_id', false), set_config('t.o1s', :'o1_session_id', false),
       set_config('t.x1u', :'x1_user_id', false), set_config('t.x1s', :'x1_session_id', false),
       set_config('t.m1', :'m1', false) \g /dev/null

\echo '-- review: the approver sees the exact version, and nothing is spent'
SET ROLE engramport_app;
SELECT t.expect_count('the review shows the text, its digest, version 1 and where it lives',
  format($$SELECT 1 FROM memory.approval_review(%L, %L, %L)
           WHERE content = 'challenge check: one' AND content_sha256 = %L AND memory_version = 1
             AND namespace_path = %L AND scope = 'cell_knowledge' AND status = 'active'$$,
         :'o1_user_id', :'o1_session_id', :'m1', :'h1', :'c1_path'), 1);
RESET ROLE;
SELECT t.expect_count('reviewing does not spend the sign-in',
  format($$SELECT 1 FROM memory.human_sign_ins_used WHERE session_hash = sha256(uuid_send(%L::uuid))$$, :'o1_session_id'), 0);
SELECT t.expect_count('or record a challenge',
  format($$SELECT 1 FROM memory.approval_challenges WHERE sign_in_hash = sha256(uuid_send(%L::uuid))$$, :'o1_session_id'), 0);
SET ROLE engramport_app;
DO $$
DECLARE e1 text; e2 text;
BEGIN
  BEGIN
    PERFORM memory.approval_review(current_setting('t.x1u')::uuid, current_setting('t.x1s')::uuid, current_setting('t.m1')::uuid);
  EXCEPTION WHEN OTHERS THEN e1 := SQLSTATE || ' ' || SQLERRM;
  END;
  BEGIN
    PERFORM memory.approval_review(current_setting('t.o1u')::uuid, current_setting('t.o1s')::uuid, gen_random_uuid());
  EXCEPTION WHEN OTHERS THEN e2 := SQLSTATE || ' ' || SQLERRM;
  END;
  IF e1 IS NULL OR e1 IS DISTINCT FROM e2 THEN
    RAISE EXCEPTION 'FAIL no authority and no memory must look the same on review: % / %', e1, e2;
  END IF;
  RAISE NOTICE 'pass on review, no authority and no memory give the same answer';
END $$;
SELECT t.expect_error('an agent cannot review',
  format($$SELECT * FROM memory.approval_review(%L, %L, %L)$$, :'bot_user_id', :'bot_session_id', :'m1'),
  '%not one enabled person%');
SELECT t.expect_error('nor can anyone without a sign-in',
  format($$SELECT * FROM memory.approval_review(%L, %L, %L)$$, gen_random_uuid(), gen_random_uuid(), :'m1'),
  '%fresh Google sign-in%');
SELECT t.expect_error('a delegate sees only what the delegation covers',
  format($$SELECT * FROM memory.approval_review(%L, %L, %L)$$, :'s1_user_id', :'s1_session_id', :'m_fact'),
  '%no valid authority%');
RESET ROLE;

\echo '-- a challenge binds one action on one exact version to one sign-in'
SET ROLE engramport_app;
SELECT t.expect_error('a challenge needs the digest the person was shown',
  format($$SELECT * FROM memory.issue_approval_challenge(%L, %L, %L, 'approve', %L, 1)$$,
         :'o1_user_id', :'o1_session_id', :'m1', repeat('0', 64)), '%not the text you were shown%');
SELECT t.expect_error('and the version they were shown',
  format($$SELECT * FROM memory.issue_approval_challenge(%L, %L, %L, 'approve', %L, 2)$$,
         :'o1_user_id', :'o1_session_id', :'m1', :'h1'), '%not the text you were shown%');
SELECT t.expect_error('and an action',
  format($$SELECT * FROM memory.issue_approval_challenge(%L, %L, %L, NULL, %L, 1)$$,
         :'o1_user_id', :'o1_session_id', :'m1', :'h1'), '%approve or reject%');
SELECT challenge_id AS ch1, secret AS sec1, expires_at AS ch1_exp
  FROM memory.issue_approval_challenge(:'o1_user_id', :'o1_session_id', :'m1', 'approve', :'h1', 1) \gset
SELECT t.expect_error('one sign-in takes one challenge',
  format($$SELECT * FROM memory.issue_approval_challenge(%L, %L, %L, 'reject', %L, 1)$$,
         :'o1_user_id', :'o1_session_id', :'m1', :'h1'), '%already used%');
RESET ROLE;
SELECT t.expect_count('the secret is 256 random bits, hex',
  format($$SELECT 1 WHERE %L ~ '^[0-9a-f]{64}$'$$, :'sec1'), 1);
SELECT t.expect_count('it expires in ten minutes',
  format($$SELECT 1 WHERE %L::timestamptz BETWEEN now() + interval '9 minutes' AND now() + interval '11 minutes'$$, :'ch1_exp'), 1);
SELECT t.expect_count('the challenge records who, where, what, which version, which digest and which authority',
  format($$SELECT 1 FROM memory.approval_challenges WHERE id = %L AND actor_id = %L AND namespace_id = %L
             AND memory_id = %L AND memory_version = 1 AND content_sha256 = %L AND action = 'approve'
             AND authority_id = %L AND sign_in_hash = sha256(uuid_send(%L::uuid))$$,
         :'ch1', :'owner', :'c1', :'m1', :'h1', :'a_owner', :'o1_session_id'), 1);
SELECT t.expect_count('only the secret''s hash is kept',
  format($$SELECT 1 FROM memory.approval_challenges WHERE id = %L AND secret_sha256 = sha256(decode(%L, 'hex'))
             AND secret_sha256 <> decode(%L, 'hex')$$, :'ch1', :'sec1', :'sec1'), 1);
SELECT t.expect_count('issuing still does not spend the sign-in',
  format($$SELECT 1 FROM memory.human_sign_ins_used WHERE session_hash = sha256(uuid_send(%L::uuid))$$, :'o1_session_id'), 0);

-- A sign-in already used to connect a client cannot take a challenge.
INSERT INTO memory.human_sign_ins_used (session_hash, actor_id, purpose)
  VALUES (sha256(uuid_send(:'o8_session_id'::uuid)), :'owner', 'connect');
SET ROLE engramport_app;
SELECT t.expect_error('a sign-in spent on connecting cannot take a challenge',
  format($$SELECT * FROM memory.issue_approval_challenge(%L, %L, %L, 'approve', %L, 1)$$,
         :'o8_user_id', :'o8_session_id', :'m1', :'h1'), '%already used%');
RESET ROLE;

\echo '-- deciding: only the same person, the same sign-in and the secret'
SET ROLE engramport_app;
SELECT t.expect_error('a wrong secret is refused',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o1_user_id', :'o1_session_id', :'ch1', repeat('a', 64)),
  'no such challenge for this sign-in');
SELECT t.expect_error('with the same answer as no challenge at all',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o1_user_id', :'o1_session_id', gen_random_uuid(), :'sec1'),
  'no such challenge for this sign-in');
SELECT t.expect_error('someone else with the secret is refused',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'x1_user_id', :'x1_session_id', :'ch1', :'sec1'),
  'no such challenge for this sign-in');
SELECT t.expect_error('the same person on another sign-in is refused',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o2_user_id', :'o2_session_id', :'ch1', :'sec1'),
  'no such challenge for this sign-in');
SELECT t.expect_error('an agent is refused',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'bot_user_id', :'bot_session_id', :'ch1', :'sec1'),
  '%not one enabled person%');
SELECT t.expect_error('a malformed secret is refused',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, 'secret')$$, :'o1_user_id', :'o1_session_id', :'ch1'),
  '%64 lowercase hex%');
RESET ROLE;
SELECT t.expect_count('refused attempts recorded nothing',
  format($$SELECT 1 FROM memory.approvals WHERE challenge_id = %L$$, :'ch1'), 0);
SET ROLE engramport_app;
SELECT memory.decide_approval_challenge(:'o1_user_id', :'o1_session_id', :'ch1', :'sec1') AS ap1 \gset
SELECT t.expect_error('a used challenge cannot be replayed',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o1_user_id', :'o1_session_id', :'ch1', :'sec1'),
  '%already used%');
SELECT t.expect_error('and its sign-in cannot take another challenge',
  format($$SELECT * FROM memory.issue_approval_challenge(%L, %L, %L, 'approve', %L, 1)$$,
         :'o1_user_id', :'o1_session_id', :'m_two', :'h1'), '%already used%');
RESET ROLE;
SELECT t.expect_count('the decision consumed exactly that challenge and that sign-in',
  format($$SELECT 1 FROM memory.approvals a JOIN memory.memories m ON m.id = a.memory_id
           WHERE a.id = %L AND a.challenge_id = %L AND a.action = 'approve' AND a.authority_id = %L
             AND a.sign_in_hash = sha256(uuid_send(%L::uuid)) AND m.approval_state = 'approved'$$,
         :'ap1', :'ch1', :'a_owner', :'o1_session_id'), 1);
SELECT t.expect_count('and the sign-in is spent on approving',
  format($$SELECT 1 FROM memory.human_sign_ins_used WHERE session_hash = sha256(uuid_send(%L::uuid)) AND purpose = 'approve'$$,
         :'o1_session_id'), 1);

\echo '-- the action is the one the challenge was taken for'
SET ROLE engramport_app;
SELECT * FROM t.challenge(:'o2_user_id', :'o2_session_id', :'m_rej', 'reject') \gset rj_
SELECT memory.decide_approval_challenge(:'o2_user_id', :'o2_session_id', :'rj_challenge_id', :'rj_secret') IS NOT NULL;
RESET ROLE;
SELECT t.expect_count('a reject challenge rejects',
  format($$SELECT 1 FROM memory.memories m JOIN memory.approvals a ON a.memory_id = m.id
           WHERE m.id = %L AND m.approval_state = 'rejected' AND a.action = 'reject'$$, :'m_rej'), 1);

\echo '-- a challenge dies when what it is bound to changes'
SET ROLE engramport_app;
SELECT * FROM t.challenge(:'o3_user_id', :'o3_session_id', :'m_sup', 'approve') \gset sup_
SELECT * FROM t.challenge(:'o4_user_id', :'o4_session_id', :'m_ret', 'approve') \gset ret_
SELECT * FROM t.challenge(:'o5_user_id', :'o5_session_id', :'m_ver', 'approve') \gset ver_
SELECT * FROM t.challenge(:'o6_user_id', :'o6_session_id', :'m_two', 'approve') \gset two_o_
SELECT * FROM t.challenge(:'s1_user_id', :'s1_session_id', :'m_two', 'approve') \gset two_s_
SELECT * FROM t.challenge(:'p1_user_id', :'p1_session_id', :'m_rev', 'approve') \gset rev_p_
SELECT * FROM t.challenge(:'s2_user_id', :'s2_session_id', :'m_rev', 'approve') \gset rev_s_
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  UPDATE memory.memories SET status = 'superseded' WHERE id = :'m_sup';
  UPDATE memory.memories SET status = 'retracted' WHERE id = :'m_ret';
  UPDATE memory.memories SET supersedes_id = :'m_old' WHERE id = :'m_ver';
COMMIT;
SELECT t.expect_error('a superseded memory',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o3_user_id', :'o3_session_id', :'sup_challenge_id', :'sup_secret'),
  '%no longer active%');
SELECT t.expect_error('a retracted memory',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o4_user_id', :'o4_session_id', :'ret_challenge_id', :'ret_secret'),
  '%no longer active%');
SELECT t.expect_error('a memory whose version changed',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o5_user_id', :'o5_session_id', :'ver_challenge_id', :'ver_secret'),
  '%not the text you were shown%');
SELECT memory.decide_approval_challenge(:'s1_user_id', :'s1_session_id', :'two_s_challenge_id', :'two_s_secret') IS NOT NULL;
SELECT t.expect_error('a memory someone else decided first',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o6_user_id', :'o6_session_id', :'two_o_challenge_id', :'two_o_secret'),
  '%already approved%');
RESET ROLE;
SET ROLE engramport_admin;
UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'owner_left' WHERE id = :'a_owner2';
RESET ROLE;
SET ROLE engramport_app;
SELECT t.expect_error('an authority revoked after the challenge',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'p1_user_id', :'p1_session_id', :'rev_p_challenge_id', :'rev_p_secret'),
  '%no longer valid%');
SELECT t.expect_error('a delegation whose parent was revoked after the challenge',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'s2_user_id', :'s2_session_id', :'rev_s_challenge_id', :'rev_s_secret'),
  '%no longer valid%');
RESET ROLE;

-- An expired challenge, written directly with a known secret.
INSERT INTO memory.approval_challenges (actor_id, namespace_id, memory_id, memory_version, content_sha256, action,
    authority_id, secret_sha256, sign_in_hash, issued_at, expires_at)
  SELECT :'owner', :'c1', id, 1, content_sha256, 'approve', :'a_owner', sha256(decode(repeat('b', 64), 'hex')),
         sha256(uuid_send(:'o7_session_id'::uuid)), now() - interval '20 minutes', now() - interval '10 minutes'
  FROM memory.memories WHERE id = :'m_exp' RETURNING id AS ch_exp \gset
SET ROLE engramport_app;
SELECT t.expect_error('an expired challenge',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o7_user_id', :'o7_session_id', :'ch_exp', repeat('b', 64)),
  '%expired%');
RESET ROLE;
SELECT t.expect_count('none of the dead challenges decided anything',
  format($$SELECT 1 FROM memory.approvals WHERE memory_id IN (%L, %L, %L, %L, %L)$$,
         :'m_sup', :'m_ret', :'m_ver', :'m_rev', :'m_exp'), 0);

-- A disabled approver.
SET ROLE engramport_app;
SELECT * FROM t.challenge(:'o9_user_id', :'o9_session_id', :'m_ver', 'approve') \gset dis_
RESET ROLE;
UPDATE memory.actors SET disabled_at = now() WHERE id = :'owner';
SET ROLE engramport_app;
SELECT t.expect_error('a disabled approver',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o9_user_id', :'o9_session_id', :'dis_challenge_id', :'dis_secret'),
  '%not one enabled person%');
RESET ROLE;
UPDATE memory.actors SET disabled_at = NULL WHERE id = :'owner';

\echo '-- challenges are records, and who sees what'
SELECT t.expect_denied('a challenge cannot be changed',
  format($$UPDATE memory.approval_challenges SET expires_at = now() + interval '1 day' WHERE id = %L$$, :'ch_exp'));
SELECT t.expect_denied('or deleted',
  format($$DELETE FROM memory.approval_challenges WHERE id = %L$$, :'ch_exp'));
SELECT t.expect_denied('or truncated', 'TRUNCATE memory.approval_challenges CASCADE');
SELECT t.expect_count('the old one-call decision is gone',
  $$SELECT 1 WHERE to_regprocedure('memory.record_approval(uuid, uuid, uuid, memory.approval_action, text)') IS NOT NULL$$, 0);

SET ROLE engramport_admin;
SELECT t.expect_count('the admin sees who took which challenge, for what, and whether it was used',
  format($$SELECT 1 FROM memory.approval_challenges c JOIN memory.approvals a ON a.challenge_id = c.id
           WHERE c.id = %L AND c.actor_id = %L AND c.memory_id = %L AND c.action = 'approve'$$, :'ch1', :'owner', :'m1'), 1);
SELECT t.expect_denied('but not the secret', 'SELECT secret_sha256 FROM memory.approval_challenges');
SELECT t.expect_denied('or the sign-in', 'SELECT sign_in_hash FROM memory.approval_challenges');
SELECT t.expect_denied('or the digest', 'SELECT content_sha256 FROM memory.approval_challenges');
SELECT t.expect_denied('and it cannot review',
  format($$SELECT * FROM memory.approval_review(%L, %L, %L)$$, :'o2_user_id', :'o2_session_id', :'m1'));
SELECT t.expect_denied('take a challenge',
  format($$SELECT * FROM memory.issue_approval_challenge(%L, %L, %L, 'approve', %L, 1)$$, :'o2_user_id', :'o2_session_id', :'m1', :'h1'));
SELECT t.expect_denied('or decide',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o2_user_id', :'o2_session_id', :'ch1', :'sec1'));
SELECT t.expect_denied('or write a challenge',
  format($$INSERT INTO memory.approval_challenges (actor_id, namespace_id, memory_id, memory_version, content_sha256, action,
             authority_id, secret_sha256, sign_in_hash, expires_at)
           VALUES (%L, %L, %L, 1, %L, 'approve', %L, sha256('x'), sha256('y'), now() + interval '1 minute')$$,
         :'owner', :'c1', :'m_two', :'h1', :'a_owner'));
RESET ROLE;

SET ROLE engramport_app;
SELECT t.expect_denied('the server cannot read challenges directly', 'SELECT id FROM memory.approval_challenges');
SELECT t.expect_denied('or write one',
  format($$INSERT INTO memory.approval_challenges (actor_id, namespace_id, memory_id, memory_version, content_sha256, action,
             authority_id, secret_sha256, sign_in_hash, expires_at)
           VALUES (%L, %L, %L, 1, %L, 'approve', %L, sha256('x'), sha256('y'), now() + interval '1 minute')$$,
         :'owner', :'c1', :'m_two', :'h1', :'a_owner'));
SELECT t.expect_denied('or call the helpers directly',
  format($$SELECT memory.unspent_human_sign_in(%L, %L)$$, :'o2_user_id', :'o2_session_id'));
SELECT t.expect_denied('or pick an authority itself',
  format($$SELECT memory.approval_authority_for(%L, %L, 'decision')$$, :'owner', :'c1'));
RESET ROLE;

SELECT t.expect_count('no API role can review, take a challenge, decide or read challenges',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) r
    WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r)
      AND (has_table_privilege(r, 'memory.approval_challenges', 'SELECT')
       OR has_function_privilege(r, 'memory.approval_review(uuid, uuid, uuid)', 'EXECUTE')
       OR has_function_privilege(r, 'memory.issue_approval_challenge(uuid, uuid, uuid, memory.approval_action, text, integer)', 'EXECUTE')
       OR has_function_privilege(r, 'memory.decide_approval_challenge(uuid, uuid, uuid, text)', 'EXECUTE'))$$, 0);
