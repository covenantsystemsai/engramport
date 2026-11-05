-- Tests for 0026_cell_erasure (founder decisions D-02.1 and D-02.1a): the
-- cell's owner starts a whole-cell erasure, a different person holding the
-- cell-erasure-confirmer role confirms it after a content-free preview, and
-- nothing that was in the cell is left. Run by db/test/run.sh after
-- restore_race_test.sh, on the fixtures and helpers of rls_test,
-- company_test, authority_test, challenge_test, revision_test, erasure_test
-- and restore_test.
\set ON_ERROR_STOP on
\set QUIET on
\set c1    '00000000-0000-7000-8000-000000000111'
\set c2    '00000000-0000-7000-8000-000000000112'
\set city  '00000000-0000-7000-8000-000000000001'
\set k_c1  '00000000-0000-7000-8000-0000000000f1'
\set k_c2  '00000000-0000-7000-8000-0000000000f2'

SELECT id AS hq FROM memory.namespaces WHERE path = 'opcity/company/hq' \gset
SELECT id AS c2owner FROM memory.actors WHERE slug = 'er-c2' \gset
SELECT id AS a_c2 FROM memory.approval_authorities WHERE actor_id = :'c2owner' AND parent_id IS NULL \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'ce-confirmer', 'Confirmer') RETURNING id AS conf \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'ce-confirmer2', 'Second confirmer') RETURNING id AS conf2 \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'ce-outsider', 'Outsider') RETURNING id AS outsider \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', 'ce-bot', 'Bot') RETURNING id AS bot \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES
  ('ce-confirmer@an2b.test', :'hq', :'conf'),
  ('ce-confirmer2@an2b.test', :'hq', :'conf2'),
  ('ce-outsider@client.test', :'c1', :'outsider'),
  ('er-c2@client.test', :'hq', :'c2owner');

-- Accept a role the way the page will.
CREATE FUNCTION t.accept_role(p_role uuid, p_email text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE s record; v text;
BEGIN
  SELECT * INTO s FROM t.sign_in(p_email);
  SELECT p.terms_sha256 INTO v FROM memory.pending_confirmer_roles(s.user_id, s.session_id) p WHERE p.role_id = p_role;
  SELECT * INTO s FROM t.sign_in(p_email);
  RETURN memory.decide_confirmer_role(s.user_id, s.session_id, p_role, 'accept', v);
END $$;
-- A confirmer's challenge for a request, from a fresh sign-in: user, session, challenge, secret.
CREATE FUNCTION t.cell_challenge(p_email text, p_request uuid,
                                 OUT user_id uuid, OUT session_id uuid, OUT challenge_id uuid, OUT secret text)
LANGUAGE plpgsql AS $$
DECLARE d text;
BEGIN
  SELECT s.user_id, s.session_id INTO user_id, session_id FROM t.sign_in(p_email) s;
  SELECT r.objects_sha256 INTO d FROM memory.cell_erasure_review(user_id, session_id, p_request) r;
  SELECT x.challenge_id, x.secret INTO challenge_id, secret
  FROM memory.issue_cell_erasure_challenge(user_id, session_id, p_request, d) x;
END $$;

\echo '-- the role is assigned by the admin to a person who belongs to AN2B'
SET ROLE engramport_admin;
SELECT t.expect_error('not to someone outside AN2B',
  format($$INSERT INTO memory.cell_erasure_confirmers (actor_id, scope_namespace_id, expires_at)
           VALUES (%L, %L, now() + interval '90 days')$$, :'outsider', :'city'), '%belongs to AN2B%');
SELECT t.expect_error('not to an agent',
  format($$INSERT INTO memory.cell_erasure_confirmers (actor_id, scope_namespace_id, expires_at)
           VALUES (%L, %L, now() + interval '90 days')$$, :'bot', :'city'), '%belongs to AN2B%');
SELECT t.expect_error('not for more than a year',
  format($$INSERT INTO memory.cell_erasure_confirmers (actor_id, scope_namespace_id, expires_at)
           VALUES (%L, %L, now() + interval '400 days')$$, :'conf', :'city'), '%check constraint%');
SELECT t.expect_denied('and the admin can''t accept it for them',
  format($$INSERT INTO memory.cell_erasure_confirmers (actor_id, scope_namespace_id, expires_at, accepted_at)
           VALUES (%L, %L, now() + interval '90 days', now())$$, :'conf', :'city'));
INSERT INTO memory.cell_erasure_confirmers (actor_id, scope_namespace_id, expires_at)
  VALUES (:'conf', :'city', now() + interval '90 days') RETURNING id AS role1 \gset
INSERT INTO memory.cell_erasure_confirmers (actor_id, scope_namespace_id, expires_at)
  VALUES (:'conf2', :'city', now() + interval '90 days') RETURNING id AS role2 \gset
INSERT INTO memory.cell_erasure_confirmers (actor_id, scope_namespace_id, expires_at)
  VALUES (:'c2owner', :'city', now() + interval '90 days') RETURNING id AS role_owner \gset
INSERT INTO memory.cell_erasure_confirmers (actor_id, scope_namespace_id, expires_at)
  VALUES (:'conf', :'hq', now() + interval '30 days') RETURNING id AS role_hq \gset
RESET ROLE;
SET ROLE engramport_app;
SELECT t.expect_denied('the server can''t assign one', format($$INSERT INTO memory.cell_erasure_confirmers
  (actor_id, scope_namespace_id, expires_at) VALUES (%L, %L, now() + interval '1 day')$$, :'conf', :'city'));
SELECT t.expect_denied('nor read them', $$SELECT * FROM memory.cell_erasure_confirmers$$);
RESET ROLE;
SELECT t.expect_count('assigned, it counts for nothing until accepted',
  format($$SELECT 1 WHERE NOT memory.confirmer_role_valid(%L)$$, :'role1'), 1);

\echo '-- the person accepts it with their own sign-in'
SELECT * FROM t.sign_in('ce-confirmer@an2b.test') \gset s1_
SET ROLE engramport_app;
SELECT t.expect_count('they see its exact terms',
  format($$SELECT 1 FROM memory.pending_confirmer_roles(%L, %L) WHERE role_id = %L AND scope_path = 'testcity'$$,
         :'s1_user_id', :'s1_session_id', :'role1'), 1);
SELECT t.expect_error('a fingerprint of other terms is refused',
  format($$SELECT memory.decide_confirmer_role(%L, %L, %L, 'accept', %L)$$, :'s1_user_id', :'s1_session_id', :'role1',
         repeat('a', 64)), '%not the terms you were shown%');
RESET ROLE;
SELECT * FROM t.sign_in('ce-confirmer2@an2b.test') \gset s2_
SET ROLE engramport_app;
SELECT t.expect_error('nobody else decides it',
  format($$SELECT memory.decide_confirmer_role(%L, %L, %L, 'accept', %L)$$, :'s2_user_id', :'s2_session_id', :'role1',
         repeat('a', 64)), '%no such role for you%');
RESET ROLE;
SELECT t.accept_role(:'role1', 'ce-confirmer@an2b.test') = 'accepted';
SELECT t.accept_role(:'role2', 'ce-confirmer2@an2b.test') = 'accepted';
SELECT t.accept_role(:'role_owner', 'er-c2@client.test') = 'accepted';
SELECT t.expect_count('accepted, it counts',
  format($$SELECT 1 WHERE memory.confirmer_role_valid(%L)$$, :'role1'), 1);
SELECT t.expect_count('and was decided once, with a fresh sign-in',
  format($$SELECT 1 FROM memory.cell_erasure_confirmers WHERE id = %L AND accepted_at IS NOT NULL
           AND decision_sign_in_hash IS NOT NULL$$, :'role1'), 1);
SELECT t.expect_count('a role over the company does not cover client cells',
  format($$SELECT 1 WHERE NOT memory.confirmer_role_covers(%L, %L, %L)$$, :'role_hq', :'conf', :'c2'), 1);
SELECT t.expect_error('the role is a record',
  format($$UPDATE memory.cell_erasure_confirmers SET expires_at = now() + interval '200 days' WHERE id = %L$$, :'role1'),
  '%is a record%');
SELECT t.expect_count('and grants nothing else: no approval authority',
  format($$SELECT 1 FROM memory.approval_authorities WHERE actor_id = %L$$, :'conf'), 0);

\echo '-- a cell with everything in it'
SELECT memory.cell_erasure_counts(:'c2') AS base \gset
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT memory.remember('fact', 'cell erasure check: the client keeps keys in drawer four', 'remember', 'rest',
                         p_claim_type => 'fact', p_dedup_key => 'ce-keys', p_source_ref => 'https://example.test/cell/1',
                         p_claimed => '{"agent_note": "from the walkthrough"}') AS m1 \gset
  SELECT memory.remember('fact', 'cell erasure check: a second fact', 'remember', 'rest', p_claim_type => 'fact') AS m2 \gset
  UPDATE memory.memories SET status = 'retracted' WHERE id = :'m2';
COMMIT;
RESET ROLE;
SELECT t.embed(:'m1');
SELECT provenance_id AS m1_prov FROM memory.memories WHERE id = :'m1' \gset
INSERT INTO memory.entities (namespace_id, type, name, provenance_id, origin)
  VALUES (:'c2', 'person', 'Drawer Keeper', :'m1_prov', 'asserted') RETURNING id AS e1 \gset
INSERT INTO memory.entities (namespace_id, type, name, provenance_id, origin)
  VALUES (:'c2', 'place', 'Drawer four', :'m1_prov', 'extracted') RETURNING id AS e2 \gset
INSERT INTO memory.entity_aliases (entity_id, namespace_id, alias, provenance_id) VALUES (:'e1', :'c2', 'The Keeper', :'m1_prov');
INSERT INTO memory.entity_mentions (memory_id, entity_id, namespace_id, provenance_id) VALUES (:'m1', :'e2', :'c2', :'m1_prov');
INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id, provenance_id)
  VALUES (:'c2', :'e1', 'keeps', :'e2', :'m1_prov');
INSERT INTO memory.memory_links (namespace_id, from_memory_id, kind, to_memory_id, provenance_id)
  VALUES (:'c2', :'m1', 'related', :'m2', :'m1_prov');
-- A row dated in the future is still in the cell, and goes with it.
INSERT INTO memory.entities (namespace_id, type, name, provenance_id, origin, created_at)
  VALUES (:'c2', 'person', 'Future Dated', :'m1_prov', 'asserted', now() + interval '1 year') RETURNING id AS e_future \gset
SELECT t.expect_count('a row can''t be dated ahead of its writing',
  format($$SELECT 1 FROM memory.entities WHERE id = %L AND created_at <= now()$$, :'e_future'), 1);
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('fact', 'cell erasure check: dated ahead', 'remember', 'rest') AS c1_mem \gset
  SELECT provenance_id AS c1_prov FROM memory.memories WHERE id = :'c1_mem' \gset
  INSERT INTO memory.entities (namespace_id, type, name, provenance_id, origin, created_at)
    VALUES (:'c1', 'person', 'Dated ahead by an agent', :'c1_prov', 'asserted', now() + interval '10 years') RETURNING id AS e_agent \gset
COMMIT;
RESET ROLE;
SELECT t.expect_count('not by an agent either',
  format($$SELECT 1 FROM memory.entities WHERE id = %L AND created_at <= now()$$, :'e_agent'), 1);

\echo '-- only the cell''s owner starts it'
SELECT * FROM t.sign_in('er-c2@client.test') \gset o1_
SELECT * FROM t.sign_in('er-owner@client.test') \gset x1_
SELECT * FROM t.sign_in('er-del@client.test') \gset x2_
SELECT * FROM t.sign_in('ce-confirmer@an2b.test') \gset x3_
SET ROLE engramport_app;
SELECT t.expect_count('the owner sees counts, and no text',
  format($$SELECT 1 FROM memory.cell_erasure_preview(%L, %L, %L)
           WHERE (counts ->> 'memories')::int = (%L::jsonb ->> 'memories')::int + 2
             AND (counts ->> 'entities')::int = (%L::jsonb ->> 'entities')::int + 3
             AND open_request_id IS NULL AND counts::text NOT LIKE '%%drawer%%'$$,
         :'o1_user_id', :'o1_session_id', :'c2', :'base', :'base'), 1);
SELECT t.expect_error('another cell''s owner can''t',
  format($$SELECT * FROM memory.cell_erasure_preview(%L, %L, %L)$$, :'x1_user_id', :'x1_session_id', :'c2'),
  '%not its owner%');
SELECT t.expect_error('nor can a delegate in their own cell',
  format($$SELECT * FROM memory.cell_erasure_preview(%L, %L, %L)$$, :'x2_user_id', :'x2_session_id', :'c1'),
  '%not its owner%');
SELECT t.expect_error('nor a confirmer',
  format($$SELECT memory.request_cell_erasure(%L, %L, %L, 'owner_request')$$, :'x3_user_id', :'x3_session_id', :'c2'),
  '%not its owner%');
SELECT t.expect_error('and only a cell',
  format($$SELECT * FROM memory.cell_erasure_preview(%L, %L, %L)$$, :'o1_user_id', :'o1_session_id', :'city'),
  '%not its owner%');
SELECT memory.request_cell_erasure(:'o1_user_id', :'o1_session_id', :'c2', 'owner_request') AS req \gset
RESET ROLE;
SELECT t.expect_count('started, with what the owner was shown',
  format($$SELECT 1 FROM memory.cell_erasure_requests WHERE id = %L AND state = 'proposed' AND initiated_by_actor_id = %L
           AND authority_id = %L AND (preview ->> 'memories')::int = (%L::jsonb ->> 'memories')::int + 2
           AND expires_at > now() + interval '6 days'$$,
         :'req', :'c2owner', :'a_c2', :'base'), 1);
SELECT * FROM t.sign_in('er-c2@client.test') \gset o2_
SET ROLE engramport_app;
SELECT t.expect_error('one open request per cell',
  format($$SELECT memory.request_cell_erasure(%L, %L, %L, 'owner_request')$$, :'o2_user_id', :'o2_session_id', :'c2'),
  '%already waiting%');
RESET ROLE;

\echo '-- while it is open, nothing new is written to the cell'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT t.expect_error('no new memory',
    $$SELECT memory.remember('fact', 'cell erasure check: written too late', 'remember', 'rest')$$,
    '%waiting for whole-cell erasure%');
ROLLBACK;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('fact', 'cell erasure check: another cell writes as usual', 'remember', 'rest') IS NOT NULL;
COMMIT;
RESET ROLE;
SELECT t.expect_error('no graph row either',
  format($$INSERT INTO memory.entities (namespace_id, type, name, provenance_id, origin)
           VALUES (%L, 'person', 'Late', %L, 'asserted')$$, :'c2', :'m1_prov'), '%waiting for whole-cell erasure%');
SELECT t.expect_error('nor a provenance row',
  format($$INSERT INTO memory.provenance (namespace_id, api_key_id, actor_id, tool, transport, source_ref)
           SELECT namespace_id, api_key_id, actor_id, 'remember', 'rest', 'https://example.test/late' FROM memory.provenance WHERE id = %L$$,
         :'m1_prov'), '%waiting for whole-cell erasure%');

\echo '-- a different person with the role confirms'
SELECT * FROM t.sign_in('er-c2@client.test') \gset o3_
SELECT * FROM t.sign_in('ce-outsider@client.test') \gset u1_
SELECT * FROM t.sign_in('ce-confirmer@an2b.test') \gset c1_
SET ROLE engramport_app;
SELECT t.expect_count('the owner, though holding the role, is not offered their own request',
  format($$SELECT 1 FROM memory.pending_cell_erasures(%L, %L)$$, :'o3_user_id', :'o3_session_id'), 0);
SELECT t.expect_error('and can''t review it to confirm',
  format($$SELECT * FROM memory.cell_erasure_review(%L, %L, %L)$$, :'o3_user_id', :'o3_session_id', :'req'),
  '%different person must confirm%');
SELECT t.expect_error('someone without the role can''t either',
  format($$SELECT * FROM memory.cell_erasure_review(%L, %L, %L)$$, :'u1_user_id', :'u1_session_id', :'req'),
  '%no cell-erasure-confirmer role%');
SELECT t.expect_count('the confirmer is offered it',
  format($$SELECT 1 FROM memory.pending_cell_erasures(%L, %L) WHERE request_id = %L AND initiated_by = 'er-c2'$$,
         :'c1_user_id', :'c1_session_id', :'req'), 1);
SELECT t.expect_count('and reviews counts and a digest, never the text',
  format($$SELECT 1 FROM memory.cell_erasure_review(%L, %L, %L) r
           WHERE (r.counts ->> 'memories')::int > 2 AND r.objects_sha256 ~ '^[0-9a-f]{64}$'
             AND to_jsonb(r)::text NOT LIKE '%%drawer%%' AND to_jsonb(r)::text NOT LIKE '%%Keeper%%'$$,
         :'c1_user_id', :'c1_session_id', :'req'), 1);
SELECT t.expect_error('a digest of anything else is refused',
  format($$SELECT * FROM memory.issue_cell_erasure_challenge(%L, %L, %L, %L)$$, :'c1_user_id', :'c1_session_id', :'req',
         repeat('b', 64)), '%changed since you reviewed it%');
RESET ROLE;

\echo '-- a role revoked before the decision stops it'
SELECT * FROM t.cell_challenge('ce-confirmer2@an2b.test', :'req') \gset k2_
SET ROLE engramport_admin;
UPDATE memory.cell_erasure_confirmers SET revoked_at = now(), revoke_reason = 'left_an2b' WHERE id = :'role2';
RESET ROLE;
SET ROLE engramport_app;
SELECT t.expect_error('the revoked confirmer''s challenge is refused',
  format($$SELECT memory.decide_cell_erasure_challenge(%L, %L, %L, %L)$$, :'k2_user_id', :'k2_session_id',
         :'k2_challenge_id', :'k2_secret'), '%no longer covers this cell%');
RESET ROLE;
SELECT t.expect_state('nothing was erased', :'m1', 'active/none');

\echo '-- the cell is erased'
SELECT * FROM t.cell_challenge('ce-confirmer@an2b.test', :'req') \gset k1_
SET ROLE engramport_app;
SELECT t.expect_error('no other sign-in uses the challenge',
  format($$SELECT memory.decide_cell_erasure_challenge(%L, %L, %L, %L)$$, :'c1_user_id', :'c1_session_id',
         :'k1_challenge_id', :'k1_secret'), '%no such challenge%');
RESET ROLE;
SELECT * FROM t.sign_in('ce-confirmer@an2b.test') \gset k1b_
SET ROLE engramport_app;
SELECT memory.decide_cell_erasure_challenge(:'k1_user_id', :'k1_session_id', :'k1_challenge_id', :'k1_secret') AS ev \gset
RESET ROLE;
SELECT t.expect_count('verified, with counts',
  format($$SELECT 1 WHERE (%L::jsonb ->> 'verified')::boolean
           AND (%L::jsonb ->> 'versions')::int = (%L::jsonb ->> 'memories')::int + 2
           AND (%L::jsonb ->> 'entities')::int = (%L::jsonb ->> 'entities')::int + 3
           AND (%L::jsonb ->> 'aliases')::int = (%L::jsonb ->> 'aliases')::int + 1$$,
         :'ev', :'ev', :'base', :'ev', :'base', :'ev', :'base'), 1);
SELECT t.expect_count('every memory version is erased, with a tombstone naming the request',
  format($$SELECT 1 FROM memory.memories m JOIN memory.erasures e ON e.memory_id = m.id
           WHERE m.namespace_id = %L AND m.status = 'erased' AND m.content = '' AND e.source = 'cell' AND e.cell_request_id = %L$$,
         :'c2', :'req'), (:'base'::jsonb ->> 'memories')::int + 2);
SELECT t.expect_count('no embedding, entity, alias, relation, mention or link is left in the cell',
  format($$SELECT 1 FROM (SELECT namespace_id FROM memory.memory_embeddings UNION ALL SELECT namespace_id FROM memory.entities
           UNION ALL SELECT namespace_id FROM memory.entity_aliases UNION ALL SELECT namespace_id FROM memory.relations
           UNION ALL SELECT namespace_id FROM memory.entity_mentions UNION ALL SELECT namespace_id FROM memory.memory_links) x
           WHERE x.namespace_id = %L$$, :'c2'), 0);
SELECT t.expect_count('the future-dated row went too',
  format($$SELECT 1 FROM memory.entities WHERE id = %L$$, :'e_future'), 0);
SELECT t.expect_count('nor anything content-derived in its provenance',
  format($$SELECT 1 FROM memory.provenance WHERE namespace_id = %L
           AND (source_ref IS NOT NULL OR claimed <> '{}' OR content_sha256 IS NOT NULL)$$, :'c2'), 0);
SELECT t.expect_count('nor the text anywhere',
  $$SELECT 1 FROM memory.memories WHERE content LIKE '%drawer four%' OR content LIKE '%a second fact%'$$, 0);
SELECT t.expect_count('the request records who started, who confirmed, under what, and the digest',
  format($$SELECT 1 FROM memory.cell_erasure_requests r JOIN memory.cell_erasure_challenges c ON c.id = r.challenge_id
           WHERE r.id = %L AND r.state = 'completed' AND r.initiated_by_actor_id = %L AND r.confirmed_by_actor_id = %L
             AND r.confirmer_role_id = %L AND r.authority_id = %L AND r.evidence ->> 'objects_sha256' = c.objects_sha256$$,
         :'req', :'c2owner', :'conf', :'role1', :'a_c2'), 1);
SELECT t.expect_count('another cell is untouched',
  $$SELECT 1 FROM memory.memories WHERE content = 'cell erasure check: another cell writes as usual' AND status = 'active'$$, 1);
SET ROLE engramport_app;
SELECT t.expect_error('the challenge is spent',
  format($$SELECT memory.decide_cell_erasure_challenge(%L, %L, %L, %L)$$, :'k1b_user_id', :'k1b_session_id',
         :'k1_challenge_id', :'k1_secret'), '%no such challenge%');
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT memory.remember('fact', 'cell erasure check: written after', 'remember', 'rest') IS NOT NULL;
COMMIT;
RESET ROLE;
SELECT t.expect_count('and the cell takes new writes again, as new submissions',
  $$SELECT 1 FROM memory.memories WHERE content = 'cell erasure check: written after' AND status = 'active'$$, 1);

\echo '-- a request lapses, and the admin can cancel one'
SELECT * FROM t.sign_in('er-c2@client.test') \gset o4_
SET ROLE engramport_app;
SELECT memory.request_cell_erasure(:'o4_user_id', :'o4_session_id', :'c2', 'stored_in_error') AS req2 \gset
RESET ROLE;
SET ROLE engramport_admin;
SELECT t.expect_error('the admin can''t complete one',
  format($$UPDATE memory.cell_erasure_requests SET state = 'completed' WHERE id = %L$$, :'req2'), '%');
UPDATE memory.cell_erasure_requests SET state = 'cancelled', cancel_reason = 'started_by_mistake' WHERE id = :'req2';
RESET ROLE;
SELECT t.expect_count('cancelled, stamped now',
  format($$SELECT 1 FROM memory.cell_erasure_requests WHERE id = %L AND state = 'cancelled' AND cancelled_at IS NOT NULL$$, :'req2'), 1);
SELECT * FROM t.sign_in('er-c2@client.test') \gset o5_
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT memory.remember('fact', 'cell erasure check: written after a cancel', 'remember', 'rest') IS NOT NULL;
COMMIT;
SELECT memory.request_cell_erasure(:'o5_user_id', :'o5_session_id', :'c2', 'stored_in_error') AS req3 \gset
RESET ROLE;
ALTER TABLE memory.cell_erasure_requests DISABLE TRIGGER cell_erasure_requests_kept;
UPDATE memory.cell_erasure_requests SET created_at = now() - interval '8 days', expires_at = now() - interval '1 day'
  WHERE id = :'req3';
ALTER TABLE memory.cell_erasure_requests ENABLE TRIGGER cell_erasure_requests_kept;
SELECT * FROM t.sign_in('ce-confirmer@an2b.test') \gset c2_
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT memory.remember('fact', 'cell erasure check: written after a lapse', 'remember', 'rest') IS NOT NULL;
COMMIT;
SELECT t.expect_count('a lapsed request is not offered',
  format($$SELECT 1 FROM memory.pending_cell_erasures(%L, %L) WHERE request_id = %L$$, :'c2_user_id', :'c2_session_id', :'req3'), 0);
SELECT t.expect_error('and can''t be confirmed',
  format($$SELECT * FROM memory.issue_cell_erasure_challenge(%L, %L, %L, (SELECT objects_sha256 FROM memory.cell_erasure_review(%L, %L, %L)))$$,
         :'c2_user_id', :'c2_session_id', :'req3', :'c2_user_id', :'c2_session_id', :'req3'), '%lapsed%');
RESET ROLE;

\echo '-- a restored backup is reconciled'
SELECT completed_at AS done_at FROM memory.cell_erasure_requests WHERE id = :'req' \gset
SELECT provenance_id AS late_prov FROM memory.memories WHERE content = 'cell erasure check: written after' \gset
INSERT INTO memory.entities (namespace_id, type, name, provenance_id, origin, created_at)
  VALUES (:'c2', 'person', 'Back from a backup', :'late_prov', 'asserted', :'done_at'::timestamptz - interval '1 hour')
  RETURNING id AS e_old \gset
INSERT INTO memory.entities (namespace_id, type, name, provenance_id, origin)
  VALUES (:'c2', 'person', 'Named after the erasure', :'late_prov', 'asserted') RETURNING id AS e_new \gset
SET ROLE engramport_app;
SELECT t.expect_denied('the server can''t run the reconcile',
  format($$SELECT memory.reapply_cell_erasure(%L, %L)$$, :'c2', :'done_at'));
RESET ROLE;
SELECT memory.reapply_cell_erasure(:'c2', :'done_at') ->> 'entities' AS reapplied \gset
SELECT t.expect_count('what was in the cell when it was erased goes again',
  format($$SELECT 1 FROM memory.entities WHERE id = %L$$, :'e_old'), 0);
SELECT t.expect_count('what came after stays',
  format($$SELECT 1 FROM memory.entities WHERE id = %L$$, :'e_new'), 1);
SELECT t.expect_count('safe to run twice',
  format($$SELECT 1 WHERE (memory.reapply_cell_erasure(%L, %L) ->> 'entities')::int = 0$$, :'c2', :'done_at'), 1);

\echo '-- the records'
SELECT t.expect_error('a completed request never changes',
  format($$UPDATE memory.cell_erasure_requests SET evidence = '{}' WHERE id = %L$$, :'req'), '%is a record%');
SELECT t.expect_error('nor is deleted', format($$DELETE FROM memory.cell_erasure_requests WHERE id = %L$$, :'req'), '%');
SELECT t.expect_error('nor is a challenge', $$DELETE FROM memory.cell_erasure_challenges$$, '%is a record%');
SELECT t.expect_error('nor a role', format($$DELETE FROM memory.cell_erasure_confirmers WHERE id = %L$$, :'role1'), '%is a record%');
SET ROLE engramport_app;
SELECT t.expect_denied('the server reads no request', $$SELECT * FROM memory.cell_erasure_requests$$);
SELECT t.expect_denied('nor any challenge', $$SELECT * FROM memory.cell_erasure_challenges$$);
RESET ROLE;
SET ROLE engramport_admin;
SELECT t.expect_count('the admin sees the requests', $$SELECT 1 FROM memory.cell_erasure_requests$$, 3);
SELECT t.expect_count('and the challenges, without secrets or sign-ins',
  $$SELECT id, request_id, actor_id, role_id, issued_at, expires_at FROM memory.cell_erasure_challenges$$, 2);
SELECT t.expect_denied('never a secret', $$SELECT secret_sha256 FROM memory.cell_erasure_challenges$$);
SELECT t.expect_denied('nor the digest a confirmer bound', $$SELECT objects_sha256 FROM memory.cell_erasure_challenges$$);
SELECT t.expect_denied('nor the sign-in a role was accepted with', $$SELECT decision_sign_in_hash FROM memory.cell_erasure_confirmers$$);
SELECT t.expect_denied('and the admin can''t confirm',
  format($$SELECT memory.decide_cell_erasure_challenge(gen_random_uuid(), gen_random_uuid(), %L, %L)$$,
         :'k1_challenge_id', :'k1_secret'));
RESET ROLE;
SELECT t.expect_count('no API role reaches a whole-cell erasure function',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) r(role),
           unnest(ARRAY['memory.request_cell_erasure(uuid,uuid,uuid,memory.erasure_reason)',
                        'memory.decide_cell_erasure_challenge(uuid,uuid,uuid,text)',
                        'memory.decide_confirmer_role(uuid,uuid,uuid,text,text)',
                        'memory.reapply_cell_erasure(uuid,timestamptz)']) f(fn)
    WHERE has_function_privilege(r.role, f.fn, 'EXECUTE')$$, 0);

\echo 'all whole-cell erasure tests passed'
