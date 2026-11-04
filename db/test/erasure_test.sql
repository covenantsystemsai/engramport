-- Tests for 0022_erasure (founder decision D-02): a person erases, agents can
-- only ask, and nothing of the text is left anywhere it could be found. Run by
-- db/test/run.sh after revision_race_test.sh, on the rls_test namespaces and
-- keys and the helpers from rls_test (t.as_key, t.expect_count,
-- t.expect_denied), admin_test (t.expect_rows), authority_test (t.sign_in,
-- t.accept), challenge_test (t.expect_error, t.challenge) and revision_test
-- (t.decide, t.state, t.expect_state).
\set ON_ERROR_STOP on
\set QUIET on
\set c1    '00000000-0000-7000-8000-000000000111'
\set c2    '00000000-0000-7000-8000-000000000112'
\set k_c1  '00000000-0000-7000-8000-0000000000f1'
\set k_c1b '00000000-0000-7000-8000-0000000000f4'
\set k_c2  '00000000-0000-7000-8000-0000000000f2'

-- Review, confirm and decide, the way the page does. Returns the evidence.
CREATE FUNCTION t.erase(p_user uuid, p_session uuid, p_request uuid) RETURNS jsonb LANGUAGE plpgsql AS $$
DECLARE d text; c record;
BEGIN
  SELECT r.items_sha256 INTO d FROM memory.erasure_review(p_user, p_session, p_request) r LIMIT 1;
  SELECT * INTO c FROM memory.issue_erasure_challenge(p_user, p_session, p_request, d);
  RETURN memory.decide_erasure_challenge(p_user, p_session, c.challenge_id, c.secret);
END $$;
CREATE FUNCTION t.erase_challenge(p_user uuid, p_session uuid, p_request uuid, OUT challenge_id uuid, OUT secret text)
LANGUAGE plpgsql AS $$
DECLARE d text; c record;
BEGIN
  SELECT r.items_sha256 INTO d FROM memory.erasure_review(p_user, p_session, p_request) r LIMIT 1;
  SELECT x.challenge_id, x.secret INTO challenge_id, secret
  FROM memory.issue_erasure_challenge(p_user, p_session, p_request, d) x;
END $$;
-- An embedding for a test memory, at the test model's size.
CREATE FUNCTION t.embed(p_memory uuid) RETURNS void LANGUAGE sql AS $$
  INSERT INTO memory.memory_embeddings (memory_id, namespace_id, model, dimension, embedding)
  SELECT m.id, m.namespace_id, n.embedding_model, 1536,
         ('[' || array_to_string(array_fill(0.01::real, ARRAY[1536]), ',') || ']')::extensions.halfvec
  FROM memory.memories m JOIN memory.namespaces n ON n.id = m.namespace_id WHERE m.id = p_memory
$$;

INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'er-owner', 'Erasure owner') RETURNING id AS owner \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'er-owner2', 'Second owner') RETURNING id AS owner2 \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'er-del', 'Delegate') RETURNING id AS del \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'er-obs', 'Observation owner') RETURNING id AS obs \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'er-c2', 'Cell two owner') RETURNING id AS c2owner \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES
  ('er-owner@client.test', :'c1', :'owner'),
  ('er-owner2@client.test', :'c1', :'owner2'),
  ('er-del@client.test', :'c1', :'del'),
  ('er-obs@client.test', :'c1', :'obs'),
  ('er-c2@client.test', :'c2', :'c2owner');
SET ROLE engramport_admin;
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, can_delegate)
  VALUES (:'owner', :'c1', 'cell_knowledge', true) RETURNING id AS a_owner \gset
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
  VALUES (:'owner2', :'c1', 'cell_knowledge') RETURNING id AS a_owner2 \gset
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, claim_types)
  VALUES (:'obs', :'c1', 'cell_knowledge', '{observation}') RETURNING id AS a_obs \gset
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
  VALUES (:'c2owner', :'c2', 'cell_knowledge') RETURNING id AS a_c2 \gset
RESET ROLE;
SELECT t.accept(:'a_owner', 'er-owner@client.test');
SELECT t.accept(:'a_owner2', 'er-owner2@client.test');
SELECT t.accept(:'a_obs', 'er-obs@client.test');
SELECT t.accept(:'a_c2', 'er-c2@client.test');
SELECT * FROM t.sign_in('er-owner@client.test') \gset dg_
SET ROLE engramport_app;
SELECT memory.delegate_approval_authority(:'dg_user_id', :'dg_session_id', :'a_owner', :'del') AS a_del \gset
RESET ROLE;
SELECT t.accept(:'a_del', 'er-del@client.test');
SELECT * FROM t.sign_in('er-owner@client.test') \gset o1_
SELECT * FROM t.sign_in('er-owner@client.test') \gset o2_
SELECT * FROM t.sign_in('er-owner@client.test') \gset o3_
SELECT * FROM t.sign_in('er-owner@client.test') \gset o4_
SELECT * FROM t.sign_in('er-owner@client.test') \gset o5_
SELECT * FROM t.sign_in('er-owner@client.test') \gset o6_
SELECT * FROM t.sign_in('er-owner@client.test') \gset o7_
SELECT * FROM t.sign_in('er-owner@client.test') \gset o8_
SELECT * FROM t.sign_in('er-owner@client.test') \gset o9_
SELECT * FROM t.sign_in('er-owner@client.test') \gset o10_
SELECT * FROM t.sign_in('er-owner2@client.test') \gset w1_
SELECT * FROM t.sign_in('er-del@client.test') \gset d1_
SELECT * FROM t.sign_in('er-obs@client.test') \gset b1_
SELECT * FROM t.sign_in('er-c2@client.test') \gset q1_

\echo '-- a memory with history, a pending revision, and everything derived from it'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('fact', 'erasure check: the vendor contact is Pat at 555 0100', 'remember', 'rest',
                         p_claim_type => 'fact', p_dedup_key => 'er-contact', p_source_ref => 'https://example.test/notes/1',
                         p_metadata => '{"from": "call notes"}', p_claimed => '{"agent_note": "from the call"}') AS m1 \gset
  SELECT memory.remember('fact', 'erasure check: an unrelated memory that stays', 'remember', 'rest') AS keep \gset
COMMIT;
SELECT t.decide(:'o1_user_id', :'o1_session_id', :'m1', 'approve') IS NOT NULL;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.propose_revision(:'m1', 'fact', 'erasure check: the vendor contact is Pat at 555 0199', 'supersede_memory',
                                 'rest', 'fact', p_dedup_key => 'er-contact') AS m2 \gset
COMMIT;
SELECT t.decide(:'o2_user_id', :'o2_session_id', :'m2', 'approve') IS NOT NULL;
BEGIN; SELECT t.as_key(:'k_c1b', :'c1');
  SELECT memory.propose_revision(:'m2', 'fact', 'erasure check: the vendor contact is Sam', 'supersede_memory',
                                 'rest', 'fact', p_dedup_key => 'er-contact') AS m3 \gset
COMMIT;
-- A challenge taken on the pending revision before the erasure.
SELECT * FROM t.challenge(:'o3_user_id', :'o3_session_id', :'m3', 'approve') \gset pend_
RESET ROLE;
SELECT t.expect_state('the first version is superseded', :'m1', 'superseded/approved');
SELECT t.expect_state('the second is current', :'m2', 'active/approved');
SELECT t.expect_state('the third is pending', :'m3', 'proposed/pending');
SELECT provenance_id AS m2_prov FROM memory.memories WHERE id = :'m2' \gset
SELECT t.embed(:'m1');
SELECT t.embed(:'m2');
SELECT t.embed(:'keep');
INSERT INTO memory.entities (namespace_id, type, name, provenance_id, origin)
  VALUES (:'c1', 'person', 'Pat', :'m2_prov', 'extracted') RETURNING id AS e_pat \gset
INSERT INTO memory.entities (namespace_id, type, name, provenance_id, origin)
  VALUES (:'c1', 'organization', 'The vendor', :'m2_prov', 'asserted') RETURNING id AS e_vendor \gset
INSERT INTO memory.entities (namespace_id, type, name, provenance_id, origin)
  VALUES (:'c1', 'project', 'Shared project', :'m2_prov', 'extracted') RETURNING id AS e_shared \gset
INSERT INTO memory.entity_aliases (entity_id, namespace_id, alias, provenance_id)
  VALUES (:'e_pat', :'c1', 'Patricia', :'m2_prov');
INSERT INTO memory.entity_mentions (memory_id, entity_id, namespace_id, provenance_id) VALUES
  (:'m2', :'e_pat', :'c1', :'m2_prov'), (:'m2', :'e_vendor', :'c1', :'m2_prov'),
  (:'m1', :'e_shared', :'c1', :'m2_prov'), (:'keep', :'e_shared', :'c1', :'m2_prov');
INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id, evidence_memory_id, provenance_id)
  VALUES (:'c1', :'e_pat', 'works_for', :'e_vendor', :'m2', :'m2_prov');
INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id, provenance_id)
  VALUES (:'c1', :'e_vendor', 'part_of', :'e_shared', :'m2_prov');
INSERT INTO memory.memory_links (namespace_id, from_memory_id, kind, to_memory_id, provenance_id)
  VALUES (:'c1', :'keep', 'related', :'m2', :'m2_prov'), (:'c1', :'m1', 'related', :'keep', :'m2_prov');

\echo '-- an agent can only ask, in its own cell, for a bounded set'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT t.expect_error('another cell cannot ask for it',
    format($$SELECT memory.request_erasure(ARRAY[%L]::uuid[], 'owner_request')$$, :'m2'), 'memory not found');
COMMIT;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT t.expect_error('a request names at least one memory',
    $$SELECT memory.request_erasure('{}'::uuid[], 'owner_request')$$, '%at least one%');
  SELECT t.expect_error('and says why',
    format($$SELECT memory.request_erasure(ARRAY[%L]::uuid[], NULL)$$, :'m2'), '%say why%');
  SELECT t.expect_error('and names at most 100',
    $$SELECT memory.request_erasure(ARRAY(SELECT gen_random_uuid() FROM generate_series(1, 101)), 'owner_request')$$,
    '%at most 100%');
  SELECT t.expect_error('a memory it cannot see is not found',
    format($$SELECT memory.request_erasure(ARRAY[%L, gen_random_uuid()]::uuid[], 'owner_request')$$, :'m2'), 'memory not found');
  SELECT memory.request_erasure(ARRAY[:'m2', :'m2']::uuid[], 'owner_request') AS req \gset
COMMIT;
RESET ROLE;
SELECT t.expect_count('the request is on record, proposed, naming one memory',
  format($$SELECT 1 FROM memory.erasure_requests r JOIN memory.erasure_request_items i ON i.request_id = r.id
           WHERE r.id = %L AND r.state = 'proposed' AND i.memory_id = %L$$, :'req', :'m2'), 1);
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT t.expect_denied('an agent cannot blank the text itself',
    format($$UPDATE memory.memories SET content = 'x' WHERE id = %L$$, :'m2'));
  SELECT t.expect_denied('or mark it erased',
    format($$UPDATE memory.memories SET status = 'erased' WHERE id = %L$$, :'m2'));
  SELECT t.expect_denied('or write a tombstone',
    format($$INSERT INTO memory.erasures (memory_id, namespace_id, source) VALUES (%L, %L, 'restore')$$, :'m2', :'c1'));
  SELECT t.expect_denied('or complete the request',
    format($$UPDATE memory.erasure_requests SET state = 'completed' WHERE id = %L$$, :'req'));
  SELECT t.expect_denied('or call the erasing step',
    format($$SELECT memory.erase_chain(%L, %L, 'request')$$, :'m2', :'req'));
  SELECT t.expect_denied('or the restore step',
    format($$SELECT memory.reapply_erasures(ARRAY[%L]::uuid[])$$, :'m2'));
  SELECT t.expect_denied('or delete its embedding',
    format($$DELETE FROM memory.memory_embeddings WHERE memory_id = %L$$, :'m2'));
COMMIT;
RESET ROLE;
SELECT t.expect_state('the memory is untouched', :'m2', 'active/approved');

\echo '-- only an owner with authority over every version reviews it'
SET ROLE engramport_app;
SELECT t.expect_count('the owner sees each memory named, its text, and what would go with it',
  format($$SELECT 1 FROM memory.erasure_review(%L, %L, %L)
           WHERE memory_id = %L AND content = 'erasure check: the vendor contact is Pat at 555 0199'
             AND versions = 3 AND embeddings = 2 AND mentions = 3 AND links = 2 AND relations = 1
             AND reason = 'owner_request' AND state = 'proposed' AND items_sha256 ~ '^[0-9a-f]{64}$'$$,
         :'o4_user_id', :'o4_session_id', :'req', :'m2'), 1);
SELECT t.expect_error('a delegate cannot erase',
  format($$SELECT * FROM memory.erasure_review(%L, %L, %L)$$, :'d1_user_id', :'d1_session_id', :'req'), '%no authority%');
SELECT t.expect_error('nor an owner whose grant does not cover what it names',
  format($$SELECT * FROM memory.erasure_review(%L, %L, %L)$$, :'b1_user_id', :'b1_session_id', :'req'), '%no authority%');
SELECT t.expect_error('nor another cell''s owner',
  format($$SELECT * FROM memory.erasure_review(%L, %L, %L)$$, :'q1_user_id', :'q1_session_id', :'req'), '%no authority%');
SELECT t.expect_error('and a request that does not exist looks the same',
  format($$SELECT * FROM memory.erasure_review(%L, %L, gen_random_uuid())$$, :'o4_user_id', :'o4_session_id'), '%no authority%');
SELECT t.expect_error('the confirmation must carry the digest the owner was shown',
  format($$SELECT * FROM memory.issue_erasure_challenge(%L, %L, %L, %L)$$, :'o4_user_id', :'o4_session_id', :'req', repeat('0', 64)),
  '%not the request you were shown%');
RESET ROLE;

\echo '-- the owner confirms, and every version and everything derived goes'
SET ROLE engramport_app;
SELECT * FROM t.erase_challenge(:'o4_user_id', :'o4_session_id', :'req') \gset ec_
SELECT memory.decide_erasure_challenge(:'o4_user_id', :'o4_session_id', :'ec_challenge_id', :'ec_secret') AS evidence \gset
RESET ROLE;
SELECT t.expect_count('the evidence counts what went',
  format($$SELECT 1 WHERE (%L::jsonb) @> '{"versions": 3, "embeddings": 2, "mentions": 3, "links": 2, "relations": 1,
                                           "entities": 1, "verified": true, "memories_named": 3}'$$, :'evidence'), 1);
SELECT t.expect_count('all three versions are content-free tombstones',
  format($$SELECT 1 FROM memory.memories WHERE id IN (%L, %L, %L) AND status = 'erased' AND content = ''
             AND content_sha256 IS NULL AND dedup_key IS NULL AND metadata = '{}' AND fts = ''::tsvector$$,
         :'m1', :'m2', :'m3'), 3);
SELECT t.expect_count('they keep their trust and timestamps',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND approval_state = 'approved' AND claim_type = 'fact'$$, :'m2'), 1);
SELECT t.expect_count('no embeddings',
  format($$SELECT 1 FROM memory.memory_embeddings WHERE memory_id IN (%L, %L, %L)$$, :'m1', :'m2', :'m3'), 0);
SELECT t.expect_count('no mentions',
  format($$SELECT 1 FROM memory.entity_mentions WHERE memory_id IN (%L, %L, %L)$$, :'m1', :'m2', :'m3'), 0);
SELECT t.expect_count('no links either way',
  format($$SELECT 1 FROM memory.memory_links WHERE from_memory_id IN (%L, %L, %L) OR to_memory_id IN (%L, %L, %L)$$,
         :'m1', :'m2', :'m3', :'m1', :'m2', :'m3'), 0);
SELECT t.expect_count('no relation it was evidence for',
  format($$SELECT 1 FROM memory.relations WHERE evidence_memory_id IN (%L, %L, %L)$$, :'m1', :'m2', :'m3'), 0);
SELECT t.expect_count('the extracted entity only it named is gone, with its alias',
  format($$SELECT 1 FROM memory.entities WHERE id = %L UNION ALL SELECT 1 FROM memory.entity_aliases WHERE entity_id = %L$$,
         :'e_pat', :'e_pat'), 0);
SELECT t.expect_count('an asserted entity and one another memory names stay',
  format($$SELECT 1 FROM memory.entities WHERE id IN (%L, %L)$$, :'e_vendor', :'e_shared'), 2);
SELECT t.expect_count('provenance keeps who and when, not the source, claims or digest',
  format($$SELECT 1 FROM memory.memories m JOIN memory.provenance p ON p.id = m.provenance_id
           WHERE m.id IN (%L, %L, %L) AND p.source_ref IS NULL AND p.claimed = '{}' AND p.content_sha256 IS NULL
             AND p.actor_id IS NOT NULL$$, :'m1', :'m2', :'m3'), 3);
SELECT t.expect_count('approval decisions keep who and when, not the digest',
  format($$SELECT 1 FROM memory.approvals WHERE memory_id IN (%L, %L, %L) AND content_sha256 IS NULL$$, :'m1', :'m2', :'m3'), 2);
SELECT t.expect_count('and so do approval challenges',
  format($$SELECT 1 FROM memory.approval_challenges WHERE memory_id IN (%L, %L, %L) AND content_sha256 IS NOT NULL$$,
         :'m1', :'m2', :'m3'), 0);
SELECT t.expect_count('one tombstone per version, under the request',
  format($$SELECT 1 FROM memory.erasures WHERE memory_id IN (%L, %L, %L) AND request_id = %L AND source = 'request'
             AND namespace_id = %L$$, :'m1', :'m2', :'m3', :'req', :'c1'), 3);
SELECT t.expect_count('the request is completed with who decided and under which authority',
  format($$SELECT 1 FROM memory.erasure_requests WHERE id = %L AND state = 'completed' AND decided_by_actor_id = %L
             AND authority_id = %L AND challenge_id = %L AND (evidence ->> 'verified')::boolean$$,
         :'req', :'owner', :'a_owner', :'ec_challenge_id'), 1);
SELECT t.expect_count('the sign-in was spent for erasing',
  format($$SELECT 1 FROM memory.human_sign_ins_used WHERE session_hash = sha256(uuid_send(%L::uuid)) AND purpose = 'erase'$$,
         :'o4_session_id'), 1);
SELECT t.expect_count('the unrelated memory is untouched, with its embedding',
  format($$SELECT 1 FROM memory.memories m JOIN memory.memory_embeddings e ON e.memory_id = m.id
           WHERE m.id = %L AND m.status = 'active' AND m.content = 'erasure check: an unrelated memory that stays'$$, :'keep'), 1);
SELECT t.expect_count('nothing with the text is left in the database',
  $$SELECT 1 FROM memory.memories WHERE content LIKE '%vendor contact%'$$, 0);

\echo '-- the erasure cannot be replayed, and the pending decision died with it'
SET ROLE engramport_app;
SELECT t.expect_error('the same challenge again',
  format($$SELECT memory.decide_erasure_challenge(%L, %L, %L, %L)$$, :'o4_user_id', :'o4_session_id', :'ec_challenge_id', :'ec_secret'),
  '%already used%');
SELECT t.expect_error('or from a fresh sign-in',
  format($$SELECT memory.decide_erasure_challenge(%L, %L, %L, %L)$$, :'o5_user_id', :'o5_session_id', :'ec_challenge_id', :'ec_secret'),
  '%no such challenge%');
SELECT t.expect_error('a completed request cannot be confirmed again',
  format($$SELECT * FROM t.erase_challenge(%L, %L, %L)$$, :'o5_user_id', :'o5_session_id', :'req'), '%already carried out%');
SELECT t.expect_error('the approval taken before the erasure cannot be used',
  format($$SELECT memory.decide_approval_challenge(%L, %L, %L, %L)$$, :'o3_user_id', :'o3_session_id', :'pend_challenge_id', :'pend_secret'),
  '%');
RESET ROLE;
SELECT t.expect_state('the erased revision stays erased', :'m3', 'erased/pending');

\echo '-- an erased memory stays erased, and nothing attaches to it'
SELECT t.expect_denied('not even the database owner can bring it back',
  format($$UPDATE memory.memories SET status = 'active' WHERE id = %L$$, :'m2'));
SELECT t.expect_denied('or give it text',
  format($$UPDATE memory.memories SET content = 'back' WHERE id = %L$$, :'m2'));
SELECT t.expect_denied('or embed it again', format($$SELECT t.embed(%L)$$, :'m2'));
SELECT t.expect_denied('or mention an entity in it',
  format($$INSERT INTO memory.entity_mentions (memory_id, entity_id, namespace_id, provenance_id) VALUES (%L, %L, %L, %L)$$,
         :'m2', :'e_vendor', :'c1', :'m2_prov'));
SELECT t.expect_denied('or link to it',
  format($$INSERT INTO memory.memory_links (namespace_id, from_memory_id, kind, to_memory_id, provenance_id)
           VALUES (%L, %L, 'related', %L, %L)$$, :'c1', :'keep', :'m2', :'m2_prov'));
SELECT t.expect_denied('or cite it as evidence',
  format($$INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id, evidence_memory_id, provenance_id)
           VALUES (%L, %L, 'knows', %L, %L, %L)$$, :'c1', :'e_vendor', :'e_shared', :'m2', :'m2_prov'));
SELECT t.expect_denied('or erase it twice by hand',
  format($$INSERT INTO memory.erasures (memory_id, namespace_id, source) VALUES (%L, %L, 'restore')$$, :'m2', :'c1'));
SELECT t.expect_denied('the tombstone is a record',
  format($$DELETE FROM memory.erasures WHERE memory_id = %L$$, :'m2'));
SELECT t.expect_denied('and so is the request',
  format($$UPDATE memory.erasure_requests SET reason = 'legal' WHERE id = %L$$, :'req'));
SELECT t.expect_denied('and its items',
  format($$DELETE FROM memory.erasure_request_items WHERE request_id = %L$$, :'req'));
SELECT t.expect_denied('and the approval records keep their shape',
  'UPDATE memory.approvals SET content_sha256 = NULL WHERE content_sha256 IS NOT NULL');
SELECT t.expect_denied('and so do the approval challenges',
  'UPDATE memory.approval_challenges SET content_sha256 = NULL WHERE content_sha256 IS NOT NULL');
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT t.expect_error('a revision of an erased memory is refused',
    format($$SELECT memory.propose_revision(%L, 'fact', 'x', 'remember', 'rest', 'fact')$$, :'m2'), '%');
  SELECT t.expect_error('as is asking to erase it again',
    format($$SELECT memory.request_erasure(ARRAY[%L]::uuid[], 'owner_request')$$, :'m2'), '%already erased%');
  SELECT t.expect_denied('it cannot be retracted',
    format($$UPDATE memory.memories SET status = 'retracted' WHERE id = %L$$, :'m2'), true);
  SELECT t.expect_count('recall does not find it',
    $$SELECT 1 FROM memory.memories WHERE dedup_key = 'er-contact' AND status = 'active'$$, 0);
  -- The tombstone holds no fingerprint, so the same text can be stored again.
  SELECT memory.remember('fact', 'erasure check: the vendor contact is Pat at 555 0199', 'remember', 'rest',
                         p_dedup_key => 'er-contact') AS again \gset
COMMIT;
RESET ROLE;
SELECT t.expect_state('storing the same text again is a new memory', :'again', 'active/none');

\echo '-- a revoked owner erases nothing'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('note', 'erasure check: revoke case', 'remember', 'rest') AS rv \gset
  SELECT memory.request_erasure(ARRAY[:'rv']::uuid[], 'stored_in_error') AS req_rv \gset
COMMIT;
SELECT * FROM t.erase_challenge(:'w1_user_id', :'w1_session_id', :'req_rv') \gset rc_
RESET ROLE;
SET ROLE engramport_admin;
UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'owner_left' WHERE id = :'a_owner2';
RESET ROLE;
SET ROLE engramport_app;
SELECT t.expect_error('the revoked owner''s challenge',
  format($$SELECT memory.decide_erasure_challenge(%L, %L, %L, %L)$$, :'w1_user_id', :'w1_session_id', :'rc_challenge_id', :'rc_secret'),
  '%no longer valid%');
SELECT memory.note_erasure_failure(:'req_rv', '55000');
SELECT t.expect_error('a failure note needs a real error class',
  format($$SELECT memory.note_erasure_failure(%L, 'oops')$$, :'req_rv'), '%SQLSTATE%');
RESET ROLE;
SELECT t.expect_state('the memory is untouched', :'rv', 'active/none');
SELECT t.expect_count('the failure is on record, with its error class only',
  format($$SELECT 1 FROM memory.erasure_attempts WHERE request_id = %L AND sqlstate = '55000'$$, :'req_rv'), 1);

\echo '-- a grant that does not cover every version erases nothing, even with a challenge written under it'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('fact', 'erasure check: a fact the observation owner cannot erase', 'remember', 'rest',
                         p_claim_type => 'fact') AS cv \gset
  SELECT memory.request_erasure(ARRAY[:'cv']::uuid[], 'owner_request') AS req_cv \gset
COMMIT;
RESET ROLE;
SELECT * FROM t.sign_in('er-obs@client.test') \gset b2_
INSERT INTO memory.erasure_challenges (request_id, actor_id, authority_id, items_sha256, secret_sha256, sign_in_hash, expires_at)
  VALUES (:'req_cv', :'obs', :'a_obs', memory.erasure_items_sha256(:'req_cv'), sha256(decode(repeat('b', 64), 'hex')),
          sha256(uuid_send(:'b2_session_id'::uuid)), now() + interval '10 minutes')
  RETURNING id AS ch_cv \gset
SET ROLE engramport_app;
SELECT t.expect_error('the observation-only owner''s challenge for a fact',
  format($$SELECT memory.decide_erasure_challenge(%L, %L, %L, %L)$$, :'b2_user_id', :'b2_session_id', :'ch_cv', repeat('b', 64)),
  '%no longer valid%');
RESET ROLE;
SELECT t.expect_state('the fact is untouched', :'cv', 'active/none');

\echo '-- an expired confirmation erases nothing'
SELECT * FROM t.sign_in('er-owner@client.test') \gset ex_
INSERT INTO memory.erasure_challenges (request_id, actor_id, authority_id, items_sha256, secret_sha256, sign_in_hash,
    issued_at, expires_at)
  VALUES (:'req_rv', :'owner', :'a_owner', memory.erasure_items_sha256(:'req_rv'), sha256(decode(repeat('a', 64), 'hex')),
          sha256(uuid_send(:'ex_session_id'::uuid)), now() - interval '20 minutes', now() - interval '10 minutes')
  RETURNING id AS ch_ex \gset
SET ROLE engramport_app;
SELECT t.expect_error('an expired challenge',
  format($$SELECT memory.decide_erasure_challenge(%L, %L, %L, %L)$$, :'ex_user_id', :'ex_session_id', :'ch_ex', repeat('a', 64)),
  '%expired%');
RESET ROLE;
SELECT t.expect_state('still untouched', :'rv', 'active/none');

\echo '-- an erasure is all or nothing'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('note', 'erasure check: bulk one', 'remember', 'rest') AS bk1 \gset
  SELECT memory.remember('note', 'erasure check: bulk two', 'remember', 'rest') AS bk2 \gset
  SELECT memory.request_erasure(ARRAY[:'bk1', :'bk2']::uuid[], 'owner_request') AS req_bk \gset
COMMIT;
SELECT * FROM t.erase_challenge(:'o6_user_id', :'o6_session_id', :'req_bk') \gset bk_
BEGIN;
  SELECT memory.decide_erasure_challenge(:'o6_user_id', :'o6_session_id', :'bk_challenge_id', :'bk_secret') IS NOT NULL;
ROLLBACK;
RESET ROLE;
SELECT t.expect_count('rolled back, both memories keep their text',
  format($$SELECT 1 FROM memory.memories WHERE id IN (%L, %L) AND status = 'active' AND content LIKE 'erasure check: bulk%%'$$,
         :'bk1', :'bk2'), 2);
SELECT t.expect_count('and no tombstone is kept',
  format($$SELECT 1 FROM memory.erasures WHERE request_id = %L$$, :'req_bk'), 0);
CREATE FUNCTION t.boom_erase() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id::text = current_setting('t.boom_id', true) AND NEW.status = 'erased' THEN
    RAISE EXCEPTION 'boom';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER zz_boom BEFORE UPDATE ON memory.memories FOR EACH ROW EXECUTE FUNCTION t.boom_erase();
SELECT set_config('t.boom_id', greatest(:'bk1', :'bk2'), false) \g /dev/null
SET ROLE engramport_app;
SELECT t.expect_error('a failure on the second memory',
  format($$SELECT memory.decide_erasure_challenge(%L, %L, %L, %L)$$, :'o6_user_id', :'o6_session_id', :'bk_challenge_id', :'bk_secret'),
  'boom');
RESET ROLE;
DROP TRIGGER zz_boom ON memory.memories;
SELECT set_config('t.boom_id', '', false) \g /dev/null
SELECT t.expect_count('leaves the first memory untouched too',
  format($$SELECT 1 FROM memory.memories WHERE id IN (%L, %L) AND status = 'active'$$, :'bk1', :'bk2'), 2);
SELECT t.expect_count('with no tombstone',
  format($$SELECT 1 FROM memory.erasures WHERE request_id = %L$$, :'req_bk'), 0);
SET ROLE engramport_app;
SELECT memory.decide_erasure_challenge(:'o6_user_id', :'o6_session_id', :'bk_challenge_id', :'bk_secret') ->> 'versions' AS bk_versions \gset
RESET ROLE;
SELECT t.expect_count('then the same challenge erases both, once',
  format($$SELECT 1 WHERE %L = '2'$$, :'bk_versions'), 1);
SELECT t.expect_count('two tombstones',
  format($$SELECT 1 FROM memory.erasures WHERE request_id = %L$$, :'req_bk'), 2);

\echo '-- restoring from a backup: erasures are applied again before anyone is served'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('note', 'erasure check: brought back by a restore', 'remember', 'rest') AS rs \gset
COMMIT;
RESET ROLE;
SELECT t.embed(:'rs');
-- A restored database still holds this text; the ledger kept outside says it was erased.
SELECT memory.reapply_erasures(ARRAY[:'rs', :'m2', gen_random_uuid()]::uuid[]) AS reapplied \gset
SELECT t.expect_count('the restored memory is erased again; the ones already erased are skipped',
  format($$SELECT 1 WHERE (%L::jsonb) = '{"versions_erased": 1, "not_in_this_database": 1}'$$, :'reapplied'), 1);
SELECT t.expect_count('with a restore tombstone and nothing derived left',
  format($$SELECT 1 FROM memory.erasures e JOIN memory.memories m ON m.id = e.memory_id
           WHERE e.memory_id = %L AND e.source = 'restore' AND e.request_id IS NULL AND m.content = ''
             AND NOT EXISTS (SELECT 1 FROM memory.memory_embeddings x WHERE x.memory_id = %L)$$, :'rs', :'rs'), 1);
SELECT t.expect_count('running it again changes nothing',
  format($$SELECT 1 WHERE memory.reapply_erasures(ARRAY[%L]::uuid[]) ->> 'versions_erased' = '0'$$, :'rs'), 1);

\echo '-- the admin sees the ledger, never text or secrets, and erases nothing'
SET ROLE engramport_admin;
SELECT t.expect_count('the admin reads requests, items, tombstones and failures',
  format($$SELECT 1 FROM memory.erasure_requests WHERE id = %L
           UNION ALL SELECT 1 FROM memory.erasure_request_items WHERE request_id = %L
           UNION ALL SELECT 1 FROM memory.erasures WHERE memory_id = %L
           UNION ALL SELECT 1 FROM memory.erasure_attempts WHERE request_id = %L$$, :'req', :'req', :'m2', :'req_rv'), 4);
SELECT t.expect_count('and who took which challenge, when',
  format($$SELECT id, request_id, actor_id, authority_id, issued_at, expires_at FROM memory.erasure_challenges
           WHERE id = %L$$, :'ec_challenge_id'), 1);
SELECT t.expect_denied('not the challenge secret', 'SELECT secret_sha256 FROM memory.erasure_challenges');
SELECT t.expect_denied('or the sign-in it was bound to', 'SELECT sign_in_hash FROM memory.erasure_challenges');
SELECT t.expect_denied('the admin cannot ask for an erasure',
  format($$SELECT memory.request_erasure(ARRAY[%L]::uuid[], 'legal')$$, :'keep'));
SELECT t.expect_denied('or carry one out',
  format($$SELECT memory.erase_chain(%L, NULL, 'restore')$$, :'keep'));
SELECT t.expect_denied('or reapply erasures',
  format($$SELECT memory.reapply_erasures(ARRAY[%L]::uuid[])$$, :'keep'));
SELECT t.expect_denied('or write the ledger',
  format($$INSERT INTO memory.erasures (memory_id, namespace_id, source) VALUES (%L, %L, 'restore')$$, :'keep', :'c1'));
RESET ROLE;
SELECT t.expect_count('no API role reaches any erasure function or table',
  $$SELECT 1 FROM pg_roles r CROSS JOIN pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE r.rolname IN ('anon', 'authenticated', 'service_role') AND n.nspname = 'memory'
      AND p.proname LIKE '%erasure%' AND has_function_privilege(r.oid, p.oid, 'EXECUTE')
    UNION ALL
    SELECT 1 FROM pg_roles r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE r.rolname IN ('anon', 'authenticated', 'service_role') AND n.nspname = 'memory'
      AND c.relname LIKE 'erasure%' AND has_table_privilege(r.oid, c.oid, 'SELECT')$$, 0);
SELECT t.expect_count('the app holds no erasure table privilege',
  $$SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'memory' AND c.relname LIKE 'erasure%' AND c.relkind = 'r'
      AND (has_table_privilege('engramport_app', c.oid, 'SELECT') OR has_table_privilege('engramport_app', c.oid, 'INSERT')
           OR has_table_privilege('engramport_app', c.oid, 'UPDATE') OR has_table_privilege('engramport_app', c.oid, 'DELETE'))$$, 0);

\echo 'all erasure tests passed'
