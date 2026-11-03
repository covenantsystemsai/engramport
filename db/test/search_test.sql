-- Tests for 0008_search. Run by db/test/run.sh after extraction_test.sql. Uses
-- the rls_test fixtures (city > tower-b > cell-3, and tower-a > cell-2) and
-- words no other test writes, so the counts are exact.
\set ON_ERROR_STOP on
\set QUIET on
\set city '00000000-0000-7000-8000-000000000001'
\set tb   '00000000-0000-7000-8000-000000000012'
\set c2   '00000000-0000-7000-8000-000000000112'
\set c3   '00000000-0000-7000-8000-000000000121'
\set k_city '00000000-0000-7000-8000-0000000000c0'
\set k_tb '00000000-0000-7000-8000-0000000000b0'
\set k_c2 '00000000-0000-7000-8000-0000000000f2'
\set k_c3 '00000000-0000-7000-8000-0000000000f3'

-- A stand-in 1536-dimension model for cell 3 (0011), so no real model is needed.
INSERT INTO memory.embedding_models (model, dimension, stays_in_supabase, description)
  VALUES ('test-model', 1536, true, 'test only');
UPDATE memory.namespaces SET embedding_model = 'test-model' WHERE id = :'c3';

SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_city', :'city');
  SELECT memory.remember('principle', 'zephyr pump city principle', 'remember', 'rest') IS NOT NULL;
COMMIT;
BEGIN; SELECT t.as_key(:'k_tb', :'tb');
  SELECT memory.remember('insight', 'zephyr pump general lesson', 'remember', 'rest') IS NOT NULL;
  SELECT memory.remember('fact', 'quill gasket same words', 'remember', 'rest') IS NOT NULL;
COMMIT;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT memory.remember('fact', 'zephyr pump cell two secret', 'remember', 'rest') IS NOT NULL;
COMMIT;
BEGIN; SELECT t.as_key(:'k_c3', :'c3');
  SELECT memory.remember('decision', 'zephyr pump decision for the north yard', 'remember', 'rest') AS dec_mem \gset
  SELECT memory.remember('note', 'zephyr pump retracted note', 'remember', 'rest') AS gone_mem \gset
  SELECT memory.remember('fact', 'quill gasket same words', 'remember', 'rest') AS tie_mem \gset
  SELECT memory.remember('fact', 'maintenance schedule for the yard', 'remember', 'rest') AS yard_mem \gset
  SELECT memory.remember('fact', 'weak link memory about the shed', 'remember', 'rest') AS shed_mem \gset
  SELECT memory.remember('fact', 'inspection notes for the valve', 'remember', 'rest') AS valve_mem \gset
  UPDATE memory.memories SET status = 'retracted' WHERE id = :'gone_mem';
  SELECT memory.record_provenance('link', 'rest') AS prov \gset
  INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
    VALUES (:'c3', 'equipment', 'Zephyr Pump', :'prov') RETURNING id AS pump \gset
  INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
    VALUES (:'c3', 'place', 'North Yard', :'prov') RETURNING id AS yard \gset
  INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
    VALUES (:'c3', 'place', 'Old Shed', :'prov') RETURNING id AS shed \gset
  INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
    VALUES (:'c3', 'equipment', 'Gate Valve', :'prov') RETURNING id AS valve \gset
  INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id, confidence, provenance_id)
    VALUES (:'c3', :'pump', 'located_at', :'yard', 0.9, :'prov'),
           (:'c3', :'pump', 'maybe_near', :'shed', 0.3, :'prov'),
           (:'c3', :'yard', 'has_part', :'valve', 0.9, :'prov');
  INSERT INTO memory.entity_mentions (memory_id, entity_id, namespace_id, provenance_id)
    VALUES (:'yard_mem', :'yard', :'c3', :'prov'), (:'shed_mem', :'shed', :'c3', :'prov'),
           (:'valve_mem', :'valve', :'c3', :'prov');
  INSERT INTO memory.memory_embeddings (memory_id, namespace_id, model, dimension, embedding)
    VALUES (:'yard_mem', :'c3', 'test-model', 1536,
            ('[' || array_to_string(array_fill(0.1::real, ARRAY[1536]), ',') || ']')::extensions.halfvec);
COMMIT;

\echo '-- what a cell can find'
BEGIN; SELECT t.as_key(:'k_c3', :'c3');
SELECT t.expect_count('keyword search finds the cell''s, its tower''s and its city''s memories',
  $$SELECT 1 FROM memory.search('zephyr pump', p_retrievers => ARRAY['keyword'], p_limit => 50) s
    JOIN memory.memories m ON m.id = s.memory_id WHERE m.content LIKE 'zephyr pump%'$$, 3);
SELECT t.expect_count('never a cell under another tower',
  $$SELECT 1 FROM memory.search('zephyr pump cell two secret', p_limit => 50) s
    JOIN memory.memories m ON m.id = s.memory_id WHERE m.content LIKE '%cell two%'$$, 0);
SELECT t.expect_count('never a retracted memory',
  format($$SELECT 1 FROM memory.search('zephyr pump retracted note', p_limit => 50) WHERE memory_id = %L$$, :'gone_mem'), 0);
SELECT t.expect_count('each hit says how far up the tree it came from',
  $$SELECT 1 FROM memory.search('zephyr pump', p_retrievers => ARRAY['keyword'], p_limit => 50) s
    JOIN memory.memories m ON m.id = s.memory_id
    WHERE (m.content LIKE '%north yard' AND s.depth = 0) OR (m.content LIKE '%general lesson' AND s.depth = 1)
       OR (m.content LIKE '%city principle' AND s.depth = 2)$$, 3);
SELECT t.expect_count('any query word may match, so a question still finds the memory',
  $$SELECT 1 FROM memory.search('what did we decide about the zephyr', p_retrievers => ARRAY['keyword']) s
    JOIN memory.memories m ON m.id = s.memory_id WHERE m.content LIKE '%north yard'$$, 1);
SELECT t.expect_count('a decision outranks a lesson that matches as well',
  $$SELECT 1 FROM (SELECT s.memory_id, row_number() OVER () AS pos
                   FROM memory.search('zephyr pump', p_retrievers => ARRAY['keyword']) s) r
    JOIN memory.memories m ON m.id = r.memory_id WHERE r.pos = 1 AND m.kind = 'decision'$$, 1);
SELECT t.expect_count('on a tie the cell''s own memory comes before its tower''s',
  format($$SELECT 1 FROM (SELECT s.memory_id, row_number() OVER () AS pos
                          FROM memory.search('quill gasket same words', p_retrievers => ARRAY['keyword']) s) r
           WHERE r.pos = 1 AND r.memory_id = %L$$, :'tie_mem'), 1);
SELECT t.expect_count('the graph finds a memory through an entity the query names, one hop away',
  format($$SELECT 1 FROM memory.search('zephyr pump', p_retrievers => ARRAY['graph'])
           WHERE memory_id = %L AND graph_entity = 'North Yard' AND graph_hops = 1 AND graph_rank = 1$$, :'yard_mem'), 1);
SELECT t.expect_count('and two hops away, ranked after the nearer hop',
  format($$SELECT 1 FROM memory.search('zephyr pump', p_retrievers => ARRAY['graph'])
           WHERE memory_id = %L AND graph_entity = 'Gate Valve' AND graph_hops = 2 AND graph_rank = 2$$, :'valve_mem'), 1);
SELECT t.expect_count('but not across a relation below the confidence floor',
  format($$SELECT 1 FROM memory.search('zephyr pump', p_retrievers => ARRAY['graph']) WHERE memory_id = %L$$, :'shed_mem'), 0);
SELECT t.expect_count('vector search ranks by the query embedding',
  format($$SELECT 1 FROM memory.search('anything', ('[' || array_to_string(array_fill(0.1::real, ARRAY[1536]), ',') || ']')::extensions.halfvec,
             'test-model', p_retrievers => ARRAY['vector']) WHERE memory_id = %L AND vector_rank = 1$$, :'yard_mem'), 1);
SELECT t.expect_count('an embedding of another model is never compared',
  $$SELECT 1 FROM memory.search('anything', ('[' || array_to_string(array_fill(0.1::real, ARRAY[1536]), ',') || ']')::extensions.halfvec,
      'other-model', p_retrievers => ARRAY['vector'])$$, 0);
SELECT t.expect_count('hybrid blends all three and keeps each rank',
  format($$SELECT 1 FROM memory.search('zephyr pump yard', ('[' || array_to_string(array_fill(0.1::real, ARRAY[1536]), ',') || ']')::extensions.halfvec,
             'test-model') WHERE memory_id = %L AND vector_rank IS NOT NULL AND keyword_rank IS NOT NULL AND graph_rank IS NOT NULL$$, :'yard_mem'), 1);
SELECT t.expect_count('kind and date filters apply',
  $$SELECT 1 FROM memory.search('zephyr pump', p_kind => 'decision', p_from => now() - interval '1 hour', p_limit => 50)$$, 1);
SELECT t.expect_count('a search returns every match up to its limit',
  $$SELECT 1 FROM memory.search('zephyr pump quill yard', p_limit => 1000)$$, 7);
SELECT t.expect_count('and no more',
  $$SELECT 1 FROM memory.search('zephyr pump quill yard', p_limit => 2)$$, 2);
ROLLBACK;

BEGIN; SELECT t.as_key(:'k_c3', :'c3');
UPDATE memory.entities SET status = 'retracted' WHERE id = :'yard';
SELECT t.expect_count('a retracted entity breaks the path through it',
  format($$SELECT 1 FROM memory.search('zephyr pump', p_retrievers => ARRAY['graph']) WHERE memory_id IN (%L, %L)$$,
         :'yard_mem', :'valve_mem'), 0);
ROLLBACK;

\echo '-- what others can find'
BEGIN; SELECT t.as_key(:'k_tb', :'tb');
SELECT t.expect_count('a tower never finds its cells'' memories',
  $$SELECT 1 FROM memory.search('zephyr pump', p_limit => 50) s JOIN memory.memories m ON m.id = s.memory_id
    WHERE m.namespace_id = '00000000-0000-7000-8000-000000000121'$$, 0);
ROLLBACK;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
SELECT t.expect_count('another tower''s cell finds none of cell 3''s graph',
  $$SELECT 1 FROM memory.search('zephyr pump', p_retrievers => ARRAY['graph'], p_limit => 50)$$, 0);
ROLLBACK;
BEGIN;
SELECT t.expect_count('no key finds nothing', $$SELECT 1 FROM memory.search('zephyr pump', p_limit => 50)$$, 0);
ROLLBACK;
RESET ROLE;

\echo '-- who may run it'
SELECT t.expect_count('search runs with the caller''s rights',
  $$SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'memory' AND p.proname = 'search' AND NOT p.prosecdef$$, 1);
SELECT t.expect_count('no API role and not the admin role can run it',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role', 'engramport_admin']) r
    JOIN pg_proc p ON p.proname = 'search' JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = 'memory'
    WHERE has_function_privilege(r, p.oid, 'EXECUTE')$$, 0);

\echo 'all search tests passed'

\echo '-- keyword candidates are chosen by coverage, not raw rank (0013)'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c3', :'c3');
SELECT count(memory.remember('fact', repeat('quokka ', 10) || 'decoy ' || g, 'remember', 'rest')) FROM generate_series(1, 45) g \gset
SELECT memory.remember('fact', 'quokka harbour lantern ledger', 'remember', 'rest') AS full_mem \gset
SELECT t.expect_count('a memory with every query word is found past forty that repeat one',
  format($$SELECT 1 FROM (SELECT s.memory_id, row_number() OVER () AS pos
                          FROM memory.search('quokka harbour lantern ledger', p_retrievers => ARRAY['keyword'], p_limit => 5) s) r
           WHERE r.memory_id = %L AND r.pos = 1$$, :'full_mem'), 1);
ROLLBACK;
RESET ROLE;
