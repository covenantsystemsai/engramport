-- Tests for 0005_company_namespace. Run by db/test/run.sh after graph_test.sql,
-- which leaves the helpers in schema t and the client fixtures in place: city
-- testcity > tower-a > cell-1, cell-2, with memories and graph rows in each.
-- The company tree is opcity > company > hq. Nothing may cross between them.
\set ON_ERROR_STOP on
\set QUIET on
\set city '00000000-0000-7000-8000-000000000001'
\set ta   '00000000-0000-7000-8000-000000000011'
\set c1   '00000000-0000-7000-8000-000000000111'
\set k_c1 '00000000-0000-7000-8000-0000000000f1'
\set k_city '00000000-0000-7000-8000-0000000000c0'
\set k_co_city '00000000-0000-7000-8000-0000000000c9'
\set k_co_hq   '00000000-0000-7000-8000-0000000000f9'

\echo '-- purpose shape'
SELECT t.expect_count('every namespace made before 0005 is a client namespace',
  $$SELECT 1 FROM memory.namespaces WHERE purpose <> 'client'$$, 0);
SELECT t.expect_count('purpose is required',
  $$SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'memory' AND table_name = 'namespaces' AND column_name = 'purpose' AND is_nullable = 'NO'$$, 1);

\echo '-- the admin role builds the company tree'
SET ROLE engramport_admin;
INSERT INTO memory.namespaces (level, slug, purpose) VALUES ('city', 'opcity', 'company') RETURNING id AS co_city \gset
INSERT INTO memory.namespaces (parent_id, level, slug, purpose) VALUES (:'co_city', 'tower', 'company', 'company')
  RETURNING id AS co_tower \gset
INSERT INTO memory.namespaces (parent_id, level, slug, purpose) VALUES (:'co_tower', 'cell', 'hq', 'company')
  RETURNING id AS co_hq, path AS co_path \gset
SELECT t.expect_count('the company cell has a derived path',
  format($$SELECT 1 WHERE %L = 'opcity/company/hq'$$, :'co_path'), 1);
SELECT t.expect_denied('a client tower cannot sit under the company city',
  format($$INSERT INTO memory.namespaces (parent_id, level, slug) VALUES (%L, 'tower', 'client-tower')$$, :'co_city'));
SELECT t.expect_denied('a client cell cannot sit under a company tower',
  format($$INSERT INTO memory.namespaces (parent_id, level, slug) VALUES (%L, 'cell', 'client-cell')$$, :'co_tower'));
SELECT t.expect_denied('a company tower cannot sit under a client city',
  format($$INSERT INTO memory.namespaces (parent_id, level, slug, purpose) VALUES (%L, 'tower', 'co', 'company')$$, :'city'));
SELECT t.expect_denied('a company cell cannot sit under a client tower',
  format($$INSERT INTO memory.namespaces (parent_id, level, slug, purpose) VALUES (%L, 'cell', 'co', 'company')$$, :'ta'));
SELECT t.expect_denied('there is only one company city',
  $$INSERT INTO memory.namespaces (level, slug, purpose) VALUES ('city', 'opcity-two', 'company')$$);
SELECT t.expect_denied('the admin role cannot change a purpose',
  format($$UPDATE memory.namespaces SET purpose = 'client' WHERE id = %L$$, :'co_city'));
RESET ROLE;
SELECT t.expect_denied('even the owner cannot turn the company city into a client city',
  format($$UPDATE memory.namespaces SET purpose = 'client' WHERE id = %L$$, :'co_city'));
SELECT t.expect_denied('even the owner cannot turn a client cell into a company cell',
  format($$UPDATE memory.namespaces SET purpose = 'company' WHERE id = %L$$, :'c1'));
SELECT t.expect_denied('even the owner cannot move the company cell under a client tower',
  format($$UPDATE memory.namespaces SET parent_id = %L WHERE id = %L$$, :'ta', :'co_hq'));

-- Company keys, as the owner, the way the admin tool mints them.
INSERT INTO memory.api_keys (id, namespace_id, actor_id, prefix, key_hash, scopes) VALUES
  (:'k_co_city', :'co_city', '00000000-0000-7000-8000-00000000a001', 'ek_cocity00', sha256('co-city'), '{read,write}'),
  (:'k_co_hq', :'co_hq', '00000000-0000-7000-8000-00000000a002', 'ek_cohq0000', sha256('co-hq'), '{read,write}');

-- One memory and one entity in the company city and cell.
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_co_city', :'co_city');
  SELECT memory.remember('principle', 'company city principle', 'remember', 'rest') IS NOT NULL;
COMMIT;
BEGIN; SELECT t.as_key(:'k_co_hq', :'co_hq');
  SELECT memory.remember('fact', 'company hq decision', 'remember', 'rest') AS co_mem \gset
  SELECT memory.record_provenance('link', 'rest') AS co_prov \gset
  INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
    VALUES (:'co_hq', 'concept', 'How we price', :'co_prov') RETURNING id AS co_ent \gset
COMMIT;
RESET ROLE;
SELECT id AS ta_ent FROM memory.entities WHERE name = 'Listing workflow' \gset
SELECT id AS c1_mem FROM memory.memories WHERE content = 'cell 1 secret' \gset

\echo '-- a client cell sees nothing of the company'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT t.expect_count('a client cell sees no company namespace',
  $$SELECT 1 FROM memory.namespaces WHERE purpose = 'company'$$, 0);
SELECT t.expect_count('a client cell sees no company memory',
  $$SELECT 1 FROM memory.memories WHERE content LIKE 'company%'$$, 0);
SELECT t.expect_count('a client cell sees no company entity',
  $$SELECT 1 FROM memory.entities WHERE name = 'How we price'$$, 0);
SELECT memory.record_provenance('link', 'rest') AS c1_prov \gset
SELECT t.expect_denied('a client cell cannot relate its graph to a company entity',
  format($$INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id, provenance_id)
           VALUES (%L, %L, 'uses', %L, %L)$$, :'c1', :'ta_ent', :'co_ent', :'c1_prov'));
SELECT t.expect_denied('a client cell cannot link a memory to a company memory',
  format($$INSERT INTO memory.memory_links (namespace_id, from_memory_id, kind, to_memory_id, provenance_id)
           VALUES (%L, %L, 'related', %L, %L)$$, :'c1', :'c1_mem', :'co_mem', :'c1_prov'));
COMMIT;

BEGIN; SELECT t.as_key(:'k_city', :'city');
SELECT t.expect_count('the client city sees no company memory either',
  $$SELECT 1 FROM memory.memories WHERE content LIKE 'company%'$$, 0);
COMMIT;

\echo '-- the company cell sees its own tree and nothing of any client'
BEGIN; SELECT t.as_key(:'k_co_hq', :'co_hq');
SELECT t.expect_count('the company cell reads its own and its city''s memories',
  $$SELECT 1 FROM memory.memories WHERE content IN ('company hq decision', 'company city principle')$$, 2);
SELECT t.expect_count('the company cell sees only company namespaces',
  $$SELECT 1 FROM memory.namespaces WHERE purpose = 'client'$$, 0);
SELECT t.expect_count('the company cell sees no client memory, not even a client city''s',
  $$SELECT 1 FROM memory.memories WHERE content NOT LIKE 'company%'$$, 0);
SELECT t.expect_count('the company cell sees no client entity',
  $$SELECT 1 FROM memory.entities WHERE name <> 'How we price'$$, 0);
SELECT t.expect_denied('the company cell cannot relate its graph to a client entity',
  format($$INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id, provenance_id)
           VALUES (%L, %L, 'uses', %L, %L)$$, :'co_hq', :'co_ent', :'ta_ent', :'co_prov'));
SELECT t.expect_denied('the company cell cannot link a memory to a client memory',
  format($$INSERT INTO memory.memory_links (namespace_id, from_memory_id, kind, to_memory_id, provenance_id)
           VALUES (%L, %L, 'related', %L, %L)$$, :'co_hq', :'co_mem', :'c1_mem', :'co_prov'));
SELECT t.expect_denied('the company cell cannot write into a client cell',
  format($$INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
           VALUES (%L, 'concept', 'leak', %L)$$, :'c1', :'co_prov'));
COMMIT;
RESET ROLE;

\echo '-- the Supabase API roles get nothing new'
SELECT t.expect_count('no API role can run the purpose trigger',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) r
    WHERE has_function_privilege(r, 'memory.namespaces_purpose()', 'EXECUTE')$$, 0);

\echo 'all company namespace tests passed'
