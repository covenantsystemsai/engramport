-- Tests for 0004_graph. Run by db/test/run.sh after rls_test.sql, which
-- leaves its helpers in schema t and its namespaces, actors and keys in place.
\set ON_ERROR_STOP on
\set QUIET on
\set city '00000000-0000-7000-8000-000000000001'
\set ta   '00000000-0000-7000-8000-000000000011'
\set c1   '00000000-0000-7000-8000-000000000111'
\set c2   '00000000-0000-7000-8000-000000000112'
\set k_ta '00000000-0000-7000-8000-0000000000a0'
\set k_c1 '00000000-0000-7000-8000-0000000000f1'
\set k_c1b '00000000-0000-7000-8000-0000000000f4'
\set k_c1ro '00000000-0000-7000-8000-0000000000e1'
\set k_c2 '00000000-0000-7000-8000-0000000000f2'

\echo '-- graph shape'
SELECT t.expect_count('every graph table has row security on and forced',
  $$SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'memory' AND c.relname IN
      ('entities', 'entity_aliases', 'relations', 'entity_mentions', 'memory_links')
      AND c.relrowsecurity AND c.relforcerowsecurity$$, 5);
SELECT t.expect_count('names normalize the same way however they are typed',
  $$SELECT 1 WHERE memory.norm_key('  Grok   BOT ') = 'grok bot' AND memory.norm_key('ＡＮ２Ｂ') = 'an2b'$$, 1);

-- Fixtures written through the app role: an entity and a memory in tower a,
-- and one each in cell 2, so cell 1 has something it may and may not reach.
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_ta', :'ta');
  SELECT memory.record_provenance('link', 'rest') AS ta_prov \gset
  INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
    VALUES (:'ta', 'concept', 'Listing workflow', :'ta_prov') RETURNING id AS ta_ent \gset
  SELECT memory.remember('insight', 'tower graph lesson', 'remember', 'rest') AS ta_mem \gset
COMMIT;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT memory.record_provenance('link', 'rest') AS c2_prov \gset
  INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
    VALUES (:'c2', 'person', 'Cell two client', :'c2_prov') RETURNING id AS c2_ent \gset
  SELECT memory.remember('fact', 'cell 2 graph secret', 'remember', 'rest') AS c2_mem \gset
COMMIT;
BEGIN; SELECT t.as_key(:'k_c1b', :'c1');
  SELECT memory.record_provenance('link', 'rest') AS c1b_prov \gset
COMMIT;

\echo '-- what a cell can write'
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT memory.record_provenance('link', 'streamable_http', p_client_name => 'claude-ai') AS prov \gset
INSERT INTO memory.entities (namespace_id, type, name, norm_key, provenance_id)
  VALUES (:'c1', 'agent', '  Grok   Bot ', 'forged', :'prov') RETURNING id AS e_bot, norm_key AS bot_key \gset
INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
  VALUES (:'c1', 'project', 'EngramPort', :'prov') RETURNING id AS e_proj \gset
SELECT t.expect_count('the stored key is computed, not taken from the caller',
  format($$SELECT 1 WHERE %L = 'grok bot'$$, :'bot_key'), 1);
SELECT memory.remember('fact', 'Grok Bot builds EngramPort', 'remember', 'streamable_http') AS c1_mem \gset
SELECT t.expect_rows('a cell adds an alias to its own entity',
  format($$INSERT INTO memory.entity_aliases (entity_id, namespace_id, alias, provenance_id)
           VALUES (%L, %L, 'Grok', %L)$$, :'e_bot', :'c1', :'prov'), 1);
SELECT t.expect_rows('a cell relates two of its own entities, with evidence',
  format($$INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id,
             confidence, evidence_memory_id, evidence_span, provenance_id)
           VALUES (%L, %L, 'works_on', %L, 0.9, %L, 'builds EngramPort', %L)$$,
    :'c1', :'e_bot', :'e_proj', :'c1_mem', :'prov'), 1);
SELECT t.expect_rows('a cell relates its entity to a tower entity',
  format($$INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id, provenance_id)
           VALUES (%L, %L, 'follows', %L, %L)$$, :'c1', :'e_proj', :'ta_ent', :'prov'), 1);
SELECT t.expect_rows('a cell records that its memory mentions an entity',
  format($$INSERT INTO memory.entity_mentions (memory_id, entity_id, namespace_id, provenance_id)
           VALUES (%L, %L, %L, %L)$$, :'c1_mem', :'e_bot', :'c1', :'prov'), 1);
SELECT t.expect_rows('a cell records that its memory mentions a tower entity',
  format($$INSERT INTO memory.entity_mentions (memory_id, entity_id, namespace_id, provenance_id)
           VALUES (%L, %L, %L, %L)$$, :'c1_mem', :'ta_ent', :'c1', :'prov'), 1);
SELECT t.expect_rows('a cell links its memory to a tower memory',
  format($$INSERT INTO memory.memory_links (namespace_id, from_memory_id, kind, to_memory_id, provenance_id)
           VALUES (%L, %L, 'derived_from', %L, %L)$$, :'c1', :'c1_mem', :'ta_mem', :'prov'), 1);
COMMIT;

\echo '-- what a cell cannot write'
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT memory.record_provenance('link', 'rest') AS prov \gset
SELECT t.expect_denied('a second active entity with the same name and type',
  format($$INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
           VALUES (%L, 'agent', 'grok bot', %L)$$, :'c1', :'prov'));
SELECT t.expect_denied('an entity in another namespace',
  format($$INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
           VALUES (%L, 'person', 'planted', %L)$$, :'c2', :'prov'));
SELECT t.expect_denied('an entity in the tower above it',
  format($$INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
           VALUES (%L, 'person', 'planted', %L)$$, :'ta', :'prov'));
SELECT t.expect_denied('an entity under another key''s provenance',
  format($$INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
           VALUES (%L, 'person', 'borrowed', %L)$$, :'c1', :'c1b_prov'));
SELECT t.expect_denied('an entity under another namespace''s provenance',
  format($$INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
           VALUES (%L, 'person', 'borrowed', %L)$$, :'c1', :'ta_prov'));
SELECT t.expect_denied('an agent labelling its own claim as extracted',
  format($$INSERT INTO memory.entities (namespace_id, type, name, origin, provenance_id)
           VALUES (%L, 'person', 'fake extract', 'extracted', %L)$$, :'c1', :'prov'));
SELECT t.expect_denied('an entity that starts out retracted',
  format($$INSERT INTO memory.entities (namespace_id, type, name, status, provenance_id)
           VALUES (%L, 'person', 'born dead', 'retracted', %L)$$, :'c1', :'prov'));
SELECT t.expect_denied('a type outside the allowed shape',
  format($$INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
           VALUES (%L, 'Robert''); DROP', 'x', %L)$$, :'c1', :'prov'));
SELECT t.expect_denied('a relation to a sibling cell''s entity',
  format($$INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id, provenance_id)
           VALUES (%L, %L, 'knows', %L, %L)$$, :'c1', :'e_bot', :'c2_ent', :'prov'));
SELECT t.expect_denied('a relation whose evidence is a sibling cell''s memory',
  format($$INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id,
             evidence_memory_id, provenance_id)
           VALUES (%L, %L, 'uses', %L, %L, %L)$$, :'c1', :'e_bot', :'ta_ent', :'c2_mem', :'prov'));
SELECT t.expect_denied('the same active relation twice',
  format($$INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id, provenance_id)
           VALUES (%L, %L, 'works_on', %L, %L)$$, :'c1', :'e_bot', :'e_proj', :'prov'));
SELECT t.expect_denied('a relation from an entity to itself',
  format($$INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id, provenance_id)
           VALUES (%L, %L, 'is', %L, %L)$$, :'c1', :'e_bot', :'e_bot', :'prov'));
COMMIT;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT memory.record_provenance('link', 'rest') AS prov \gset
SELECT t.expect_rows('a cell aliases a tower entity',
  format($$INSERT INTO memory.entity_aliases (entity_id, namespace_id, alias, provenance_id)
           VALUES (%L, %L, 'The workflow', %L)$$, :'ta_ent', :'c1', :'prov'), 1);
COMMIT;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
SELECT memory.record_provenance('link', 'rest') AS prov2 \gset
SELECT t.expect_rows('a sibling can give the tower entity the same alias without learning of the first',
  format($$INSERT INTO memory.entity_aliases (entity_id, namespace_id, alias, provenance_id)
           VALUES (%L, %L, 'the  workflow', %L)$$, :'ta_ent', :'c2', :'prov2'), 1);
ROLLBACK;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT memory.record_provenance('link', 'rest') AS prov \gset
SELECT t.expect_denied('an alias on a sibling cell''s entity',
  format($$INSERT INTO memory.entity_aliases (entity_id, namespace_id, alias, provenance_id)
           VALUES (%L, %L, 'nickname', %L)$$, :'c2_ent', :'c1', :'prov'));
SELECT t.expect_denied('a mention on a tower memory',
  format($$INSERT INTO memory.entity_mentions (memory_id, entity_id, namespace_id, provenance_id)
           VALUES (%L, %L, %L, %L)$$, :'ta_mem', :'e_bot', :'c1', :'prov'));
SELECT t.expect_denied('a mention of a sibling cell''s entity',
  format($$INSERT INTO memory.entity_mentions (memory_id, entity_id, namespace_id, provenance_id)
           VALUES (%L, %L, %L, %L)$$, :'c1_mem', :'c2_ent', :'c1', :'prov'));
SELECT t.expect_denied('a link to a sibling cell''s memory',
  format($$INSERT INTO memory.memory_links (namespace_id, from_memory_id, kind, to_memory_id, provenance_id)
           VALUES (%L, %L, 'contradicts', %L, %L)$$, :'c1', :'c1_mem', :'c2_mem', :'prov'));
SELECT t.expect_denied('a link that starts at a tower memory',
  format($$INSERT INTO memory.memory_links (namespace_id, from_memory_id, kind, to_memory_id, provenance_id)
           VALUES (%L, %L, 'supports', %L, %L)$$, :'c1', :'ta_mem', :'c1_mem', :'prov'));
SELECT t.expect_denied('renaming an entity',
  format($$UPDATE memory.entities SET name = 'renamed' WHERE id = %L$$, :'e_bot'));
SELECT t.expect_denied('moving a relation''s target',
  $$UPDATE memory.relations SET target_entity_id = source_entity_id WHERE predicate = 'works_on'$$);
SELECT t.expect_denied('retracting a tower entity',
  format($$UPDATE memory.entities SET status = 'retracted' WHERE id = %L$$, :'ta_ent'), true);
SELECT t.expect_denied('deleting a relation', 'DELETE FROM memory.relations');
SELECT t.expect_denied('deleting an entity', 'DELETE FROM memory.entities');
SELECT t.expect_denied('deleting a mention', 'DELETE FROM memory.entity_mentions');
SELECT t.expect_denied('deleting a memory link', 'DELETE FROM memory.memory_links');
ROLLBACK;

BEGIN; SELECT t.as_key(:'k_c1ro', :'c1');
SELECT t.expect_denied('a read-only key cannot record provenance',
  $$SELECT memory.record_provenance('link', 'rest')$$);
SELECT t.expect_denied('a read-only key cannot write an entity, even with a valid provenance id',
  format($$INSERT INTO memory.entities (namespace_id, type, name, provenance_id)
           VALUES (%L, 'person', 'ro', %L)$$, :'c1', :'c1b_prov'));
SELECT t.expect_denied('a read-only key cannot retract a relation',
  $$UPDATE memory.relations SET status = 'retracted'$$, true);
ROLLBACK;

BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT memory.record_provenance('extract', 'job') AS job_prov \gset
SELECT t.expect_rows('the job transport may label rows as extracted',
  format($$INSERT INTO memory.entities (namespace_id, type, name, origin, provenance_id)
           VALUES (%L, 'person', 'Extracted person', 'extracted', %L)$$, :'c1', :'job_prov'), 1);
ROLLBACK;
RESET ROLE;

\echo '-- who can read what'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT t.expect_count('a cell sees its own entities and the tower''s',
  'SELECT 1 FROM memory.entities', 3);
SELECT t.expect_count('a cell sees its relations, aliases, mentions and links',
  $$SELECT 1 FROM memory.relations UNION ALL SELECT 1 FROM memory.entity_aliases
    UNION ALL SELECT 1 FROM memory.entity_mentions UNION ALL SELECT 1 FROM memory.memory_links$$, 7);
SELECT t.expect_count('a cell never sees a sibling cell''s entity',
  format($$SELECT 1 FROM memory.entities WHERE id = %L$$, :'c2_ent'), 0);
ROLLBACK;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
SELECT t.expect_count('a sibling cell sees none of cell 1''s graph',
  $$SELECT 1 FROM memory.entities WHERE namespace_id = '00000000-0000-7000-8000-000000000111'
    UNION ALL SELECT 1 FROM memory.relations UNION ALL SELECT 1 FROM memory.entity_aliases
    UNION ALL SELECT 1 FROM memory.entity_mentions UNION ALL SELECT 1 FROM memory.memory_links$$, 0);
ROLLBACK;
BEGIN; SELECT t.as_key(:'k_ta', :'ta');
SELECT t.expect_count('the tower sees none of its cells'' graph, even rows that point at it',
  $$SELECT 1 FROM memory.entities WHERE namespace_id <> '00000000-0000-7000-8000-000000000011'
    UNION ALL SELECT 1 FROM memory.relations UNION ALL SELECT 1 FROM memory.entity_mentions
    UNION ALL SELECT 1 FROM memory.memory_links$$, 0);
ROLLBACK;
BEGIN;
SELECT t.expect_count('no key sees no graph',
  $$SELECT 1 FROM memory.entities UNION ALL SELECT 1 FROM memory.relations$$, 0);
ROLLBACK;
RESET ROLE;
SET ROLE engramport_admin;
SELECT t.expect_denied('the admin role cannot read entities', 'SELECT 1 FROM memory.entities');
SELECT t.expect_denied('the admin role cannot read relations', 'SELECT 1 FROM memory.relations');
RESET ROLE;
SET ROLE anon;
SELECT t.expect_denied('anon cannot read entities', 'SELECT 1 FROM memory.entities');
RESET ROLE;

\echo '-- retracting is final'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT t.expect_rows('a cell retracts its own relation',
  $$UPDATE memory.relations SET status = 'retracted' WHERE predicate = 'works_on'$$, 1);
SELECT t.expect_denied('a retracted relation cannot be restored',
  $$UPDATE memory.relations SET status = 'active' WHERE predicate = 'works_on'$$);
SELECT memory.record_provenance('link', 'rest') AS prov \gset
SELECT t.expect_rows('the same relation can be asserted again after a retraction',
  format($$INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id, provenance_id)
           VALUES (%L, %L, 'works_on', %L, %L)$$, :'c1', :'e_bot', :'e_proj', :'prov'), 1);
SELECT t.expect_rows('a cell retracts its own entity',
  format($$UPDATE memory.entities SET status = 'retracted' WHERE id = %L$$, :'e_proj'), 1);
SELECT t.expect_denied('a retracted entity takes no new relations',
  format($$INSERT INTO memory.relations (namespace_id, source_entity_id, predicate, target_entity_id, provenance_id)
           VALUES (%L, %L, 'owns', %L, %L)$$, :'c1', :'e_bot', :'e_proj', :'prov'));
COMMIT;
RESET ROLE;
SELECT t.expect_denied('even the owner cannot restore a retracted entity',
  format($$UPDATE memory.entities SET status = 'active' WHERE id = %L$$, :'e_proj'));
SELECT t.expect_denied('even the owner cannot rename an entity',
  format($$UPDATE memory.entities SET name = 'renamed' WHERE id = %L$$, :'e_bot'));

\echo 'all graph tests passed'
