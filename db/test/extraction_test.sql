-- Tests for 0007_extraction. Run by db/test/run.sh after audit_test.sql, which
-- leaves the helpers in schema t and memories written in cells 1 and 2.
\set ON_ERROR_STOP on
\set QUIET on
\set c1   '00000000-0000-7000-8000-000000000111'
\set c2   '00000000-0000-7000-8000-000000000112'
\set ta   '00000000-0000-7000-8000-000000000011'
\set k_ta '00000000-0000-7000-8000-0000000000a0'
\set k_c1 '00000000-0000-7000-8000-0000000000f1'
\set k_c1b '00000000-0000-7000-8000-0000000000f4'
\set k_c1ro '00000000-0000-7000-8000-0000000000e1'
\set k_c2 '00000000-0000-7000-8000-0000000000f2'

\echo '-- shape'
SELECT t.expect_count('extraction runs have row security on and forced',
  $$SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'memory' AND c.relname = 'extraction_runs'
      AND c.relrowsecurity AND c.relforcerowsecurity$$, 1);
SELECT t.expect_count('trigram indexes cover entity names and aliases',
  $$SELECT 1 FROM pg_indexes WHERE schemaname = 'memory'
    AND indexname IN ('entities_norm_trgm', 'entity_aliases_norm_trgm')$$, 2);
SELECT t.expect_count('pg_trgm lives in the extensions schema',
  $$SELECT 1 FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
    WHERE e.extname = 'pg_trgm' AND n.nspname = 'extensions'$$, 1);
SELECT t.expect_count('a run has no column for memory text',
  $$SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'memory' AND table_name = 'extraction_runs'
      AND column_name NOT IN ('id', 'namespace_id', 'memory_id', 'extractor', 'status', 'entities_found',
        'relations_found', 'error_class', 'provenance_id', 'created_at')$$, 0);

SELECT id AS c1_mem FROM memory.memories WHERE content = 'cell 1 secret' \gset
SELECT id AS c2_mem FROM memory.memories WHERE content = 'cell 2 graph secret' \gset
SELECT id AS ta_mem FROM memory.memories WHERE content = 'tower graph lesson' \gset

\echo '-- who may record a run'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT memory.record_provenance('extract', 'job') AS job_prov \gset
SELECT memory.record_provenance('link', 'rest') AS rest_prov \gset
SELECT t.expect_rows('the job records a finished run on its own memory',
  format($$INSERT INTO memory.extraction_runs (namespace_id, memory_id, extractor, status,
             entities_found, relations_found, provenance_id)
           VALUES (%L, %L, 'test/v1', 'done', 2, 1, %L)$$, :'c1', :'c1_mem', :'job_prov'), 1);
SELECT t.expect_rows('and a failed one for another extractor',
  format($$INSERT INTO memory.extraction_runs (namespace_id, memory_id, extractor, status, error_class, provenance_id)
           VALUES (%L, %L, 'test/v2', 'failed', 'timeout', %L)$$, :'c1', :'c1_mem', :'job_prov'), 1);
SELECT t.expect_denied('a memory is finished only once per extractor',
  format($$INSERT INTO memory.extraction_runs (namespace_id, memory_id, extractor, status, provenance_id)
           VALUES (%L, %L, 'test/v1', 'done', %L)$$, :'c1', :'c1_mem', :'job_prov'));
SELECT t.expect_denied('an agent transport cannot record a run',
  format($$INSERT INTO memory.extraction_runs (namespace_id, memory_id, extractor, status, provenance_id)
           VALUES (%L, %L, 'test/v3', 'done', %L)$$, :'c1', :'c1_mem', :'rest_prov'));
SELECT t.expect_denied('a run cannot sit on a tower memory the cell only reads',
  format($$INSERT INTO memory.extraction_runs (namespace_id, memory_id, extractor, status, provenance_id)
           VALUES (%L, %L, 'test/v3', 'done', %L)$$, :'c1', :'ta_mem', :'job_prov'));
SELECT t.expect_denied('a run cannot sit on a sibling cell''s memory',
  format($$INSERT INTO memory.extraction_runs (namespace_id, memory_id, extractor, status, provenance_id)
           VALUES (%L, %L, 'test/v3', 'done', %L)$$, :'c1', :'c2_mem', :'job_prov'));
SELECT t.expect_denied('a run cannot be filed in another namespace',
  format($$INSERT INTO memory.extraction_runs (namespace_id, memory_id, extractor, status, provenance_id)
           VALUES (%L, %L, 'test/v3', 'done', %L)$$, :'c2', :'c1_mem', :'job_prov'));
SELECT t.expect_denied('a failed run needs an error class',
  format($$INSERT INTO memory.extraction_runs (namespace_id, memory_id, extractor, status, provenance_id)
           VALUES (%L, %L, 'test/v3', 'failed', %L)$$, :'c1', :'c1_mem', :'job_prov'));
SELECT t.expect_denied('a finished run has no error class',
  format($$INSERT INTO memory.extraction_runs (namespace_id, memory_id, extractor, status, error_class, provenance_id)
           VALUES (%L, %L, 'test/v3', 'done', 'timeout', %L)$$, :'c1', :'c1_mem', :'job_prov'));
SELECT t.expect_denied('an error class is a short word, never a provider message',
  format($$INSERT INTO memory.extraction_runs (namespace_id, memory_id, extractor, status, error_class, provenance_id)
           VALUES (%L, %L, 'test/v3', 'failed', 'Model said: cell 1 secret', %L)$$, :'c1', :'c1_mem', :'job_prov'));
SELECT t.expect_denied('an extractor name is a short slug',
  format($$INSERT INTO memory.extraction_runs (namespace_id, memory_id, extractor, status, provenance_id)
           VALUES (%L, %L, 'Bad Name!', 'done', %L)$$, :'c1', :'c1_mem', :'job_prov'));
SELECT t.expect_denied('a run is never changed',
  $$UPDATE memory.extraction_runs SET entities_found = 9$$);
SELECT t.expect_denied('a run is never deleted',
  $$DELETE FROM memory.extraction_runs$$);
COMMIT;

BEGIN; SELECT t.as_key(:'k_c1b', :'c1');
SELECT memory.record_provenance('extract', 'job') AS other_prov \gset
COMMIT;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT t.expect_denied('a key cannot file a run under another key''s provenance',
  format($$INSERT INTO memory.extraction_runs (namespace_id, memory_id, extractor, status, provenance_id)
           VALUES (%L, %L, 'test/v3', 'done', %L)$$, :'c1', :'c1_mem', :'other_prov'));
ROLLBACK;

BEGIN; SELECT t.as_key(:'k_c1ro', :'c1');
SELECT t.expect_denied('a read-only key cannot record a run',
  format($$INSERT INTO memory.extraction_runs (namespace_id, memory_id, extractor, status, provenance_id)
           VALUES (%L, %L, 'test/v3', 'done', %L)$$, :'c1', :'c1_mem', :'job_prov'));
ROLLBACK;

SELECT t.expect_denied('not even the owner can change a run',
  $$UPDATE memory.extraction_runs SET entities_found = 9$$);
SELECT t.expect_denied('or delete one',
  $$DELETE FROM memory.extraction_runs$$);

\echo '-- who may read runs'
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT t.expect_count('a cell reads its own runs', 'SELECT 1 FROM memory.extraction_runs', 2);
ROLLBACK;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
SELECT t.expect_count('a sibling cell reads none of them', 'SELECT 1 FROM memory.extraction_runs', 0);
ROLLBACK;
BEGIN; SELECT t.as_key(:'k_ta', :'ta');
SELECT t.expect_count('the tower reads none of its cells'' runs', 'SELECT 1 FROM memory.extraction_runs', 0);
ROLLBACK;
BEGIN;
SELECT t.expect_count('no key reads no runs', 'SELECT 1 FROM memory.extraction_runs', 0);
ROLLBACK;
RESET ROLE;

\echo '-- trigram matching'
SELECT t.expect_count('a near spelling scores above the match threshold',
  $$SELECT 1 WHERE extensions.similarity(memory.norm_key('Grok Bots'), memory.norm_key('Grok Bot')) >= 0.6$$, 1);
SELECT t.expect_count('an unrelated name does not',
  $$SELECT 1 WHERE extensions.similarity(memory.norm_key('Listing workflow'), memory.norm_key('Grok Bot')) >= 0.6$$, 0);

\echo '-- the admin and API roles'
SET ROLE engramport_admin;
SELECT t.expect_denied('the admin role cannot read extraction runs', 'SELECT * FROM memory.extraction_runs');
RESET ROLE;
SELECT t.expect_count('no API role can touch extraction runs',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) r
    WHERE has_table_privilege(r, 'memory.extraction_runs', 'SELECT, INSERT, UPDATE, DELETE')$$, 0);
SELECT t.expect_count('no API role can run the final trigger',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) r
    WHERE has_function_privilege(r, 'memory.extraction_runs_final()', 'EXECUTE')$$, 0);

\echo 'all extraction tests passed'
