-- Tests for 0011_embedding_models. Run by db/test/run.sh after search_test.sql,
-- on the rls_test fixtures: cell 1 embeds with 'test', cell 2 with 'test2',
-- cell 3 with 'test-model' (all 1536), set up by those tests.
\set ON_ERROR_STOP on
\set QUIET on
\set city '00000000-0000-7000-8000-000000000001'
\set ta   '00000000-0000-7000-8000-000000000011'
\set tb   '00000000-0000-7000-8000-000000000012'
\set c1   '00000000-0000-7000-8000-000000000111'
\set c2   '00000000-0000-7000-8000-000000000112'
\set c3   '00000000-0000-7000-8000-000000000121'
\set k_c1 '00000000-0000-7000-8000-0000000000f1'
\set k_c2 '00000000-0000-7000-8000-0000000000f2'
\set k_tb '00000000-0000-7000-8000-0000000000b0'

\echo '-- defaults and the model list'
SELECT t.expect_count('gte-small and OpenAI are the known models',
  $$SELECT 1 FROM memory.embedding_models WHERE (model, dimension, stays_in_supabase) IN
    (('gte-small', 384, true), ('text-embedding-3-small', 1536, false))$$, 2);
SELECT t.expect_count('a new namespace defaults to Supabase''s built-in model',
  $$SELECT 1 FROM memory.namespaces WHERE id = '00000000-0000-7000-8000-000000000012' AND embedding_model = 'gte-small'$$, 1);
SELECT t.expect_denied('a namespace cannot name an unknown model',
  format($$UPDATE memory.namespaces SET embedding_model = 'made-up' WHERE id = %L$$, :'c1'));
SELECT t.expect_denied('an embedding cannot be of an unknown size',
  $$INSERT INTO memory.embedding_models VALUES ('odd', 768, true, 'x')$$);

-- Tower b embeds with gte-small; cell 1 is switched to none for one test.
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_tb', :'tb');
  SELECT memory.remember('fact', 'dimension check small vector', 'remember', 'rest') AS tb_mem \gset
COMMIT;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('fact', 'dimension check cell one', 'remember', 'rest') AS c1_mem \gset
COMMIT;

\echo '-- the namespace''s own model, at its own size, and nothing else'
BEGIN; SELECT t.as_key(:'k_tb', :'tb');
SELECT t.expect_count('the current model is the namespace''s', $$SELECT 1 WHERE memory.current_embedding_model() = 'gte-small'$$, 1);
INSERT INTO memory.memory_embeddings (memory_id, namespace_id, model, dimension, embedding)
  VALUES (:'tb_mem', :'tb', 'gte-small', 384,
          ('[' || array_to_string(array_fill(0.05::real, ARRAY[384]), ',') || ']')::extensions.halfvec);
SELECT t.expect_count('a gte-small namespace stores a 384 vector', 'SELECT 1 FROM memory.memory_embeddings WHERE dimension = 384', 1);
SELECT t.expect_denied('but not an OpenAI one',
  format($$INSERT INTO memory.memory_embeddings (memory_id, namespace_id, model, dimension, embedding)
           VALUES (%L, %L, 'text-embedding-3-small', 1536,
                   ('[' || array_to_string(array_fill(0.05::real, ARRAY[1536]), ',') || ']')::extensions.halfvec)$$, :'tb_mem', :'tb'));
SELECT t.expect_denied('nor a vector whose size is not its model''s',
  format($$INSERT INTO memory.memory_embeddings (memory_id, namespace_id, model, dimension, embedding)
           VALUES (%L, %L, 'gte-small', 1536,
                   ('[' || array_to_string(array_fill(0.05::real, ARRAY[1536]), ',') || ']')::extensions.halfvec)$$, :'tb_mem', :'tb'));
SELECT t.expect_denied('nor a vector that does not match its stated size',
  format($$INSERT INTO memory.memory_embeddings (memory_id, namespace_id, model, dimension, embedding)
           VALUES (%L, %L, 'gte-small', 384,
                   ('[' || array_to_string(array_fill(0.05::real, ARRAY[1536]), ',') || ']')::extensions.halfvec)$$, :'tb_mem', :'tb'));
SELECT t.expect_count('vector search at 384 finds it',
  format($$SELECT 1 FROM memory.vector_search(('[' || array_to_string(array_fill(0.05::real, ARRAY[384]), ',') || ']')::extensions.halfvec,
             'gte-small') WHERE memory_id = %L AND score > 0.99$$, :'tb_mem'), 1);
SELECT t.expect_count('hybrid search at 384 finds it by meaning',
  format($$SELECT 1 FROM memory.search('unrelated words', ('[' || array_to_string(array_fill(0.05::real, ARRAY[384]), ',') || ']')::extensions.halfvec,
             'gte-small', p_retrievers => ARRAY['vector']) WHERE memory_id = %L AND vector_rank = 1$$, :'tb_mem'), 1);
SELECT t.expect_count('a 1536 query never meets a 384 vector',
  $$SELECT 1 FROM memory.vector_search(('[' || array_to_string(array_fill(0.05::real, ARRAY[1536]), ',') || ']')::extensions.halfvec,
      'gte-small')$$, 0);
COMMIT;

\echo '-- a namespace with no model stores no embeddings'
RESET ROLE;
UPDATE memory.namespaces SET embedding_model = NULL WHERE id = :'c1';
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT t.expect_denied('no embedding at all',
  format($$INSERT INTO memory.memory_embeddings (memory_id, namespace_id, model, dimension, embedding)
           VALUES (%L, %L, 'test', 1536,
                   ('[' || array_to_string(array_fill(0.05::real, ARRAY[1536]), ',') || ']')::extensions.halfvec)$$, :'c1_mem', :'c1'));
SELECT t.expect_denied('the app role cannot turn its own embeddings back on',
  format($$UPDATE memory.namespaces SET embedding_model = 'test' WHERE id = %L$$, :'c1'));
ROLLBACK;
RESET ROLE;
UPDATE memory.namespaces SET embedding_model = 'test' WHERE id = :'c1';

\echo '-- who may change a namespace''s model'
SET ROLE engramport_admin;
UPDATE memory.namespaces SET embedding_model = 'text-embedding-3-small' WHERE id = :'c2';
SELECT t.expect_count('the admin role can change a namespace''s model',
  format($$SELECT 1 FROM memory.namespaces WHERE id = %L AND embedding_model = 'text-embedding-3-small'$$, :'c2'), 1);
SELECT t.expect_denied('and nothing else about it',
  format($$UPDATE memory.namespaces SET slug = 'renamed' WHERE id = %L$$, :'c2'));
SELECT t.expect_denied('the admin role still cannot read embeddings', 'SELECT 1 FROM memory.memory_embeddings');
RESET ROLE;
UPDATE memory.namespaces SET embedding_model = 'test2' WHERE id = :'c2';

\echo '-- Supabase''s API roles'
SET ROLE anon;
SELECT t.expect_denied('anon cannot read the model list', 'SELECT 1 FROM memory.embedding_models');
RESET ROLE;
SET ROLE authenticated;
SELECT t.expect_denied('authenticated cannot read the model list', 'SELECT 1 FROM memory.embedding_models');
RESET ROLE;
