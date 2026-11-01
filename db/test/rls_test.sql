-- Row security tests for 0001_memory_core. Run by db/test/run.sh as a
-- superuser on a throwaway database. Every cross-namespace and cell-to-cell
-- attempt must fail or see nothing; the script stops at the first surprise.
\set ON_ERROR_STOP on
\set QUIET on

-- Helpers, run as the caller (SECURITY INVOKER), so they test the app role.
CREATE SCHEMA t;
GRANT USAGE ON SCHEMA t TO engramport_app, anon, authenticated, service_role;

CREATE FUNCTION t.as_key(p_key uuid, p_ns uuid) RETURNS void LANGUAGE sql AS $$
  SELECT set_config('app.api_key_id', coalesce(p_key::text, ''), true),
         set_config('app.namespace_id', coalesce(p_ns::text, ''), true);
$$;

CREATE FUNCTION t.count_of(p_sql text) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE n bigint;
BEGIN
  EXECUTE format('SELECT count(*) FROM (%s) q', p_sql) INTO n;
  RETURN n;
END $$;

CREATE FUNCTION t.expect_count(p_name text, p_sql text, p_want bigint) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE got bigint := t.count_of(p_sql);
BEGIN
  IF got <> p_want THEN
    RAISE EXCEPTION 'FAIL %: wanted % rows, got %', p_name, p_want, got;
  END IF;
  RAISE NOTICE 'pass %', p_name;
END $$;

-- The statement must raise. A statement that runs, even touching 0 rows, fails
-- the test unless p_zero_ok says a silent no-op is the expected denial.
CREATE FUNCTION t.expect_denied(p_name text, p_sql text, p_zero_ok boolean DEFAULT false)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE n bigint;
BEGIN
  BEGIN
    EXECUTE p_sql;
    GET DIAGNOSTICS n = ROW_COUNT;
  EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'pass % (%)', p_name, SQLSTATE;
    RETURN;
  END;
  IF p_zero_ok AND n = 0 THEN
    RAISE NOTICE 'pass % (no rows touched)', p_name;
    RETURN;
  END IF;
  RAISE EXCEPTION 'FAIL %: statement succeeded and touched % rows', p_name, n;
END $$;

GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA t TO engramport_app, anon, authenticated, service_role;

-- Fixtures, as the owner. city > tower 1 > cells 1, 2; city > tower 2 > cell 3.
INSERT INTO memory.namespaces (id, parent_id, level, slug) VALUES
  ('00000000-0000-7000-8000-000000000001', NULL, 'city', 'testcity'),
  ('00000000-0000-7000-8000-000000000011', '00000000-0000-7000-8000-000000000001', 'tower', 'tower-a'),
  ('00000000-0000-7000-8000-000000000012', '00000000-0000-7000-8000-000000000001', 'tower', 'tower-b'),
  ('00000000-0000-7000-8000-000000000111', '00000000-0000-7000-8000-000000000011', 'cell', 'cell-1'),
  ('00000000-0000-7000-8000-000000000112', '00000000-0000-7000-8000-000000000011', 'cell', 'cell-2'),
  ('00000000-0000-7000-8000-000000000121', '00000000-0000-7000-8000-000000000012', 'cell', 'cell-3');

INSERT INTO memory.actors (id, kind, slug, display_name) VALUES
  ('00000000-0000-7000-8000-00000000a001', 'agent', 'claude', 'Claude'),
  ('00000000-0000-7000-8000-00000000a002', 'agent', 'grok-bot', 'Grok Bot'),
  ('00000000-0000-7000-8000-00000000a003', 'agent', 'retired-bot', 'Retired');
UPDATE memory.actors SET disabled_at = now() WHERE slug = 'retired-bot';

-- key ids end in a short code: c0 city, a0 tower a, b0 tower b, 1/2/3 cells.
INSERT INTO memory.api_keys (id, namespace_id, actor_id, prefix, key_hash, scopes, expires_at, revoked_at) VALUES
  ('00000000-0000-7000-8000-0000000000c0', '00000000-0000-7000-8000-000000000001', '00000000-0000-7000-8000-00000000a001', 'ek_city0000', sha256('city'), '{read,write}', NULL, NULL),
  ('00000000-0000-7000-8000-0000000000a0', '00000000-0000-7000-8000-000000000011', '00000000-0000-7000-8000-00000000a001', 'ek_towera00', sha256('tower-a'), '{read,write}', NULL, NULL),
  ('00000000-0000-7000-8000-0000000000b0', '00000000-0000-7000-8000-000000000012', '00000000-0000-7000-8000-00000000a001', 'ek_towerb00', sha256('tower-b'), '{read,write}', NULL, NULL),
  ('00000000-0000-7000-8000-0000000000f1', '00000000-0000-7000-8000-000000000111', '00000000-0000-7000-8000-00000000a001', 'ek_cell1000', sha256('cell-1'), '{read,write}', NULL, NULL),
  ('00000000-0000-7000-8000-0000000000f2', '00000000-0000-7000-8000-000000000112', '00000000-0000-7000-8000-00000000a002', 'ek_cell2000', sha256('cell-2'), '{read,write}', NULL, NULL),
  ('00000000-0000-7000-8000-0000000000f3', '00000000-0000-7000-8000-000000000121', '00000000-0000-7000-8000-00000000a002', 'ek_cell3000', sha256('cell-3'), '{read,write}', NULL, NULL),
  ('00000000-0000-7000-8000-0000000000e1', '00000000-0000-7000-8000-000000000111', '00000000-0000-7000-8000-00000000a002', 'ek_cell1ro0', sha256('cell-1-ro'), '{read}', NULL, NULL),
  ('00000000-0000-7000-8000-0000000000f4', '00000000-0000-7000-8000-000000000111', '00000000-0000-7000-8000-00000000a002', 'ek_cell1b00', sha256('cell-1-b'), '{read,write}', NULL, NULL),
  ('00000000-0000-7000-8000-0000000000d1', '00000000-0000-7000-8000-000000000111', '00000000-0000-7000-8000-00000000a001', 'ek_cell1rv0', sha256('cell-1-rv'), '{read,write}', NULL, now()),
  ('00000000-0000-7000-8000-0000000000d2', '00000000-0000-7000-8000-000000000111', '00000000-0000-7000-8000-00000000a001', 'ek_cell1ex0', sha256('cell-1-ex'), '{read,write}', now() - interval '1 minute', NULL),
  ('00000000-0000-7000-8000-0000000000d3', '00000000-0000-7000-8000-000000000111', '00000000-0000-7000-8000-00000000a003', 'ek_cell1da0', sha256('cell-1-da'), '{read,write}', NULL, NULL);

\set city '00000000-0000-7000-8000-000000000001'
\set ta   '00000000-0000-7000-8000-000000000011'
\set tb   '00000000-0000-7000-8000-000000000012'
\set c1   '00000000-0000-7000-8000-000000000111'
\set c2   '00000000-0000-7000-8000-000000000112'
\set c3   '00000000-0000-7000-8000-000000000121'

-- One memory per namespace, written through the app role and remember().
SET ROLE engramport_app;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000c0', :'city');
  SELECT memory.remember('principle', 'city lesson', 'remember', 'rest') IS NOT NULL; COMMIT;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000a0', :'ta');
  SELECT memory.remember('insight', 'tower a lesson', 'remember', 'rest') IS NOT NULL; COMMIT;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000b0', :'tb');
  SELECT memory.remember('insight', 'tower b lesson', 'remember', 'rest') IS NOT NULL; COMMIT;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000f1', :'c1');
  SELECT memory.remember('fact', 'cell 1 secret', 'remember', 'streamable_http',
    p_client_name => 'claude-ai', p_claimed => '{"subagent":"x"}') IS NOT NULL; COMMIT;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000f2', :'c2');
  SELECT memory.remember('fact', 'cell 2 secret', 'remember', 'rest') IS NOT NULL; COMMIT;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000f3', :'c3');
  SELECT memory.remember('fact', 'cell 3 secret', 'remember', 'rest') IS NOT NULL; COMMIT;
RESET ROLE;

-- Ids of other namespaces' memories, for direct attempts below.
SELECT id AS c2_mem FROM memory.memories WHERE content = 'cell 2 secret' \gset
SELECT id AS c1_mem FROM memory.memories WHERE content = 'cell 1 secret' \gset
SELECT id AS ta_prov FROM memory.provenance WHERE namespace_id = :'ta' \gset

\echo '-- schema shape'
SELECT t.expect_count('every memory table has row security on and forced',
  $$SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'memory' AND c.relkind = 'r' AND c.relrowsecurity AND c.relforcerowsecurity$$, 6);
SELECT t.expect_count('the app role cannot bypass row security',
  $$SELECT 1 FROM pg_roles WHERE rolname = 'engramport_app' AND NOT rolbypassrls AND NOT rolsuper$$, 1);
SELECT t.expect_denied('a cell cannot sit under a city',
  format($$INSERT INTO memory.namespaces (parent_id, level, slug) VALUES (%L, 'cell', 'bad')$$, :'city'));
SELECT t.expect_denied('a namespace cannot be moved',
  format($$UPDATE memory.namespaces SET parent_id = %L WHERE id = %L$$, :'tb', :'c1'));
SELECT t.expect_count('paths are derived from the tree',
  $$SELECT 1 FROM memory.namespaces WHERE path = 'testcity/tower-a/cell-1'$$, 1);

\echo '-- no key, wrong key'
SET ROLE engramport_app;
BEGIN;
SELECT t.expect_count('no key sees no memories', 'SELECT 1 FROM memory.memories', 0);
SELECT t.expect_count('no key sees no namespaces', 'SELECT 1 FROM memory.namespaces', 0);
SELECT t.expect_denied('no key cannot remember', $$SELECT memory.remember('fact', 'x', 'remember', 'rest')$$);
ROLLBACK;

BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000f1', :'c2');
SELECT t.expect_count('cell 1 key claiming cell 2 sees nothing', 'SELECT 1 FROM memory.memories', 0);
SELECT t.expect_denied('cell 1 key claiming cell 2 cannot remember', $$SELECT memory.remember('fact', 'x', 'remember', 'rest')$$);
ROLLBACK;

BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000d1', :'c1');
SELECT t.expect_count('revoked key sees nothing', 'SELECT 1 FROM memory.memories', 0);
ROLLBACK;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000d2', :'c1');
SELECT t.expect_count('expired key sees nothing', 'SELECT 1 FROM memory.memories', 0);
ROLLBACK;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000d3', :'c1');
SELECT t.expect_count('disabled actor''s key sees nothing', 'SELECT 1 FROM memory.memories', 0);
ROLLBACK;

\echo '-- cell 1 reads down the tree only'
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000f1', :'c1');
SELECT t.expect_count('cell 1 sees its own, tower a and city memories',
  $$SELECT 1 FROM memory.memories WHERE content IN ('cell 1 secret', 'tower a lesson', 'city lesson')$$, 3);
SELECT t.expect_count('cell 1 sees nothing else', 'SELECT 1 FROM memory.memories', 3);
SELECT t.expect_count('cell 1 never sees cell 2 (same tower)',
  $$SELECT 1 FROM memory.memories WHERE content = 'cell 2 secret'$$, 0);
SELECT t.expect_count('cell 1 never sees tower b or cell 3',
  $$SELECT 1 FROM memory.memories WHERE content IN ('tower b lesson', 'cell 3 secret')$$, 0);
SELECT t.expect_count('cell 1 sees its namespace and ancestors only', 'SELECT 1 FROM memory.namespaces', 3);
SELECT t.expect_count('full-text search stays inside the same rule',
  $$SELECT 1 FROM memory.memories WHERE fts @@ plainto_tsquery('english', 'secret')$$, 1);
SELECT t.expect_count('provenance: own namespace only, not the tower''s',
  'SELECT 1 FROM memory.provenance', 1);
SELECT t.expect_count('provenance records actor, key and client from the key, claims kept apart',
  $$SELECT 1 FROM memory.provenance WHERE actor_id = '00000000-0000-7000-8000-00000000a001'
    AND api_key_id = '00000000-0000-7000-8000-0000000000f1' AND client_name = 'claude-ai'
    AND claimed = '{"subagent":"x"}' AND content_sha256 = encode(sha256('cell 1 secret'::bytea), 'hex')$$, 1);
SELECT t.expect_count('tower provenance id is invisible to cell 1',
  format('SELECT 1 FROM memory.provenance WHERE id = %L', :'ta_prov'), 0);
ROLLBACK;

\echo '-- cell 1 writes only its own cell'
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000f1', :'c1');
SELECT t.expect_denied('insert provenance into cell 2',
  format($$INSERT INTO memory.provenance (namespace_id, api_key_id, actor_id, tool, transport)
           VALUES (%L, '00000000-0000-7000-8000-0000000000f1', '00000000-0000-7000-8000-00000000a001', 'x', 'rest')$$, :'c2'));
SELECT t.expect_denied('forge provenance with another key',
  format($$INSERT INTO memory.provenance (namespace_id, api_key_id, actor_id, tool, transport)
           VALUES (%L, '00000000-0000-7000-8000-0000000000f2', '00000000-0000-7000-8000-00000000a002', 'x', 'rest')$$, :'c1'));
SELECT t.expect_denied('forge provenance with another actor',
  format($$INSERT INTO memory.provenance (namespace_id, api_key_id, actor_id, tool, transport)
           VALUES (%L, '00000000-0000-7000-8000-0000000000f1', '00000000-0000-7000-8000-00000000a002', 'x', 'rest')$$, :'c1'));
SELECT t.expect_denied('insert a memory into cell 2 using tower a provenance',
  format($$INSERT INTO memory.memories (namespace_id, kind, content, content_sha256, provenance_id)
           VALUES (%L, 'fact', 'x', 'x', %L)$$, :'c2', :'ta_prov'));
SELECT t.expect_denied('insert a memory into tower a',
  format($$INSERT INTO memory.memories (namespace_id, kind, content, content_sha256, provenance_id)
           VALUES (%L, 'fact', 'x', 'x', %L)$$, :'ta', :'ta_prov'));
SELECT t.expect_denied('supersede a cell 2 memory from cell 1',
  format($$UPDATE memory.memories SET supersedes_id = %L WHERE id = %L$$, :'c2_mem', :'c1_mem'));
SELECT t.expect_denied('retract a cell 2 memory', format($$UPDATE memory.memories SET status = 'retracted' WHERE id = %L$$, :'c2_mem'), true);
SELECT t.expect_denied('retract a tower memory',
  $$UPDATE memory.memories SET status = 'retracted' WHERE content = 'tower a lesson'$$, true);
SELECT t.expect_denied('rewrite memory content in place', $$UPDATE memory.memories SET content = 'changed'$$);
SELECT t.expect_denied('delete memories', 'DELETE FROM memory.memories');
SELECT t.expect_denied('delete provenance', 'DELETE FROM memory.provenance');
SELECT t.expect_denied('add a namespace', $$INSERT INTO memory.namespaces (level, slug) VALUES ('city', 'rogue')$$);
SELECT t.expect_denied('read api keys directly', 'SELECT * FROM memory.api_keys');
SELECT t.expect_denied('mint an api key', format($$INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash)
  VALUES (%L, '00000000-0000-7000-8000-00000000a001', 'ek_rogue000', sha256('r'))$$, :'c2'));
SELECT t.expect_count('cell 1 can retract its own memory',
  $$SELECT 1 FROM (SELECT 1 FROM memory.memories WHERE content = 'cell 1 secret') q$$, 1);
UPDATE memory.memories SET status = 'retracted' WHERE content = 'cell 1 secret';
SELECT t.expect_count('the retraction kept the original text',
  $$SELECT 1 FROM memory.memories WHERE content = 'cell 1 secret' AND status = 'retracted'$$, 1);
ROLLBACK;

\echo '-- embeddings'
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000f1', :'c1');
INSERT INTO memory.memory_embeddings (memory_id, namespace_id, model, dimension, embedding)
  VALUES (:'c1_mem', :'c1', 'test', 1536, array_fill(0.1::real, ARRAY[1536])::extensions.halfvec);
SELECT t.expect_count('cell 1 can embed its own memory', 'SELECT 1 FROM memory.memory_embeddings', 1);
SELECT t.expect_denied('embed a cell 2 memory under cell 1',
  format($$INSERT INTO memory.memory_embeddings (memory_id, namespace_id, model, dimension, embedding)
           VALUES (%L, %L, 'test', 1536, array_fill(0.1::real, ARRAY[1536])::extensions.halfvec)$$, :'c2_mem', :'c1'));
SELECT t.expect_denied('embed into cell 2',
  format($$INSERT INTO memory.memory_embeddings (memory_id, namespace_id, model, dimension, embedding)
           VALUES (%L, %L, 'test2', 1536, array_fill(0.1::real, ARRAY[1536])::extensions.halfvec)$$, :'c1_mem', :'c2'));
ROLLBACK;

\echo '-- read-only key, tower key'
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000e1', :'c1');
SELECT t.expect_count('read-only key reads', 'SELECT 1 FROM memory.memories', 3);
SELECT t.expect_denied('read-only key cannot remember', $$SELECT memory.remember('fact', 'x', 'remember', 'rest')$$);
SELECT t.expect_denied('read-only key cannot retract',
  $$UPDATE memory.memories SET status = 'retracted' WHERE content = 'cell 1 secret'$$, true);
ROLLBACK;

BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000a0', :'ta');
SELECT t.expect_count('tower a sees itself and the city, never its cells', 'SELECT 1 FROM memory.memories', 2);
SELECT t.expect_count('tower a sees no cell memory',
  $$SELECT 1 FROM memory.memories WHERE content LIKE 'cell %'$$, 0);
ROLLBACK;

BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000c0', :'city');
SELECT t.expect_count('the city sees only itself', 'SELECT 1 FROM memory.memories', 1);
ROLLBACK;

\echo '-- key lookup'
SELECT t.expect_count('the right hash authenticates',
  $$SELECT 1 FROM memory.authenticate('ek_cell1000', sha256('cell-1'))
    WHERE namespace_id = '00000000-0000-7000-8000-000000000111'$$, 1);
SELECT t.expect_count('a wrong hash does not', $$SELECT 1 FROM memory.authenticate('ek_cell1000', sha256('nope'))$$, 0);
SELECT t.expect_count('another key''s hash does not', $$SELECT 1 FROM memory.authenticate('ek_cell1000', sha256('cell-2'))$$, 0);
SELECT t.expect_count('a revoked key does not', $$SELECT 1 FROM memory.authenticate('ek_cell1rv0', sha256('cell-1-rv'))$$, 0);
SELECT t.expect_count('an expired key does not', $$SELECT 1 FROM memory.authenticate('ek_cell1ex0', sha256('cell-1-ex'))$$, 0);
SELECT t.expect_count('a disabled actor''s key does not', $$SELECT 1 FROM memory.authenticate('ek_cell1da0', sha256('cell-1-da'))$$, 0);
RESET ROLE;

\echo '-- Supabase API roles get nothing'
SET ROLE anon;
SELECT t.expect_denied('anon cannot read memories', 'SELECT 1 FROM memory.memories');
RESET ROLE;
SET ROLE authenticated;
SELECT t.expect_denied('authenticated cannot read memories', 'SELECT 1 FROM memory.memories');
RESET ROLE;
SET ROLE service_role;
SELECT t.expect_denied('service_role cannot read memories, despite bypassing row security', 'SELECT 1 FROM memory.memories');
SELECT t.expect_denied('service_role cannot authenticate keys', $$SELECT * FROM memory.authenticate('ek_cell1000', sha256('cell-1'))$$);
RESET ROLE;

\echo '-- dedup and hashing'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000f1', :'c1');
SELECT memory.remember('fact', 'once', 'remember', 'rest', p_dedup_key => 'k1') IS NOT NULL;
SELECT t.expect_denied('the same dedup key twice in one namespace',
  $$SELECT memory.remember('fact', 'twice', 'remember', 'rest', p_dedup_key => 'k1')$$);
ROLLBACK;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000f1', :'c1');
INSERT INTO memory.provenance (namespace_id, api_key_id, actor_id, tool, transport, content_sha256)
  VALUES (:'c1', '00000000-0000-7000-8000-0000000000f1', '00000000-0000-7000-8000-00000000a001', 'x', 'rest',
          encode(sha256('hash me'::bytea), 'hex'))
  RETURNING id AS p1 \gset
INSERT INTO memory.memories (namespace_id, kind, content, content_sha256, provenance_id)
  VALUES (:'c1', 'fact', 'hash me', 'not-a-real-hash', :'p1');
SELECT t.expect_count('the stored hash is computed, not taken from the caller',
  $$SELECT 1 FROM memory.memories WHERE content = 'hash me' AND content_sha256 = encode(sha256('hash me'::bytea), 'hex')$$, 1);
ROLLBACK;
RESET ROLE;

\echo '-- provenance belongs to one key and one write'
SELECT id AS c1_prov FROM memory.provenance WHERE namespace_id = :'c1' AND api_key_id = '00000000-0000-7000-8000-0000000000f1' \gset
-- An unused provenance row of key 1, so only the key binding can refuse it.
SET ROLE engramport_app;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000f1', :'c1');
INSERT INTO memory.provenance (namespace_id, api_key_id, actor_id, tool, transport, content_sha256)
  VALUES (:'c1', '00000000-0000-7000-8000-0000000000f1', '00000000-0000-7000-8000-00000000a001', 'x', 'rest',
          encode(sha256('borrowed'::bytea), 'hex'))
  RETURNING id AS spare_prov \gset
COMMIT;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000f4', :'c1');
SELECT t.expect_denied('a second key in the same cell borrows the first key''s provenance',
  format($$INSERT INTO memory.memories (namespace_id, kind, content, content_sha256, provenance_id)
           VALUES (%L, 'fact', 'borrowed', 'x', %L)$$, :'c1', :'spare_prov'));
ROLLBACK;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000f1', :'c1');
SELECT t.expect_denied('the same key reuses its own provenance for a second memory',
  format($$INSERT INTO memory.memories (namespace_id, kind, content, content_sha256, provenance_id)
           VALUES (%L, 'fact', 'cell 1 secret', 'x', %L)$$, :'c1', :'c1_prov'));
INSERT INTO memory.provenance (namespace_id, api_key_id, actor_id, tool, transport, content_sha256)
  VALUES (:'c1', '00000000-0000-7000-8000-0000000000f1', '00000000-0000-7000-8000-00000000a001', 'x', 'rest',
          encode(sha256('what was recorded'::bytea), 'hex'))
  RETURNING id AS p2 \gset
SELECT t.expect_denied('a memory whose text differs from what its provenance recorded',
  format($$INSERT INTO memory.memories (namespace_id, kind, content, content_sha256, provenance_id)
           VALUES (%L, 'fact', 'something else', 'x', %L)$$, :'c1', :'p2'));
ROLLBACK;
RESET ROLE;
SELECT t.expect_denied('a write-only key cannot be created',
  format($$INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes)
           VALUES (%L, '00000000-0000-7000-8000-00000000a001', 'ek_writeo00', sha256('w'), '{write}')$$, :'c1'));
SET ROLE engramport_app;
BEGIN; SELECT t.as_key('00000000-0000-7000-8000-0000000000f4', :'c1');
SELECT t.expect_count('a second key in the same cell still writes its own memories',
  $$SELECT 1 WHERE memory.remember('fact', 'from key b', 'remember', 'rest') IS NOT NULL$$, 1);
ROLLBACK;
RESET ROLE;

\echo 'all row security tests passed'
