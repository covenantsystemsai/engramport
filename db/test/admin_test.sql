-- Tests for 0002_admin_role. Run by db/test/run.sh after rls_test.sql, which
-- leaves its helpers in schema t and its fixtures in place.
\set ON_ERROR_STOP on
\set QUIET on
\set c2 '00000000-0000-7000-8000-000000000112'

-- Runs a write and checks how many rows it touched.
CREATE FUNCTION t.expect_rows(p_name text, p_sql text, p_want bigint) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE n bigint;
BEGIN
  EXECUTE p_sql;
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n <> p_want THEN
    RAISE EXCEPTION 'FAIL %: wanted % rows touched, got %', p_name, p_want, n;
  END IF;
  RAISE NOTICE 'pass %', p_name;
END $$;

GRANT USAGE ON SCHEMA t TO engramport_admin;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA t TO engramport_admin;

\echo '-- admin role shape'
SELECT t.expect_count('the admin role cannot log in or bypass row security',
  $$SELECT 1 FROM pg_roles WHERE rolname = 'engramport_admin'
    AND NOT rolcanlogin AND NOT rolbypassrls AND NOT rolsuper AND NOT rolcreaterole$$, 1);
SELECT t.expect_count('no Supabase API role and not the app role can become the admin role',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role', 'engramport_app']) r
    WHERE pg_has_role(r, 'engramport_admin', 'member')$$, 0);
SELECT t.expect_count('nothing in schema memory is executable by PUBLIC',
  $$SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'memory' AND has_function_privilege('public', p.oid, 'EXECUTE')$$, 0);

\echo '-- what the admin role can do'
SET ROLE engramport_admin;
INSERT INTO memory.namespaces (level, slug) VALUES ('city', 'admincity') RETURNING id AS a_city \gset
INSERT INTO memory.namespaces (parent_id, level, slug) VALUES (:'a_city', 'tower', 'admintower') RETURNING id AS a_tower \gset
INSERT INTO memory.namespaces (parent_id, level, slug) VALUES (:'a_tower', 'cell', 'admincell') RETURNING id AS a_cell, path AS a_path \gset
SELECT t.expect_count('the admin role creates a city, tower and cell with derived paths',
  format($$SELECT 1 WHERE %L = 'admincity/admintower/admincell'$$, :'a_path'), 1);
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', 'admin-test-bot', 'Admin test bot')
  RETURNING id AS a_actor \gset
INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes)
  VALUES (:'a_cell', :'a_actor', 'ep_live_admintest01', sha256('admin-test'), '{read,write}')
  RETURNING id AS a_key \gset
SELECT t.expect_count('the admin role lists keys without their hashes',
  $$SELECT prefix, scopes, revoked_at FROM memory.api_keys WHERE prefix = 'ep_live_admintest01'$$, 1);
SELECT t.expect_count('the admin role sees every namespace, not just one subtree',
  $$SELECT 1 FROM memory.namespaces WHERE slug IN ('testcity', 'admincity')$$, 2);
SELECT t.expect_rows('the admin role disables an actor',
  $$UPDATE memory.actors SET disabled_at = now() WHERE slug = 'admin-test-bot'$$, 1);
UPDATE memory.actors SET disabled_at = NULL WHERE slug = 'admin-test-bot';
SELECT t.expect_rows('the admin role shortens a key''s expiry',
  format($$UPDATE memory.api_keys SET expires_at = now() + interval '1 day' WHERE id = %L$$, :'a_key'), 1);

\echo '-- what the admin role cannot do'
SELECT t.expect_denied('the admin role cannot read a key hash',
  'SELECT key_hash FROM memory.api_keys');
SELECT t.expect_denied('the admin role cannot read memories', 'SELECT 1 FROM memory.memories');
SELECT t.expect_denied('the admin role cannot read provenance', 'SELECT 1 FROM memory.provenance');
SELECT t.expect_denied('the admin role cannot read embeddings', 'SELECT 1 FROM memory.memory_embeddings');
SELECT t.expect_denied('the admin role cannot write memories',
  $$SELECT memory.remember('fact', 'from admin', 'remember', 'rest')$$);
SELECT t.expect_denied('the admin role cannot call authenticate',
  $$SELECT * FROM memory.authenticate('ep_live_admintest01', sha256('admin-test'))$$);
SELECT t.expect_denied('the admin role cannot move a key to another namespace',
  format($$UPDATE memory.api_keys SET namespace_id = %L WHERE id = %L$$, :'c2', :'a_key'));
SELECT t.expect_denied('the admin role cannot widen or narrow a key''s scopes',
  format($$UPDATE memory.api_keys SET scopes = '{read}' WHERE id = %L$$, :'a_key'));
SELECT t.expect_denied('the admin role cannot replace a key hash',
  format($$UPDATE memory.api_keys SET key_hash = sha256('other') WHERE id = %L$$, :'a_key'));
SELECT t.expect_denied('the admin role cannot mint a key that is already revoked',
  format($$INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, revoked_at)
           VALUES (%L, %L, 'ep_live_admintest02', sha256('x2'), now())$$, :'a_cell', :'a_actor'));
SELECT t.expect_denied('the admin role cannot mint a write-only key',
  format($$INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes)
           VALUES (%L, %L, 'ep_live_admintest03', sha256('x3'), '{write}')$$, :'a_cell', :'a_actor'));
SELECT t.expect_denied('the admin role cannot delete a key',
  format($$DELETE FROM memory.api_keys WHERE id = %L$$, :'a_key'));
SELECT t.expect_denied('the admin role cannot delete a namespace',
  format($$DELETE FROM memory.namespaces WHERE id = %L$$, :'a_cell'));
SELECT t.expect_denied('the admin role cannot delete an actor',
  format($$DELETE FROM memory.actors WHERE id = %L$$, :'a_actor'));
SELECT t.expect_denied('the admin role cannot rename a namespace',
  format($$UPDATE memory.namespaces SET slug = 'renamed' WHERE id = %L$$, :'a_cell'));

\echo '-- revoking is final'
SELECT t.expect_rows('the admin role revokes a key',
  format($$UPDATE memory.api_keys SET revoked_at = now() WHERE id = %L$$, :'a_key'), 1);
SELECT t.expect_denied('the admin role cannot restore a revoked key',
  format($$UPDATE memory.api_keys SET revoked_at = NULL WHERE id = %L$$, :'a_key'), true);
SELECT t.expect_denied('the admin role cannot re-date a revoked key''s expiry',
  format($$UPDATE memory.api_keys SET expires_at = NULL WHERE id = %L$$, :'a_key'), true);
RESET ROLE;
SELECT t.expect_denied('even the owner cannot restore a revoked key',
  format($$UPDATE memory.api_keys SET revoked_at = NULL WHERE id = %L$$, :'a_key'));
SELECT t.expect_denied('even the owner cannot change a key''s prefix',
  $$UPDATE memory.api_keys SET prefix = 'ek_changed00' WHERE prefix = 'ek_cell1000'$$);
SELECT t.expect_count('last_used_at still updates on an active key',
  $$SELECT 1 FROM memory.authenticate('ek_cell1000', sha256('cell-1'))$$, 1);

\echo '-- the app role is unchanged'
SET ROLE engramport_app;
SELECT t.expect_denied('the app role still cannot read keys', 'SELECT 1 FROM memory.api_keys');
SELECT t.expect_denied('the app role still cannot create namespaces',
  $$INSERT INTO memory.namespaces (level, slug) VALUES ('city', 'appcity')$$);
SELECT t.expect_denied('the app role still cannot create actors',
  $$INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', 'app-bot', 'x')$$);
RESET ROLE;

\echo 'all admin role tests passed'
