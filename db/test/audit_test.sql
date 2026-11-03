-- Tests for 0006_admin_audit. Run by db/test/run.sh after company_test.sql,
-- which leaves the helpers in schema t and memories and graph rows written in
-- client and company namespaces, each with a provenance row.
\set ON_ERROR_STOP on
\set QUIET on
\set c2 '00000000-0000-7000-8000-000000000112'
\set k_c2 '00000000-0000-7000-8000-0000000000f2'

-- One more write with every optional provenance field set, so the denials
-- below are about real values.
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
  SELECT memory.remember('fact', 'audit test secret text', 'remember', 'streamable_http',
    p_client_name => 'claude-ai', p_client_version => '1.0', p_session_id => 'sess-audit',
    p_request_id => 'req-audit', p_source_kind => 'transcript', p_source_ref => 'client-doc-name.pdf',
    p_claimed => '{"subagent":"named-by-agent"}') IS NOT NULL;
COMMIT;
RESET ROLE;

\echo '-- what the admin role sees'
SET ROLE engramport_admin;
SELECT t.expect_count('the admin role reads the audit columns of every write in every namespace',
  $$SELECT id, namespace_id, api_key_id, actor_id, tool, client_name, client_version, transport,
           session_id, request_id, source_kind, log_event_id, created_at
    FROM memory.provenance$$,
  (SELECT count(*) FROM memory.provenance));
SELECT t.expect_count('it sees who, through which client and tool, and when',
  $$SELECT 1 FROM memory.provenance p JOIN memory.actors a ON a.id = p.actor_id
    JOIN memory.namespaces n ON n.id = p.namespace_id
    WHERE p.request_id = 'req-audit' AND a.slug = 'grok-bot' AND p.tool = 'remember'
      AND p.client_name = 'claude-ai' AND n.path = 'testcity/tower-a/cell-2'$$, 1);
SELECT t.expect_count('it sees company writes too',
  $$SELECT 1 FROM memory.provenance p JOIN memory.namespaces n ON n.id = p.namespace_id
    WHERE n.purpose = 'company'$$, 3);

\echo '-- what the admin role still cannot see'
SELECT t.expect_denied('no content hash', 'SELECT content_sha256 FROM memory.provenance');
SELECT t.expect_denied('no agent-claimed fields', 'SELECT claimed FROM memory.provenance');
SELECT t.expect_denied('no source reference, which can name a document', 'SELECT source_ref FROM memory.provenance');
SELECT t.expect_denied('no whole provenance rows', 'SELECT * FROM memory.provenance');
SELECT t.expect_denied('no memories', 'SELECT 1 FROM memory.memories');
SELECT t.expect_denied('no embeddings', 'SELECT 1 FROM memory.memory_embeddings');
SELECT t.expect_denied('no entities', 'SELECT 1 FROM memory.entities');
SELECT t.expect_denied('no relations', 'SELECT 1 FROM memory.relations');
SELECT t.expect_denied('no aliases', 'SELECT 1 FROM memory.entity_aliases');
SELECT t.expect_denied('no mentions', 'SELECT 1 FROM memory.entity_mentions');
SELECT t.expect_denied('no memory links', 'SELECT 1 FROM memory.memory_links');
SELECT t.expect_denied('no writing provenance',
  $$INSERT INTO memory.provenance (namespace_id, api_key_id, actor_id, tool, transport)
    SELECT namespace_id, api_key_id, actor_id, 'forged', 'rest' FROM memory.provenance LIMIT 1$$);
SELECT t.expect_denied('no changing provenance', $$UPDATE memory.provenance SET tool = 'x'$$);
SELECT t.expect_denied('no deleting provenance', 'DELETE FROM memory.provenance');
RESET ROLE;

\echo '-- nothing else changed'
SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c2', :'c2');
SELECT t.expect_count('a cell still reads only provenance it can see',
  $$SELECT 1 FROM memory.provenance p JOIN memory.namespaces n ON n.id = p.namespace_id
    WHERE n.path NOT IN ('testcity', 'testcity/tower-a', 'testcity/tower-a/cell-2')$$, 0);
COMMIT;
RESET ROLE;
SELECT t.expect_count('no API role can read provenance',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) r
    WHERE has_table_privilege(r, 'memory.provenance', 'SELECT')
       OR has_column_privilege(r, 'memory.provenance', 'tool', 'SELECT')$$, 0);

\echo 'all audit tests passed'
