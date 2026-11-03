-- 0006_admin_audit: the admin role reads the audit trail, never the content.
-- Forward-only; applied by db/migrate.sh in one transaction.
--
-- "Manage and audit only": the admin role (0002) manages namespaces, actors and
-- keys. This adds read access to provenance metadata, so it can see who wrote,
-- through which agent, client, tool and transport, in which namespace and
-- when. It gets these columns and no others:
--   id, namespace_id, api_key_id, actor_id, tool, client_name, client_version,
--   transport, session_id, request_id, source_kind, log_event_id, created_at
-- It still cannot read content_sha256 (a hash can confirm a guessed text),
-- claimed (free-form fields an agent sends), source_ref (can name a document),
-- or any memory, embedding or graph row.

GRANT SELECT (id, namespace_id, api_key_id, actor_id, tool, client_name, client_version,
              transport, session_id, request_id, source_kind, log_event_id, created_at)
  ON memory.provenance TO engramport_admin;

CREATE POLICY provenance_admin_audit ON memory.provenance FOR SELECT TO engramport_admin
  USING (true);

-- The audit reads newest first across every namespace.
CREATE INDEX provenance_created ON memory.provenance (created_at DESC);
