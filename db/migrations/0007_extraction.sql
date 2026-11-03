-- 0007_extraction: what the extraction job needs to fill the graph from new
-- memories. Forward-only; applied by db/migrate.sh in one transaction.
--
--   * extraction_runs records that a memory was read by a given extractor, so
--     the job never reads a memory twice and a failure can be retried a few
--     times. A run sits in the memory's own namespace, can only be written
--     through a 'job' provenance of the writer's own key, and is never edited
--     or deleted. It holds counts and an error class, never memory text.
--   * pg_trgm, with trigram indexes on entity and alias keys, so the job can
--     match "Grok Bots" to an existing "Grok Bot" instead of making a twin.

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA extensions;

CREATE INDEX entities_norm_trgm ON memory.entities USING gin (norm_key extensions.gin_trgm_ops);
CREATE INDEX entity_aliases_norm_trgm ON memory.entity_aliases USING gin (norm_key extensions.gin_trgm_ops);

CREATE TYPE memory.extraction_status AS ENUM ('done', 'failed');

CREATE TABLE memory.extraction_runs (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  memory_id uuid NOT NULL REFERENCES memory.memories(id),
  -- Which extractor and version, such as "claude-haiku/v1", so a better one
  -- can re-read memories an older one already did.
  extractor text NOT NULL CHECK (extractor ~ '^[a-z0-9][a-z0-9._/-]{0,63}$'),
  status memory.extraction_status NOT NULL,
  entities_found integer NOT NULL DEFAULT 0 CHECK (entities_found >= 0),
  relations_found integer NOT NULL DEFAULT 0 CHECK (relations_found >= 0),
  -- A short class such as "timeout" or "bad_output"; never a provider message,
  -- which can echo the text it was sent.
  error_class text CHECK (error_class ~ '^[a-z_]{1,32}$'),
  provenance_id uuid NOT NULL REFERENCES memory.provenance(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((status = 'failed') = (error_class IS NOT NULL))
);

-- One finished run per memory and extractor.
CREATE UNIQUE INDEX extraction_runs_done ON memory.extraction_runs (memory_id, extractor) WHERE status = 'done';
CREATE INDEX extraction_runs_memory ON memory.extraction_runs (memory_id, extractor);
CREATE INDEX extraction_runs_namespace ON memory.extraction_runs (namespace_id, created_at DESC);
CREATE INDEX extraction_runs_provenance ON memory.extraction_runs (provenance_id);

CREATE FUNCTION memory.extraction_runs_final() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'extraction runs are never changed or deleted';
END
$$;
CREATE TRIGGER extraction_runs_final BEFORE UPDATE OR DELETE ON memory.extraction_runs
  FOR EACH ROW EXECUTE FUNCTION memory.extraction_runs_final();

ALTER TABLE memory.extraction_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.extraction_runs FORCE ROW LEVEL SECURITY;

CREATE POLICY extraction_runs_read ON memory.extraction_runs FOR SELECT TO engramport_app
  USING (namespace_id = memory.current_namespace());
CREATE POLICY extraction_runs_write ON memory.extraction_runs FOR INSERT TO engramport_app
  WITH CHECK (memory.can_write()
    AND namespace_id = memory.current_namespace()
    AND memory.is_own_memory(memory_id)
    AND memory.own_provenance_transport(provenance_id) = 'job');

GRANT SELECT, INSERT ON memory.extraction_runs TO engramport_app;

REVOKE ALL ON FUNCTION memory.extraction_runs_final() FROM PUBLIC;

DO $$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA memory FROM %I', r);
      EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA memory FROM %I', r);
    END IF;
  END LOOP;
END
$$;
