-- 0001_memory_core: the memory schema's core tables, row security and the
-- write path. Forward-only. Apply with db/migrate.sh, which runs each file in
-- one transaction and records its checksum, so files carry no BEGIN or COMMIT.
--
-- Access model:
--   * Nothing in schema memory is granted to PUBLIC, anon, authenticated or
--     service_role, and the schema is not exposed through Supabase's REST API.
--   * The server connects as engramport_app, which cannot bypass RLS. It gets
--     LOGIN and a password at deploy time, from the secrets manager, not here.
--   * Each transaction runs SET LOCAL app.api_key_id and app.namespace_id after
--     the server has checked the caller's key. Policies trust neither setting
--     alone: the namespace is read from an active, unexpired key row, and must
--     equal app.namespace_id. A revoked key loses access on its next statement.
--   * Reads flow down the tree: a namespace reads itself plus its ancestors
--     (cell reads its tower and city). It never reads a sibling or a child.
--     Writes land only in the caller's own namespace.

CREATE SCHEMA IF NOT EXISTS extensions;
CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA extensions;

CREATE SCHEMA memory;
REVOKE ALL ON SCHEMA memory FROM PUBLIC;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'engramport_app') THEN
    CREATE ROLE engramport_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END
$$;

-- UUIDv7: time-ordered ids, so recent rows cluster in the index.
CREATE FUNCTION memory.uuid_v7() RETURNS uuid
LANGUAGE sql VOLATILE SET search_path = pg_catalog AS $$
  SELECT encode(
    set_bit(set_bit(
      overlay(uuid_send(gen_random_uuid())
        PLACING substring(int8send((extract(epoch FROM clock_timestamp()) * 1000)::bigint) FROM 3)
        FROM 1 FOR 6),
      52, 1), 53, 1),
    'hex')::uuid
$$;

CREATE TYPE memory.namespace_level AS ENUM ('city', 'tower', 'cell');
CREATE TYPE memory.actor_kind AS ENUM ('human', 'agent', 'service');
CREATE TYPE memory.memory_kind AS ENUM
  ('fact', 'decision', 'note', 'summary', 'insight', 'principle', 'hypothesis', 'document_chunk');
CREATE TYPE memory.memory_status AS ENUM ('active', 'superseded', 'retracted');
CREATE TYPE memory.transport AS ENUM ('stdio', 'streamable_http', 'rest', 'job');

-- Namespaces form a city > tower > cell tree. Slugs carry no client names at
-- the tower and city levels; that is a review rule, not something SQL can check.
CREATE TABLE memory.namespaces (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  parent_id uuid REFERENCES memory.namespaces(id),
  level memory.namespace_level NOT NULL,
  slug text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  path text NOT NULL UNIQUE,
  embedding_model text NOT NULL DEFAULT 'text-embedding-3-small',
  embedding_dim integer NOT NULL DEFAULT 1536 CHECK (embedding_dim = 1536),
  retention jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (parent_id, slug),
  CHECK ((level = 'city') = (parent_id IS NULL))
);

-- A city has no parent, a tower's parent is a city, a cell's parent is a tower.
-- path is derived, never supplied.
CREATE FUNCTION memory.namespaces_shape() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  parent memory.namespaces;
BEGIN
  IF TG_OP = 'UPDATE' AND (NEW.parent_id IS DISTINCT FROM OLD.parent_id
      OR NEW.level IS DISTINCT FROM OLD.level OR NEW.slug IS DISTINCT FROM OLD.slug) THEN
    RAISE EXCEPTION 'a namespace cannot be moved, re-levelled or renamed';
  END IF;
  IF NEW.level = 'city' THEN
    NEW.path := NEW.slug;
    RETURN NEW;
  END IF;
  SELECT * INTO parent FROM memory.namespaces WHERE id = NEW.parent_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'parent namespace % does not exist', NEW.parent_id;
  END IF;
  IF (NEW.level = 'tower' AND parent.level <> 'city')
     OR (NEW.level = 'cell' AND parent.level <> 'tower') THEN
    RAISE EXCEPTION 'a % cannot sit under a %', NEW.level, parent.level;
  END IF;
  NEW.path := parent.path || '/' || NEW.slug;
  RETURN NEW;
END
$$;
CREATE TRIGGER namespaces_shape BEFORE INSERT OR UPDATE ON memory.namespaces
  FOR EACH ROW EXECUTE FUNCTION memory.namespaces_shape();

CREATE TABLE memory.actors (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  kind memory.actor_kind NOT NULL,
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
  display_name text NOT NULL,
  disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- One key, one namespace. The server hashes the presented key with
-- HMAC-SHA256 and a pepper held in the secrets manager; only the hash is here.
CREATE TABLE memory.api_keys (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  actor_id uuid NOT NULL REFERENCES memory.actors(id),
  prefix text NOT NULL UNIQUE CHECK (prefix ~ '^[A-Za-z0-9_]{8,32}$'),
  key_hash bytea NOT NULL UNIQUE CHECK (octet_length(key_hash) = 32),
  scopes text[] NOT NULL DEFAULT '{read,write}'
    CHECK (scopes <@ ARRAY['read', 'write']::text[] AND cardinality(scopes) > 0),
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- One row per write. namespace_id, api_key_id and actor_id come from the key,
-- checked by policy; the rest is what the server saw on the request. Labels an
-- agent supplies about itself go in claimed, never in the checked columns.
CREATE TABLE memory.provenance (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  api_key_id uuid NOT NULL REFERENCES memory.api_keys(id),
  actor_id uuid NOT NULL REFERENCES memory.actors(id),
  tool text NOT NULL,
  client_name text,
  client_version text,
  transport memory.transport NOT NULL,
  session_id text,
  request_id text,
  source_kind text,
  source_ref text,
  log_event_id uuid,
  content_sha256 text CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  claimed jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memory.memories (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  kind memory.memory_kind NOT NULL,
  content text NOT NULL CHECK (length(content) BETWEEN 1 AND 32000),
  content_sha256 text NOT NULL,
  dedup_key text,
  status memory.memory_status NOT NULL DEFAULT 'active',
  supersedes_id uuid REFERENCES memory.memories(id),
  importance real NOT NULL DEFAULT 0.5 CHECK (importance BETWEEN 0 AND 1),
  metadata jsonb NOT NULL DEFAULT '{}',
  provenance_id uuid NOT NULL REFERENCES memory.provenance(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  fts tsvector GENERATED ALWAYS AS (to_tsvector('english'::regconfig, content)) STORED
);

-- The hash is always computed here, never taken from the caller.
CREATE FUNCTION memory.memories_hash() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  NEW.content_sha256 := encode(sha256(convert_to(NEW.content, 'UTF8')), 'hex');
  RETURN NEW;
END
$$;
CREATE TRIGGER memories_hash BEFORE INSERT ON memory.memories
  FOR EACH ROW EXECUTE FUNCTION memory.memories_hash();

-- Kept apart from memories so a re-embed or a model change never touches the record.
CREATE TABLE memory.memory_embeddings (
  memory_id uuid NOT NULL REFERENCES memory.memories(id),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  model text NOT NULL,
  dimension integer NOT NULL CHECK (dimension = 1536),
  embedding extensions.halfvec(1536) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (memory_id, model)
);

CREATE INDEX memories_ns_status_created ON memory.memories (namespace_id, status, created_at DESC);
CREATE INDEX memories_fts ON memory.memories USING gin (fts);
CREATE UNIQUE INDEX memories_dedup ON memory.memories (namespace_id, dedup_key)
  WHERE dedup_key IS NOT NULL AND status = 'active';
CREATE INDEX memory_embeddings_hnsw ON memory.memory_embeddings
  USING hnsw (embedding extensions.halfvec_cosine_ops) WITH (m = 16, ef_construction = 64);
CREATE INDEX memory_embeddings_ns ON memory.memory_embeddings (namespace_id);
CREATE INDEX provenance_ns_created ON memory.provenance (namespace_id, created_at DESC);
CREATE INDEX api_keys_namespace ON memory.api_keys (namespace_id);

-- The caller's key, if it is active, unexpired, write-capable or not, and its
-- namespace matches app.namespace_id. Anything missing or wrong returns no row.
CREATE FUNCTION memory.current_key()
RETURNS TABLE (api_key_id uuid, namespace_id uuid, actor_id uuid, scopes text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT k.id, k.namespace_id, k.actor_id, k.scopes
  FROM memory.api_keys k
  JOIN memory.actors a ON a.id = k.actor_id
  WHERE k.id = nullif(current_setting('app.api_key_id', true), '')::uuid
    AND k.namespace_id = nullif(current_setting('app.namespace_id', true), '')::uuid
    AND k.revoked_at IS NULL
    AND (k.expires_at IS NULL OR k.expires_at > now())
    AND a.disabled_at IS NULL
$$;

CREATE FUNCTION memory.current_namespace() RETURNS uuid
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  SELECT namespace_id FROM memory.current_key()
$$;

CREATE FUNCTION memory.can_write() RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  SELECT coalesce((SELECT 'write' = ANY (scopes) FROM memory.current_key()), false)
$$;

-- The caller's namespace and its ancestors: a cell sees cell, tower, city.
CREATE FUNCTION memory.readable_namespaces() RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  WITH RECURSIVE up AS (
    SELECT n.id, n.parent_id FROM memory.namespaces n
    WHERE n.id = (SELECT namespace_id FROM memory.current_key())
    UNION ALL
    SELECT p.id, p.parent_id FROM memory.namespaces p JOIN up ON p.id = up.parent_id
  )
  SELECT id FROM up
$$;

-- True if the memory exists in the caller's own namespace. A definer function,
-- so policies on memories can use it without recursing into themselves.
CREATE FUNCTION memory.is_own_memory(p_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT EXISTS (SELECT 1 FROM memory.memories m
                 WHERE m.id = p_id AND m.namespace_id = memory.current_namespace())
$$;

-- Key lookup for the server, before any namespace is set. Takes the HMAC the
-- server computed; returns the key's ids only if it is usable, and stamps use.
CREATE FUNCTION memory.authenticate(p_prefix text, p_key_hash bytea)
RETURNS TABLE (api_key_id uuid, namespace_id uuid, actor_id uuid, scopes text[])
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  RETURN QUERY
  UPDATE memory.api_keys k SET last_used_at = now()
  FROM memory.actors a
  WHERE a.id = k.actor_id
    AND k.prefix = p_prefix
    AND k.key_hash = p_key_hash
    AND k.revoked_at IS NULL
    AND (k.expires_at IS NULL OR k.expires_at > now())
    AND a.disabled_at IS NULL
  RETURNING k.id, k.namespace_id, k.actor_id, k.scopes;
END
$$;

-- The write path: provenance and memory in one statement's transaction.
-- SECURITY INVOKER, so every insert passes the policies below.
CREATE FUNCTION memory.remember(
  p_kind memory.memory_kind,
  p_content text,
  p_tool text,
  p_transport memory.transport,
  p_importance real DEFAULT 0.5,
  p_metadata jsonb DEFAULT '{}',
  p_dedup_key text DEFAULT NULL,
  p_client_name text DEFAULT NULL,
  p_client_version text DEFAULT NULL,
  p_session_id text DEFAULT NULL,
  p_request_id text DEFAULT NULL,
  p_source_kind text DEFAULT NULL,
  p_source_ref text DEFAULT NULL,
  p_log_event_id uuid DEFAULT NULL,
  p_claimed jsonb DEFAULT '{}'
) RETURNS uuid
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, extensions AS $$
DECLARE
  k record;
  prov_id uuid;
  mem_id uuid;
BEGIN
  SELECT * INTO k FROM memory.current_key();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no valid key for this transaction' USING ERRCODE = '42501';
  END IF;
  INSERT INTO memory.provenance (namespace_id, api_key_id, actor_id, tool, client_name,
      client_version, transport, session_id, request_id, source_kind, source_ref,
      log_event_id, content_sha256, claimed)
  VALUES (k.namespace_id, k.api_key_id, k.actor_id, p_tool, p_client_name,
      p_client_version, p_transport, p_session_id, p_request_id, p_source_kind, p_source_ref,
      p_log_event_id, encode(sha256(convert_to(p_content, 'UTF8')), 'hex'), p_claimed)
  RETURNING id INTO prov_id;
  INSERT INTO memory.memories (namespace_id, kind, content, dedup_key, importance, metadata, provenance_id)
  VALUES (k.namespace_id, p_kind, p_content, p_dedup_key, p_importance, p_metadata, prov_id)
  RETURNING id INTO mem_id;
  RETURN mem_id;
END
$$;

-- Row security, enabled and forced on every table.
ALTER TABLE memory.namespaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.namespaces FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.actors ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.actors FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.api_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.provenance ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.provenance FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.memories ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.memories FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.memory_embeddings ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.memory_embeddings FORCE ROW LEVEL SECURITY;

CREATE POLICY namespaces_read ON memory.namespaces FOR SELECT TO engramport_app
  USING (id IN (SELECT memory.readable_namespaces()));

CREATE POLICY actors_read ON memory.actors FOR SELECT TO engramport_app
  USING (true);

-- api_keys has no policy for the app: it is reached only through
-- current_key() and authenticate().

-- Provenance of the caller's own namespace only, so a cell never learns which
-- client a tower memory came from.
CREATE POLICY provenance_read ON memory.provenance FOR SELECT TO engramport_app
  USING (namespace_id = memory.current_namespace());
CREATE POLICY provenance_write ON memory.provenance FOR INSERT TO engramport_app
  WITH CHECK (memory.can_write() AND (namespace_id, api_key_id, actor_id) =
    (SELECT k.namespace_id, k.api_key_id, k.actor_id FROM memory.current_key() k));

CREATE POLICY memories_read ON memory.memories FOR SELECT TO engramport_app
  USING (namespace_id IN (SELECT memory.readable_namespaces()));
CREATE POLICY memories_write ON memory.memories FOR INSERT TO engramport_app
  WITH CHECK (memory.can_write() AND namespace_id = memory.current_namespace()
    AND EXISTS (SELECT 1 FROM memory.provenance p
                WHERE p.id = provenance_id AND p.namespace_id = memory.current_namespace())
    AND (supersedes_id IS NULL OR memory.is_own_memory(supersedes_id)));
CREATE POLICY memories_status ON memory.memories FOR UPDATE TO engramport_app
  USING (memory.can_write() AND namespace_id = memory.current_namespace())
  WITH CHECK (namespace_id = memory.current_namespace()
    AND (supersedes_id IS NULL OR memory.is_own_memory(supersedes_id)));

CREATE POLICY embeddings_read ON memory.memory_embeddings FOR SELECT TO engramport_app
  USING (namespace_id IN (SELECT memory.readable_namespaces()));
CREATE POLICY embeddings_write ON memory.memory_embeddings FOR INSERT TO engramport_app
  WITH CHECK (memory.can_write() AND namespace_id = memory.current_namespace()
    AND memory.is_own_memory(memory_id));

-- Grants: the least the server needs. Content is never updated in place; only
-- status and supersedes_id change, so a retraction keeps the original text.
REVOKE ALL ON ALL TABLES IN SCHEMA memory FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA memory FROM PUBLIC;
GRANT USAGE ON SCHEMA memory TO engramport_app;
GRANT USAGE ON SCHEMA extensions TO engramport_app;
GRANT SELECT ON memory.namespaces, memory.actors TO engramport_app;
GRANT SELECT, INSERT ON memory.provenance, memory.memories, memory.memory_embeddings TO engramport_app;
GRANT UPDATE (status, supersedes_id) ON memory.memories TO engramport_app;
GRANT EXECUTE ON FUNCTION
  memory.uuid_v7(), memory.current_key(), memory.current_namespace(), memory.can_write(),
  memory.readable_namespaces(), memory.is_own_memory(uuid), memory.authenticate(text, bytea),
  memory.remember(memory.memory_kind, text, text, memory.transport, real, jsonb, text, text,
                  text, text, text, text, text, uuid, jsonb)
  TO engramport_app;

-- Supabase's API roles get nothing here, even if a later default grants them.
DO $$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE ALL ON SCHEMA memory FROM %I', r);
      EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA memory FROM %I', r);
      EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA memory FROM %I', r);
    END IF;
  END LOOP;
END
$$;
-- New functions default to EXECUTE for PUBLIC and a schema-level default cannot
-- take that back, so every later migration revokes and grants explicitly.
