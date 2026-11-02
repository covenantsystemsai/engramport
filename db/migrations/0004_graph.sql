-- 0004_graph: the knowledge graph. Entities (people, organizations, projects,
-- tools, ...), their aliases, typed relations between them, which memories
-- mention which entities, and memory-to-memory links. Forward-only; applied by
-- db/migrate.sh in one transaction.
--
-- The same walls as 0001:
--   * Every row sits in exactly one namespace, the writer's own.
--   * Reads flow down the tree: a cell sees graph rows in itself, its tower and
--     its city, never a sibling's or a child's.
--   * A row may point at things the writer can read (a cell relation can name
--     a tower entity), but the row itself stays in the cell, so the tower never
--     learns it exists.
--   * Every write carries a provenance row of the writer's own key.
--   * Nothing is edited or deleted: an entity, relation or link can only move
--     from active to retracted, and the text stays for the record.

-- One normal form for names and aliases, so "Grok  Bot" and "grok bot" match.
CREATE FUNCTION memory.norm_key(p text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog AS $$
  -- Collapse every run of whitespace (tabs and newlines too) to one space
  -- first, then trim, since btrim alone strips only plain spaces.
  SELECT lower(btrim(regexp_replace(normalize(p, NFKC), '\s+', ' ', 'g')))
$$;

CREATE TYPE memory.graph_status AS ENUM ('active', 'retracted');
-- asserted: an agent or person said so through the link tool.
-- extracted: the extraction job read it out of a memory (transport job only).
CREATE TYPE memory.graph_origin AS ENUM ('asserted', 'extracted');
CREATE TYPE memory.memory_link_kind AS ENUM
  ('supports', 'contradicts', 'derived_from', 'synthesizes', 'related');

CREATE TABLE memory.entities (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  type text NOT NULL CHECK (type ~ '^[a-z][a-z0-9_]{0,31}$'),
  name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
  norm_key text NOT NULL,
  description text CHECK (length(description) <= 2000),
  status memory.graph_status NOT NULL DEFAULT 'active',
  origin memory.graph_origin NOT NULL DEFAULT 'asserted',
  provenance_id uuid NOT NULL REFERENCES memory.provenance(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memory.entity_aliases (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  entity_id uuid NOT NULL REFERENCES memory.entities(id),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  alias text NOT NULL CHECK (length(btrim(alias)) BETWEEN 1 AND 200),
  norm_key text NOT NULL,
  provenance_id uuid NOT NULL REFERENCES memory.provenance(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE memory.relations (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  source_entity_id uuid NOT NULL REFERENCES memory.entities(id),
  predicate text NOT NULL CHECK (predicate ~ '^[a-z][a-z0-9_]{0,47}$'),
  target_entity_id uuid NOT NULL REFERENCES memory.entities(id),
  confidence real NOT NULL DEFAULT 1 CHECK (confidence BETWEEN 0 AND 1),
  -- The memory that supports it, and the words in it that do, when there is one.
  evidence_memory_id uuid REFERENCES memory.memories(id),
  evidence_span text CHECK (length(evidence_span) <= 1000),
  status memory.graph_status NOT NULL DEFAULT 'active',
  origin memory.graph_origin NOT NULL DEFAULT 'asserted',
  provenance_id uuid NOT NULL REFERENCES memory.provenance(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (source_entity_id <> target_entity_id),
  CHECK (evidence_span IS NULL OR evidence_memory_id IS NOT NULL)
);

-- Which memories mention which entities. A cell can note that its own memory
-- mentions a tower entity; it cannot annotate a tower memory.
CREATE TABLE memory.entity_mentions (
  memory_id uuid NOT NULL REFERENCES memory.memories(id),
  entity_id uuid NOT NULL REFERENCES memory.entities(id),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  origin memory.graph_origin NOT NULL DEFAULT 'asserted',
  provenance_id uuid NOT NULL REFERENCES memory.provenance(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (memory_id, entity_id)
);

-- Memory-to-memory edges: an insight derived from its sources, a note that
-- contradicts a decision. The link starts at one of the writer's own memories.
CREATE TABLE memory.memory_links (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  from_memory_id uuid NOT NULL REFERENCES memory.memories(id),
  kind memory.memory_link_kind NOT NULL,
  to_memory_id uuid NOT NULL REFERENCES memory.memories(id),
  status memory.graph_status NOT NULL DEFAULT 'active',
  origin memory.graph_origin NOT NULL DEFAULT 'asserted',
  provenance_id uuid NOT NULL REFERENCES memory.provenance(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (from_memory_id <> to_memory_id)
);

-- One active entity per name and type in a namespace; one active copy of each
-- relation and link. Every uniqueness rule includes the namespace, so a write
-- can never collide with a row the writer cannot see.
CREATE UNIQUE INDEX entities_ns_key ON memory.entities (namespace_id, type, norm_key) WHERE status = 'active';
CREATE INDEX entities_provenance ON memory.entities (provenance_id);
CREATE INDEX entities_norm_key ON memory.entities (norm_key);
-- Unique per namespace, so one cell's alias on a tower entity never collides
-- with (and so never reveals) another cell's.
CREATE UNIQUE INDEX entity_aliases_ns_key ON memory.entity_aliases (namespace_id, entity_id, norm_key);
CREATE INDEX entity_aliases_lookup ON memory.entity_aliases (namespace_id, norm_key);
CREATE INDEX entity_aliases_entity ON memory.entity_aliases (entity_id);
CREATE INDEX entity_aliases_provenance ON memory.entity_aliases (provenance_id);
CREATE UNIQUE INDEX relations_active ON memory.relations
  (namespace_id, source_entity_id, predicate, target_entity_id) WHERE status = 'active';
CREATE INDEX relations_source ON memory.relations (source_entity_id);
CREATE INDEX relations_target ON memory.relations (target_entity_id);
CREATE INDEX relations_evidence ON memory.relations (evidence_memory_id) WHERE evidence_memory_id IS NOT NULL;
CREATE INDEX relations_provenance ON memory.relations (provenance_id);
CREATE INDEX entity_mentions_entity ON memory.entity_mentions (entity_id);
CREATE INDEX entity_mentions_ns ON memory.entity_mentions (namespace_id);
CREATE INDEX entity_mentions_provenance ON memory.entity_mentions (provenance_id);
CREATE UNIQUE INDEX memory_links_active ON memory.memory_links
  (namespace_id, from_memory_id, kind, to_memory_id) WHERE status = 'active';
CREATE INDEX memory_links_from ON memory.memory_links (from_memory_id);
CREATE INDEX memory_links_to ON memory.memory_links (to_memory_id);
CREATE INDEX memory_links_provenance ON memory.memory_links (provenance_id);

-- norm_key is always computed here, never taken from the caller.
CREATE FUNCTION memory.entities_norm() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  NEW.norm_key := memory.norm_key(NEW.name);
  RETURN NEW;
END
$$;
CREATE TRIGGER entities_norm BEFORE INSERT ON memory.entities
  FOR EACH ROW EXECUTE FUNCTION memory.entities_norm();

CREATE FUNCTION memory.entity_aliases_norm() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  NEW.norm_key := memory.norm_key(NEW.alias);
  RETURN NEW;
END
$$;
CREATE TRIGGER entity_aliases_norm BEFORE INSERT ON memory.entity_aliases
  FOR EACH ROW EXECUTE FUNCTION memory.entity_aliases_norm();

-- Graph rows are append-only: the only change is active to retracted, once.
-- Applies to every role, the owner included.
CREATE FUNCTION memory.graph_retract_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF NOT (OLD.status = 'active' AND NEW.status = 'retracted') THEN
    RAISE EXCEPTION 'a graph row can only be retracted, once';
  END IF;
  IF (to_jsonb(NEW) - 'status') IS DISTINCT FROM (to_jsonb(OLD) - 'status') THEN
    RAISE EXCEPTION 'only the status of a graph row can change';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER entities_retract_only BEFORE UPDATE ON memory.entities
  FOR EACH ROW EXECUTE FUNCTION memory.graph_retract_only();
CREATE TRIGGER relations_retract_only BEFORE UPDATE ON memory.relations
  FOR EACH ROW EXECUTE FUNCTION memory.graph_retract_only();
CREATE TRIGGER memory_links_retract_only BEFORE UPDATE ON memory.memory_links
  FOR EACH ROW EXECUTE FUNCTION memory.graph_retract_only();

-- The transport of a provenance row, if it belongs to the caller's own key;
-- NULL otherwise. Invoker rights: provenance_read already limits it to the
-- caller's namespace, and the join pins it to the caller's key.
CREATE FUNCTION memory.own_provenance_transport(p_id uuid) RETURNS memory.transport
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  SELECT p.transport FROM memory.provenance p
  JOIN memory.current_key() k
    ON (p.namespace_id, p.api_key_id, p.actor_id) = (k.namespace_id, k.api_key_id, k.actor_id)
  WHERE p.id = p_id
$$;

-- A write's provenance must be the caller's own, and only the job transport
-- may label a row as extracted, so an agent can't pass its claims off as the
-- extractor's.
CREATE FUNCTION memory.graph_write_ok(p_provenance uuid, p_origin memory.graph_origin) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  SELECT memory.can_write() AND coalesce(
    (SELECT p_origin = 'asserted' OR t = 'job' FROM memory.own_provenance_transport(p_provenance) t
      WHERE t IS NOT NULL), false)
$$;

-- An active entity the caller can read. Definer rights, so policies on
-- entities and aliases can use it without recursing into their own policies.
CREATE FUNCTION memory.is_readable_entity(p_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT EXISTS (SELECT 1 FROM memory.entities e
                 WHERE e.id = p_id AND e.status = 'active'
                   AND e.namespace_id IN (SELECT memory.readable_namespaces()))
$$;

-- An active memory the caller can read.
CREATE FUNCTION memory.is_readable_memory(p_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT EXISTS (SELECT 1 FROM memory.memories m
                 WHERE m.id = p_id AND m.status = 'active'
                   AND m.namespace_id IN (SELECT memory.readable_namespaces()))
$$;

-- Records a provenance row for a graph write (no memory text, so no hash) and
-- returns its id. Invoker rights, so the insert passes provenance_write.
CREATE FUNCTION memory.record_provenance(
  p_tool text,
  p_transport memory.transport,
  p_client_name text DEFAULT NULL,
  p_client_version text DEFAULT NULL,
  p_session_id text DEFAULT NULL,
  p_request_id text DEFAULT NULL,
  p_source_kind text DEFAULT NULL,
  p_source_ref text DEFAULT NULL,
  p_log_event_id uuid DEFAULT NULL,
  p_claimed jsonb DEFAULT '{}'
) RETURNS uuid
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog AS $$
DECLARE
  k record;
  prov_id uuid;
BEGIN
  SELECT * INTO k FROM memory.current_key();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no valid key for this transaction' USING ERRCODE = '42501';
  END IF;
  INSERT INTO memory.provenance (namespace_id, api_key_id, actor_id, tool, client_name,
      client_version, transport, session_id, request_id, source_kind, source_ref,
      log_event_id, claimed)
  VALUES (k.namespace_id, k.api_key_id, k.actor_id, p_tool, p_client_name,
      p_client_version, p_transport, p_session_id, p_request_id, p_source_kind, p_source_ref,
      p_log_event_id, p_claimed)
  RETURNING id INTO prov_id;
  RETURN prov_id;
END
$$;

ALTER TABLE memory.entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.entities FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.entity_aliases ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.entity_aliases FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.relations ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.relations FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.entity_mentions ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.entity_mentions FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.memory_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.memory_links FORCE ROW LEVEL SECURITY;

CREATE POLICY entities_read ON memory.entities FOR SELECT TO engramport_app
  USING (namespace_id IN (SELECT memory.readable_namespaces()));
CREATE POLICY entities_write ON memory.entities FOR INSERT TO engramport_app
  WITH CHECK (namespace_id = memory.current_namespace() AND status = 'active'
    AND memory.graph_write_ok(provenance_id, origin));
CREATE POLICY entities_retract ON memory.entities FOR UPDATE TO engramport_app
  USING (memory.can_write() AND namespace_id = memory.current_namespace())
  WITH CHECK (namespace_id = memory.current_namespace());

CREATE POLICY entity_aliases_read ON memory.entity_aliases FOR SELECT TO engramport_app
  USING (namespace_id IN (SELECT memory.readable_namespaces()));
CREATE POLICY entity_aliases_write ON memory.entity_aliases FOR INSERT TO engramport_app
  WITH CHECK (namespace_id = memory.current_namespace()
    AND memory.graph_write_ok(provenance_id, 'asserted')
    AND memory.is_readable_entity(entity_id));

CREATE POLICY relations_read ON memory.relations FOR SELECT TO engramport_app
  USING (namespace_id IN (SELECT memory.readable_namespaces()));
CREATE POLICY relations_write ON memory.relations FOR INSERT TO engramport_app
  WITH CHECK (namespace_id = memory.current_namespace() AND status = 'active'
    AND memory.graph_write_ok(provenance_id, origin)
    AND memory.is_readable_entity(source_entity_id)
    AND memory.is_readable_entity(target_entity_id)
    AND (evidence_memory_id IS NULL OR memory.is_readable_memory(evidence_memory_id)));
CREATE POLICY relations_retract ON memory.relations FOR UPDATE TO engramport_app
  USING (memory.can_write() AND namespace_id = memory.current_namespace())
  WITH CHECK (namespace_id = memory.current_namespace());

CREATE POLICY entity_mentions_read ON memory.entity_mentions FOR SELECT TO engramport_app
  USING (namespace_id IN (SELECT memory.readable_namespaces()));
CREATE POLICY entity_mentions_write ON memory.entity_mentions FOR INSERT TO engramport_app
  WITH CHECK (namespace_id = memory.current_namespace()
    AND memory.graph_write_ok(provenance_id, origin)
    AND memory.is_own_memory(memory_id)
    AND memory.is_readable_entity(entity_id));

CREATE POLICY memory_links_read ON memory.memory_links FOR SELECT TO engramport_app
  USING (namespace_id IN (SELECT memory.readable_namespaces()));
CREATE POLICY memory_links_write ON memory.memory_links FOR INSERT TO engramport_app
  WITH CHECK (namespace_id = memory.current_namespace() AND status = 'active'
    AND memory.graph_write_ok(provenance_id, origin)
    AND memory.is_own_memory(from_memory_id)
    AND memory.is_readable_memory(to_memory_id));
CREATE POLICY memory_links_retract ON memory.memory_links FOR UPDATE TO engramport_app
  USING (memory.can_write() AND namespace_id = memory.current_namespace())
  WITH CHECK (namespace_id = memory.current_namespace());

-- The app role gets reads, inserts and a status change; no deletes. The admin
-- role from 0002 gets nothing here: the graph is client data.
GRANT SELECT, INSERT ON memory.entities, memory.entity_aliases, memory.relations,
  memory.entity_mentions, memory.memory_links TO engramport_app;
GRANT UPDATE (status) ON memory.entities, memory.relations, memory.memory_links TO engramport_app;

REVOKE ALL ON FUNCTION
  memory.norm_key(text), memory.entities_norm(), memory.entity_aliases_norm(),
  memory.graph_retract_only(), memory.own_provenance_transport(uuid),
  memory.graph_write_ok(uuid, memory.graph_origin), memory.is_readable_entity(uuid),
  memory.is_readable_memory(uuid),
  memory.record_provenance(text, memory.transport, text, text, text, text, text, text, uuid, jsonb)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  memory.norm_key(text), memory.own_provenance_transport(uuid),
  memory.graph_write_ok(uuid, memory.graph_origin), memory.is_readable_entity(uuid),
  memory.is_readable_memory(uuid),
  memory.record_provenance(text, memory.transport, text, text, text, text, text, text, uuid, jsonb)
  TO engramport_app;

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
