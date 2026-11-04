-- D-02: erasure. A person with authority over a namespace has memories erased;
-- agents can only ask. Forward-only; applied by db/migrate.sh in one transaction.
--
-- What erasure removes, for every version of each memory named (the whole
-- supersession chain, proposals included):
--   - the text, metadata and dedup key, and the text's digest;
--   - its embeddings, and so its place in vector search;
--   - its keyword index entry (generated from the text, so it empties with it);
--   - graph rows that cite it: entity mentions, memory links in either
--     direction, relations it is evidence for, and extracted entities left
--     with nothing pointing at them;
--   - its provenance's source link, client claims and digest;
--   - the digest held in approval decisions and challenges about it.
-- There are no caches or derived summaries yet; anything added later must
-- register here.
--
-- What it keeps: the memory's row as a content-free tombstone (id, namespace,
-- kind, claim type, approval state, timestamps, status 'erased'), a tombstone
-- in memory.erasures (who, when, under which request), the request and its
-- completion evidence, and the approval and audit records, which hold no text.
--
-- How it's enforced:
--   - Only memory.erase_chain changes a memory's text or erases it, and only
--     after recording its tombstone in the same transaction. An erased memory
--     stays erased.
--   - Nothing can attach to an erased memory afterwards: new embeddings,
--     mentions, links, evidence and versions are refused. Each such write takes
--     a share lock on the memory, so one racing an erasure waits for it and is
--     then refused (deletion during indexing).
--   - An agent can propose an erasure (memory.request_erasure), never carry it
--     out. A person decides with a fresh sign-in and a single-use challenge
--     bound to the exact request, under an owner's authority over the
--     namespace (a grant made to them directly, not a delegation; delegated
--     erasure comes in a later migration). The admin sees requests, tombstones
--     and evidence, never text.
--   - Backups: a database restored from a backup taken before an erasure
--     brings the erased text back. memory.reapply_erasures re-erases the
--     memories in a ledger of tombstones kept outside the database; the
--     restore runbook in docs/erasure.md requires it before serving anyone.
--     Nothing here claims that backups themselves are erased.

-- Erased rows hold no text and no digest.
ALTER TABLE memory.memories DROP CONSTRAINT memories_content_check;
ALTER TABLE memory.memories ADD CONSTRAINT memories_content_check
  CHECK ((status = 'erased' AND content = '') OR (status <> 'erased' AND length(content) BETWEEN 1 AND 32000));
ALTER TABLE memory.memories ALTER COLUMN content_sha256 DROP NOT NULL;
ALTER TABLE memory.memories ADD CONSTRAINT memories_digest_unless_erased
  CHECK ((status = 'erased') = (content_sha256 IS NULL));
ALTER TABLE memory.approvals ALTER COLUMN content_sha256 DROP NOT NULL;
ALTER TABLE memory.approval_challenges ALTER COLUMN content_sha256 DROP NOT NULL;

ALTER TABLE memory.human_sign_ins_used DROP CONSTRAINT human_sign_ins_used_purpose_check;
ALTER TABLE memory.human_sign_ins_used ADD CONSTRAINT human_sign_ins_used_purpose_check
  CHECK (purpose IN ('approve', 'delegate', 'revoke', 'connect', 'accept', 'erase'));

-- ── Requests, challenges and tombstones ─────────────────────────────────────

CREATE TYPE memory.erasure_reason AS ENUM ('owner_request', 'stored_in_error', 'legal');
CREATE TYPE memory.erasure_state AS ENUM ('proposed', 'completed');

CREATE TABLE memory.erasure_requests (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  reason memory.erasure_reason NOT NULL,
  requested_by_actor_id uuid NOT NULL REFERENCES memory.actors(id),
  api_key_id uuid REFERENCES memory.api_keys(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  state memory.erasure_state NOT NULL DEFAULT 'proposed',
  completed_at timestamptz,
  decided_by_actor_id uuid REFERENCES memory.actors(id),
  authority_id uuid REFERENCES memory.approval_authorities(id),
  challenge_id uuid UNIQUE,
  evidence jsonb,
  CHECK ((state = 'completed') = (completed_at IS NOT NULL AND decided_by_actor_id IS NOT NULL
                                  AND authority_id IS NOT NULL AND challenge_id IS NOT NULL AND evidence IS NOT NULL))
);
CREATE INDEX erasure_requests_ns ON memory.erasure_requests (namespace_id, created_at DESC);
CREATE INDEX erasure_requests_requested_by ON memory.erasure_requests (requested_by_actor_id);
CREATE INDEX erasure_requests_key ON memory.erasure_requests (api_key_id);
CREATE INDEX erasure_requests_decided_by ON memory.erasure_requests (decided_by_actor_id);
CREATE INDEX erasure_requests_authority ON memory.erasure_requests (authority_id);

-- One request names at most 100 memories (a bounded bulk request).
CREATE TABLE memory.erasure_request_items (
  request_id uuid NOT NULL REFERENCES memory.erasure_requests(id),
  memory_id uuid NOT NULL REFERENCES memory.memories(id),
  PRIMARY KEY (request_id, memory_id)
);
CREATE INDEX erasure_request_items_memory ON memory.erasure_request_items (memory_id);

CREATE TABLE memory.erasure_challenges (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  request_id uuid NOT NULL REFERENCES memory.erasure_requests(id),
  actor_id uuid NOT NULL REFERENCES memory.actors(id),
  authority_id uuid NOT NULL REFERENCES memory.approval_authorities(id),
  items_sha256 text NOT NULL CHECK (items_sha256 ~ '^[0-9a-f]{64}$'),
  secret_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(secret_sha256) = 32),
  sign_in_hash bytea NOT NULL UNIQUE CHECK (octet_length(sign_in_hash) = 32),
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  CHECK (expires_at > issued_at)
);
CREATE INDEX erasure_challenges_request ON memory.erasure_challenges (request_id);
CREATE INDEX erasure_challenges_actor ON memory.erasure_challenges (actor_id);
CREATE INDEX erasure_challenges_authority ON memory.erasure_challenges (authority_id);
ALTER TABLE memory.erasure_requests ADD CONSTRAINT erasure_requests_challenge
  FOREIGN KEY (challenge_id) REFERENCES memory.erasure_challenges(id);

-- The tombstone: one row per erased memory version. Its txid is how the
-- guards know an erasure is under way in this transaction.
CREATE TABLE memory.erasures (
  memory_id uuid PRIMARY KEY REFERENCES memory.memories(id),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  request_id uuid REFERENCES memory.erasure_requests(id),
  source text NOT NULL CHECK (source IN ('request', 'restore')),
  erased_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  txid bigint NOT NULL DEFAULT txid_current(),
  CHECK ((source = 'request') = (request_id IS NOT NULL))
);
CREATE INDEX erasures_ns ON memory.erasures (namespace_id, erased_at);
CREATE INDEX erasures_request ON memory.erasures (request_id);

-- An attempt that failed and rolled back leaves this note: the request, when,
-- and the error class. Nothing else.
CREATE TABLE memory.erasure_attempts (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  request_id uuid NOT NULL REFERENCES memory.erasure_requests(id),
  failed_at timestamptz NOT NULL DEFAULT now(),
  sqlstate text NOT NULL CHECK (sqlstate ~ '^[0-9A-Z]{5}$')
);
CREATE INDEX erasure_attempts_request ON memory.erasure_attempts (request_id);

-- All of these are records. A request changes once, from proposed to
-- completed, inside memory.decide_erasure_challenge.
CREATE FUNCTION memory.erasure_records_kept() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  -- Nested, so the row fields are read only on the one table that has them.
  IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'erasure_requests' THEN
    IF (to_jsonb(OLD) ->> 'state') = 'proposed' AND (to_jsonb(NEW) ->> 'state') = 'completed'
       AND (to_jsonb(NEW) - ARRAY['state', 'completed_at', 'decided_by_actor_id', 'authority_id', 'challenge_id', 'evidence'])
         = (to_jsonb(OLD) - ARRAY['state', 'completed_at', 'decided_by_actor_id', 'authority_id', 'challenge_id', 'evidence'])
       AND current_setting('engramport.erasure_decision', true) = (to_jsonb(NEW) ->> 'id') THEN
      RETURN NEW;
    END IF;
  END IF;
  RAISE EXCEPTION '% is a record and is never changed or deleted', TG_TABLE_NAME USING ERRCODE = '42501';
END
$$;
CREATE TRIGGER erasure_requests_kept BEFORE UPDATE OR DELETE ON memory.erasure_requests
  FOR EACH ROW EXECUTE FUNCTION memory.erasure_records_kept();
CREATE TRIGGER erasure_request_items_kept BEFORE UPDATE OR DELETE ON memory.erasure_request_items
  FOR EACH ROW EXECUTE FUNCTION memory.erasure_records_kept();
CREATE TRIGGER erasure_challenges_kept BEFORE UPDATE OR DELETE ON memory.erasure_challenges
  FOR EACH ROW EXECUTE FUNCTION memory.erasure_records_kept();
CREATE TRIGGER erasures_kept BEFORE UPDATE OR DELETE ON memory.erasures
  FOR EACH ROW EXECUTE FUNCTION memory.erasure_records_kept();
CREATE TRIGGER erasure_attempts_kept BEFORE UPDATE OR DELETE ON memory.erasure_attempts
  FOR EACH ROW EXECUTE FUNCTION memory.erasure_records_kept();
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['erasure_requests', 'erasure_request_items', 'erasure_challenges', 'erasures',
                           'erasure_attempts'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON memory.%I FOR EACH STATEMENT EXECUTE FUNCTION memory.erasure_records_kept()',
                   t || '_kept_all', t);
  END LOOP;
END
$$;
REVOKE ALL ON FUNCTION memory.erasure_records_kept() FROM PUBLIC;

-- ── Guards ──────────────────────────────────────────────────────────────────

-- 0020's lifecycle guard, now also for erasure, and taking a share lock on
-- the version a new row follows so a write racing an erasure waits for it.
CREATE OR REPLACE FUNCTION memory.memories_lifecycle_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  t memory.memories;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status = 'active' THEN
      IF NEW.supersedes_id IS NOT NULL THEN
        SELECT * INTO t FROM memory.memories x WHERE x.id = NEW.supersedes_id FOR SHARE;
        IF NOT FOUND OR t.status <> 'superseded' THEN
          RAISE EXCEPTION 'a new version can only follow a version that was already superseded' USING ERRCODE = '42501';
        END IF;
      END IF;
      RETURN NEW;
    END IF;
    IF NEW.status = 'proposed' THEN
      SELECT * INTO t FROM memory.memories x WHERE x.id = NEW.supersedes_id FOR SHARE;
      IF NOT FOUND OR t.status <> 'active' OR t.approval_state <> 'approved' OR t.namespace_id <> NEW.namespace_id THEN
        RAISE EXCEPTION 'a revision can be proposed only for the current approved version, in its own namespace'
          USING ERRCODE = '42501';
      END IF;
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'a memory is written active, or proposed as a revision' USING ERRCODE = '42501';
  END IF;

  -- Erasure (D-02): an erased memory stays erased, and a memory's text,
  -- metadata and key change only when it is erased, by memory.erase_chain.
  IF OLD.status = 'erased' THEN
    RAISE EXCEPTION 'an erased memory stays erased' USING ERRCODE = '42501';
  END IF;
  IF NEW.status = 'erased' OR NEW.content IS DISTINCT FROM OLD.content OR NEW.metadata IS DISTINCT FROM OLD.metadata
     OR NEW.dedup_key IS DISTINCT FROM OLD.dedup_key OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
     OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.namespace_id IS DISTINCT FROM OLD.namespace_id
     OR NEW.provenance_id IS DISTINCT FROM OLD.provenance_id THEN
    IF NEW.status = 'erased' AND NEW.supersedes_id IS NOT DISTINCT FROM OLD.supersedes_id
       AND NEW.kind = OLD.kind AND NEW.namespace_id = OLD.namespace_id AND NEW.provenance_id = OLD.provenance_id
       AND NEW.content = '' AND NEW.content_sha256 IS NULL AND NEW.dedup_key IS NULL AND NEW.metadata = '{}'
       AND EXISTS (SELECT 1 FROM memory.erasures e WHERE e.memory_id = NEW.id AND e.txid = txid_current()) THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'a memory''s text changes only when a person has it erased' USING ERRCODE = '42501';
  END IF;

  IF NEW.supersedes_id IS DISTINCT FROM OLD.supersedes_id THEN
    IF OLD.supersedes_id IS NOT NULL OR OLD.status <> 'active' THEN
      RAISE EXCEPTION 'the version a memory follows does not change' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO t FROM memory.memories x WHERE x.id = NEW.supersedes_id FOR SHARE;
    IF NOT FOUND OR t.status <> 'superseded' THEN
      RAISE EXCEPTION 'a new version can only follow a version that was already superseded' USING ERRCODE = '42501';
    END IF;
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'proposed' THEN
      RAISE EXCEPTION 'a memory is proposed only when it is written' USING ERRCODE = '42501';
    END IF;
    IF OLD.status = 'retracted'
       OR (OLD.status = 'superseded' AND (NEW.status <> 'retracted' OR OLD.approval_state = 'approved')) THEN
      RAISE EXCEPTION 'a % version stays that way', OLD.status USING ERRCODE = '42501';
    END IF;
    IF OLD.status = 'active' AND OLD.approval_state = 'approved' THEN
      IF NEW.status = 'superseded' AND EXISTS (
           SELECT 1 FROM memory.approvals a JOIN memory.memories p ON p.id = a.memory_id
           WHERE a.txid = txid_current() AND a.action = 'approve'
             AND p.supersedes_id = OLD.id AND p.namespace_id = OLD.namespace_id) THEN
        RETURN NEW;
      END IF;
      RAISE EXCEPTION 'an approved memory is replaced only when a person approves a revision of it'
        USING ERRCODE = '42501',
              HINT = 'propose a revision; the approved version stays current until a person approves it';
    END IF;
    IF OLD.status = 'proposed' THEN
      IF NEW.status = 'active' AND EXISTS (
           SELECT 1 FROM memory.approvals a
           WHERE a.memory_id = NEW.id AND a.txid = txid_current() AND a.action = 'approve') THEN
        RETURN NEW;
      END IF;
      IF NEW.status = 'retracted' AND OLD.approval_state <> 'approved' THEN
        RETURN NEW;
      END IF;
      RAISE EXCEPTION 'a proposed revision becomes current only when a person approves it' USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

-- The approval records keep their shape; erasure may clear only the digest of
-- the text it erases, in its own transaction.
CREATE OR REPLACE FUNCTION memory.approval_records_append_only() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'approvals'
     AND OLD.content_sha256 IS NOT NULL AND NEW.content_sha256 IS NULL
     AND (to_jsonb(NEW) - 'content_sha256') = (to_jsonb(OLD) - 'content_sha256')
     AND EXISTS (SELECT 1 FROM memory.erasures e WHERE e.memory_id = OLD.memory_id AND e.txid = txid_current()) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION '% is a record and does not change', TG_TABLE_NAME USING ERRCODE = '42501';
END
$$;
CREATE OR REPLACE FUNCTION memory.approval_record_kept() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'approval_challenges'
     AND OLD.content_sha256 IS NOT NULL AND NEW.content_sha256 IS NULL
     AND (to_jsonb(NEW) - 'content_sha256') = (to_jsonb(OLD) - 'content_sha256')
     AND EXISTS (SELECT 1 FROM memory.erasures e WHERE e.memory_id = OLD.memory_id AND e.txid = txid_current()) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION '% is a record and is never changed or deleted', TG_TABLE_NAME USING ERRCODE = '42501';
END
$$;

-- Nothing derived attaches to an erased memory. The share lock makes a write
-- racing an erasure wait for it and then see the erasure.
CREATE FUNCTION memory.derived_rows_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_ids uuid[];
  v uuid;
BEGIN
  -- Each branch names only fields its own table has.
  IF TG_TABLE_NAME = 'memory_links' THEN
    v_ids := ARRAY[NEW.from_memory_id, NEW.to_memory_id];
  ELSIF TG_TABLE_NAME = 'relations' THEN
    v_ids := ARRAY[NEW.evidence_memory_id];
  ELSE
    v_ids := ARRAY[NEW.memory_id];
  END IF;
  FOREACH v IN ARRAY v_ids LOOP
    CONTINUE WHEN v IS NULL;
    PERFORM 1 FROM memory.memories m WHERE m.id = v AND m.status <> 'erased' FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'this memory was erased' USING ERRCODE = '55000';
    END IF;
  END LOOP;
  RETURN NEW;
END
$$;
CREATE TRIGGER memory_embeddings_not_erased BEFORE INSERT ON memory.memory_embeddings
  FOR EACH ROW EXECUTE FUNCTION memory.derived_rows_guard();
CREATE TRIGGER entity_mentions_not_erased BEFORE INSERT ON memory.entity_mentions
  FOR EACH ROW EXECUTE FUNCTION memory.derived_rows_guard();
CREATE TRIGGER memory_links_not_erased BEFORE INSERT ON memory.memory_links
  FOR EACH ROW EXECUTE FUNCTION memory.derived_rows_guard();
CREATE TRIGGER relations_not_erased BEFORE INSERT ON memory.relations
  FOR EACH ROW EXECUTE FUNCTION memory.derived_rows_guard();
REVOKE ALL ON FUNCTION memory.derived_rows_guard() FROM PUBLIC;

-- ── Erasing ─────────────────────────────────────────────────────────────────

-- Every version connected to a memory by supersession, in either direction.
CREATE FUNCTION memory.erasure_chain(p_memory_id uuid) RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  WITH RECURSIVE c(id) AS (
    SELECT p_memory_id
    UNION
    SELECT x.id FROM c JOIN memory.memories m ON m.id = c.id
      JOIN memory.memories x ON x.supersedes_id = m.id OR x.id = m.supersedes_id
  )
  SELECT array_agg(c.id ORDER BY c.id) FROM c JOIN memory.memories m ON m.id = c.id
$$;

-- Erase every version of one memory. Locks the whole chain first, and again
-- if it grew while waiting, so no version can be added or changed under it.
-- Idempotent: versions already erased are skipped. Returns what was removed.
CREATE FUNCTION memory.erase_chain(p_memory_id uuid, p_request_id uuid, p_source text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_ids uuid[];
  v_new uuid[];
  v_todo uuid[];
  v_ents uuid[];
  n_emb bigint; n_men bigint; n_lnk bigint; n_rel bigint; n_ent bigint; n_apr bigint; n_chl bigint;
BEGIN
  v_ids := memory.erasure_chain(p_memory_id);
  IF v_ids IS NULL THEN
    RAISE EXCEPTION 'memory not found' USING ERRCODE = 'P0002';
  END IF;
  LOOP
    PERFORM 1 FROM memory.memories m WHERE m.id = ANY (v_ids) ORDER BY m.id FOR UPDATE;
    v_new := memory.erasure_chain(p_memory_id);
    EXIT WHEN v_new = v_ids;
    v_ids := v_new;
  END LOOP;
  SELECT array_agg(m.id ORDER BY m.id) INTO v_todo FROM memory.memories m
  WHERE m.id = ANY (v_ids) AND m.status <> 'erased';
  IF v_todo IS NULL THEN
    RETURN jsonb_build_object('versions', 0, 'embeddings', 0, 'mentions', 0, 'links', 0, 'relations', 0,
                              'entities', 0, 'approval_digests', 0, 'challenge_digests', 0);
  END IF;

  INSERT INTO memory.erasures (memory_id, namespace_id, request_id, source)
  SELECT m.id, m.namespace_id, p_request_id, p_source FROM memory.memories m WHERE m.id = ANY (v_todo);

  DELETE FROM memory.memory_embeddings WHERE memory_id = ANY (v_todo);
  GET DIAGNOSTICS n_emb = ROW_COUNT;
  WITH d AS (DELETE FROM memory.entity_mentions WHERE memory_id = ANY (v_todo) RETURNING entity_id)
  SELECT count(*), array_agg(DISTINCT entity_id) INTO n_men, v_ents FROM d;
  DELETE FROM memory.memory_links WHERE from_memory_id = ANY (v_todo) OR to_memory_id = ANY (v_todo);
  GET DIAGNOSTICS n_lnk = ROW_COUNT;
  WITH d AS (DELETE FROM memory.relations WHERE evidence_memory_id = ANY (v_todo)
             RETURNING source_entity_id, target_entity_id)
  SELECT n_men, coalesce(v_ents, '{}') || coalesce(array_agg(source_entity_id) || array_agg(target_entity_id), '{}'),
         count(*)
  INTO n_men, v_ents, n_rel FROM d;
  -- Extracted entities this memory alone pointed at go with it. Entities an
  -- agent asserted are its own claims, kept unless erased in their own right.
  WITH orphan AS (
    SELECT e.id FROM memory.entities e
    WHERE e.id = ANY (v_ents) AND e.origin = 'extracted'
      AND NOT EXISTS (SELECT 1 FROM memory.entity_mentions x WHERE x.entity_id = e.id)
      AND NOT EXISTS (SELECT 1 FROM memory.relations r WHERE r.source_entity_id = e.id OR r.target_entity_id = e.id)
  ), a AS (DELETE FROM memory.entity_aliases WHERE entity_id IN (SELECT id FROM orphan))
  DELETE FROM memory.entities WHERE id IN (SELECT id FROM orphan);
  GET DIAGNOSTICS n_ent = ROW_COUNT;

  UPDATE memory.provenance p SET source_ref = NULL, claimed = '{}', content_sha256 = NULL
  FROM memory.memories m WHERE m.id = ANY (v_todo) AND p.id = m.provenance_id;
  UPDATE memory.approvals SET content_sha256 = NULL WHERE memory_id = ANY (v_todo) AND content_sha256 IS NOT NULL;
  GET DIAGNOSTICS n_apr = ROW_COUNT;
  UPDATE memory.approval_challenges SET content_sha256 = NULL
  WHERE memory_id = ANY (v_todo) AND content_sha256 IS NOT NULL;
  GET DIAGNOSTICS n_chl = ROW_COUNT;
  UPDATE memory.memories
  SET content = '', metadata = '{}', dedup_key = NULL, content_sha256 = NULL, status = 'erased'
  WHERE id = ANY (v_todo);

  RETURN jsonb_build_object('versions', cardinality(v_todo), 'embeddings', n_emb, 'mentions', n_men,
                            'links', n_lnk, 'relations', n_rel, 'entities', n_ent,
                            'approval_digests', n_apr, 'challenge_digests', n_chl);
END
$$;
REVOKE ALL ON FUNCTION memory.erasure_chain(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.erase_chain(uuid, uuid, text) FROM PUBLIC;

-- Nothing of these versions is left anywhere retrievable.
CREATE FUNCTION memory.erasure_verified(p_ids uuid[]) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT NOT EXISTS (SELECT 1 FROM memory.memories m WHERE m.id = ANY (p_ids)
                       AND (m.status <> 'erased' OR m.content <> '' OR m.content_sha256 IS NOT NULL
                            OR m.dedup_key IS NOT NULL OR m.metadata <> '{}' OR m.fts <> ''::tsvector))
     AND NOT EXISTS (SELECT 1 FROM memory.memory_embeddings x WHERE x.memory_id = ANY (p_ids))
     AND NOT EXISTS (SELECT 1 FROM memory.entity_mentions x WHERE x.memory_id = ANY (p_ids))
     AND NOT EXISTS (SELECT 1 FROM memory.memory_links x WHERE x.from_memory_id = ANY (p_ids) OR x.to_memory_id = ANY (p_ids))
     AND NOT EXISTS (SELECT 1 FROM memory.relations x WHERE x.evidence_memory_id = ANY (p_ids))
     AND NOT EXISTS (SELECT 1 FROM memory.approvals x WHERE x.memory_id = ANY (p_ids) AND x.content_sha256 IS NOT NULL)
     AND NOT EXISTS (SELECT 1 FROM memory.approval_challenges x WHERE x.memory_id = ANY (p_ids) AND x.content_sha256 IS NOT NULL)
     AND NOT EXISTS (SELECT 1 FROM memory.memories m JOIN memory.provenance p ON p.id = m.provenance_id
                     WHERE m.id = ANY (p_ids) AND (p.source_ref IS NOT NULL OR p.claimed <> '{}' OR p.content_sha256 IS NOT NULL))
$$;
REVOKE ALL ON FUNCTION memory.erasure_verified(uuid[]) FROM PUBLIC;

-- ── Asking ──────────────────────────────────────────────────────────────────

-- An agent (or any writer) asks for up to 100 memories in its key's own
-- namespace to be erased. Nothing is erased until a person decides.
CREATE FUNCTION memory.request_erasure(p_memory_ids uuid[], p_reason memory.erasure_reason) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  k record;
  v_ids uuid[];
  v_id uuid;
BEGIN
  SELECT * INTO k FROM memory.current_key();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no valid key for this transaction' USING ERRCODE = '42501';
  END IF;
  IF NOT ('write' = ANY (k.scopes)) THEN
    RAISE EXCEPTION 'this key is read-only' USING ERRCODE = '42501';
  END IF;
  IF p_reason IS NULL THEN
    RAISE EXCEPTION 'say why: owner_request, stored_in_error or legal' USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(DISTINCT x) INTO v_ids FROM unnest(p_memory_ids) x WHERE x IS NOT NULL;
  IF v_ids IS NULL THEN
    RAISE EXCEPTION 'name at least one memory' USING ERRCODE = '22023';
  END IF;
  IF cardinality(v_ids) > 100 THEN
    RAISE EXCEPTION 'one request names at most 100 memories' USING ERRCODE = '22023';
  END IF;
  IF EXISTS (SELECT 1 FROM unnest(v_ids) x
             WHERE NOT EXISTS (SELECT 1 FROM memory.memories m WHERE m.id = x
                                 AND m.namespace_id IN (SELECT memory.readable_namespaces()))) THEN
    RAISE EXCEPTION 'memory not found' USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (SELECT 1 FROM memory.memories m WHERE m.id = ANY (v_ids) AND m.namespace_id <> k.namespace_id) THEN
    RAISE EXCEPTION 'only memories in this key''s own namespace can be put up for erasure' USING ERRCODE = '42501';
  END IF;
  IF EXISTS (SELECT 1 FROM memory.memories m WHERE m.id = ANY (v_ids) AND m.status = 'erased') THEN
    RAISE EXCEPTION 'a memory named was already erased' USING ERRCODE = '55000';
  END IF;
  INSERT INTO memory.erasure_requests (namespace_id, reason, requested_by_actor_id, api_key_id)
  VALUES (k.namespace_id, p_reason, k.actor_id, k.api_key_id)
  RETURNING id INTO v_id;
  INSERT INTO memory.erasure_request_items (request_id, memory_id) SELECT v_id, x FROM unnest(v_ids) x;
  RETURN v_id;
END
$$;

-- ── Deciding ────────────────────────────────────────────────────────────────

-- Whether this authority lets this person erase what this request names: a
-- valid grant made to them directly (an owner, not a delegate), over the
-- request's namespace, covering the claim type of every version named.
CREATE FUNCTION memory.erasure_authority_covers(p_authority uuid, p_actor uuid, p_request_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT coalesce((
    SELECT a.actor_id = p_actor AND a.parent_id IS NULL
       AND a.scope = memory.approval_scope_for(r.namespace_id)
       AND a.namespace_id IN (SELECT memory.namespace_and_ancestors(r.namespace_id))
       AND memory.approval_authority_valid(a.id)
       AND (a.claim_types IS NULL OR NOT EXISTS (
             SELECT 1 FROM memory.erasure_request_items i
             CROSS JOIN LATERAL unnest(memory.erasure_chain(i.memory_id)) v(id)
             JOIN memory.memories m ON m.id = v.id
             WHERE i.request_id = r.id AND NOT (m.claim_type = ANY (a.claim_types))))
    FROM memory.approval_authorities a, memory.erasure_requests r
    WHERE a.id = p_authority AND r.id = p_request_id), false)
$$;
REVOKE ALL ON FUNCTION memory.erasure_authority_covers(uuid, uuid, uuid) FROM PUBLIC;

-- The authority under which this person may erase what this request names, or NULL.
CREATE FUNCTION memory.erasure_authority_for(p_actor uuid, p_request_id uuid) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT a.id FROM memory.approval_authorities a
  WHERE a.actor_id = p_actor AND a.parent_id IS NULL
    AND memory.erasure_authority_covers(a.id, p_actor, p_request_id)
  ORDER BY a.created_at
  LIMIT 1
$$;
REVOKE ALL ON FUNCTION memory.erasure_authority_for(uuid, uuid) FROM PUBLIC;

-- The digest of what a request names, which the challenge binds.
CREATE FUNCTION memory.erasure_items_sha256(p_request_id uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT encode(sha256(convert_to(p_request_id::text || ':' || string_agg(i.memory_id::text, ',' ORDER BY i.memory_id), 'UTF8')), 'hex')
  FROM memory.erasure_request_items i WHERE i.request_id = p_request_id
$$;
REVOKE ALL ON FUNCTION memory.erasure_items_sha256(uuid) FROM PUBLIC;

-- Step 1, the preview: what the request would erase, one row per memory
-- named, with the text and how much would go with it. Someone with no
-- authority gets the same answer whether or not the request exists.
CREATE FUNCTION memory.erasure_review(p_user_id uuid, p_session_id uuid, p_request_id uuid)
RETURNS TABLE (request_id uuid, namespace_path text, reason memory.erasure_reason, state memory.erasure_state,
               requested_by text, requested_at timestamptz, items_sha256 text, memory_id uuid,
               kind memory.memory_kind, claim_type memory.claim_type, status memory.memory_status,
               approval_state memory.approval_state, content text, versions integer, embeddings bigint,
               mentions bigint, links bigint, relations bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid := memory.unspent_human_sign_in(p_user_id, p_session_id);
BEGIN
  IF memory.erasure_authority_for(v_actor, p_request_id) IS NULL THEN
    RAISE EXCEPTION 'request not found, or you have no authority to erase in it' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT r.id, n.path, r.reason, r.state, a.slug, r.created_at, memory.erasure_items_sha256(r.id), m.id,
         m.kind, m.claim_type, m.status, m.approval_state, m.content, cardinality(ch.ids),
         (SELECT count(*) FROM memory.memory_embeddings x WHERE x.memory_id = ANY (ch.ids)),
         (SELECT count(*) FROM memory.entity_mentions x WHERE x.memory_id = ANY (ch.ids)),
         (SELECT count(*) FROM memory.memory_links x WHERE x.from_memory_id = ANY (ch.ids) OR x.to_memory_id = ANY (ch.ids)),
         (SELECT count(*) FROM memory.relations x WHERE x.evidence_memory_id = ANY (ch.ids))
  FROM memory.erasure_requests r
  JOIN memory.namespaces n ON n.id = r.namespace_id
  JOIN memory.actors a ON a.id = r.requested_by_actor_id
  JOIN memory.erasure_request_items i ON i.request_id = r.id
  JOIN memory.memories m ON m.id = i.memory_id
  CROSS JOIN LATERAL (SELECT memory.erasure_chain(m.id) AS ids) ch
  WHERE r.id = p_request_id
  ORDER BY m.created_at, m.id;
END
$$;

-- Step 2: the person has seen the preview and confirms. The secret comes back
-- once and is never stored, only its hash.
CREATE FUNCTION memory.issue_erasure_challenge(p_user_id uuid, p_session_id uuid, p_request_id uuid,
                                               p_items_sha256 text)
RETURNS TABLE (challenge_id uuid, secret text, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  v_authority uuid;
  r memory.erasure_requests;
  v_secret bytea;
  v_id uuid;
  v_expires timestamptz;
BEGIN
  IF p_items_sha256 IS NULL OR p_items_sha256 !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'pass the digest of the request you were shown, as 64 lowercase hex digits' USING ERRCODE = '22023';
  END IF;
  v_actor := memory.unspent_human_sign_in(p_user_id, p_session_id);
  v_authority := memory.erasure_authority_for(v_actor, p_request_id);
  IF v_authority IS NULL THEN
    RAISE EXCEPTION 'request not found, or you have no authority to erase in it' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO r FROM memory.erasure_requests x WHERE x.id = p_request_id;
  IF r.state <> 'proposed' THEN
    RAISE EXCEPTION 'this erasure was already carried out' USING ERRCODE = '55000';
  END IF;
  IF memory.erasure_items_sha256(r.id) <> p_items_sha256 THEN
    RAISE EXCEPTION 'this is not the request you were shown' USING ERRCODE = '55000';
  END IF;
  v_secret := uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid());
  v_expires := now() + interval '10 minutes';
  BEGIN
    INSERT INTO memory.erasure_challenges (request_id, actor_id, authority_id, items_sha256, secret_sha256,
        sign_in_hash, expires_at)
    VALUES (r.id, v_actor, v_authority, p_items_sha256, sha256(v_secret), sha256(uuid_send(p_session_id)), v_expires)
    RETURNING id INTO v_id;
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'this sign-in was already used; sign in again' USING ERRCODE = '42501';
  END;
  RETURN QUERY SELECT v_id, encode(v_secret, 'hex'), v_expires;
END
$$;

-- Step 3: spend the sign-in and the challenge, re-check the authority, erase
-- everything the request names, verify nothing is left, and record the
-- evidence. All of it, or none of it.
CREATE FUNCTION memory.decide_erasure_challenge(p_user_id uuid, p_session_id uuid, p_challenge_id uuid,
                                                p_secret text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  c memory.erasure_challenges;
  r memory.erasure_requests;
  v_link uuid;
  v_chain_expires timestamptz;
  l record;
  i record;
  v_counts jsonb := '{}';
  v_part jsonb;
  v_ids uuid[] := '{}';
  v_key text;
BEGIN
  IF p_secret IS NULL OR p_secret !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'pass the challenge secret, as 64 lowercase hex digits' USING ERRCODE = '22023';
  END IF;
  v_actor := memory.consume_human_sign_in(p_user_id, p_session_id, 'erase');

  SELECT * INTO c FROM memory.erasure_challenges x WHERE x.id = p_challenge_id FOR UPDATE;
  IF NOT FOUND OR c.actor_id <> v_actor
     OR c.sign_in_hash <> sha256(uuid_send(p_session_id))
     OR c.secret_sha256 <> sha256(decode(p_secret, 'hex')) THEN
    RAISE EXCEPTION 'no such challenge for this sign-in' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO r FROM memory.erasure_requests x WHERE x.id = c.request_id FOR UPDATE;
  IF r.state <> 'proposed' THEN
    RAISE EXCEPTION 'this erasure was already carried out' USING ERRCODE = '55000';
  END IF;
  IF c.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'this challenge has expired; review the request again' USING ERRCODE = '55000';
  END IF;

  -- Hold the authority chain and its holders still until the erasure is
  -- recorded, so a revocation racing it is seen.
  v_link := c.authority_id;
  WHILE v_link IS NOT NULL LOOP
    SELECT a.id, a.parent_id, a.actor_id, a.expires_at INTO l
    FROM memory.approval_authorities a WHERE a.id = v_link FOR SHARE;
    PERFORM 1 FROM memory.actors x WHERE x.id = l.actor_id FOR SHARE;
    v_chain_expires := least(v_chain_expires, l.expires_at);
    v_link := l.parent_id;
  END LOOP;
  IF NOT memory.erasure_authority_covers(c.authority_id, v_actor, r.id) THEN
    RAISE EXCEPTION 'the authority this challenge was issued under is no longer valid' USING ERRCODE = '55000';
  END IF;
  IF memory.erasure_items_sha256(r.id) <> c.items_sha256 THEN
    RAISE EXCEPTION 'this is not the request you were shown' USING ERRCODE = '55000';
  END IF;

  FOR i IN SELECT x.memory_id FROM memory.erasure_request_items x WHERE x.request_id = r.id ORDER BY x.memory_id LOOP
    v_part := memory.erase_chain(i.memory_id, r.id, 'request');
    FOR v_key IN SELECT jsonb_object_keys(v_part) LOOP
      v_counts := jsonb_set(v_counts, ARRAY[v_key],
                            to_jsonb(coalesce((v_counts ->> v_key)::bigint, 0) + (v_part ->> v_key)::bigint));
    END LOOP;
    v_ids := v_ids || memory.erasure_chain(i.memory_id);
  END LOOP;
  IF NOT memory.erasure_verified(v_ids) THEN
    RAISE EXCEPTION 'erasure could not be verified; nothing was changed' USING ERRCODE = 'XX000';
  END IF;

  IF c.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'this challenge has expired; review the request again' USING ERRCODE = '55000';
  END IF;
  -- Every version is locked now, so this is the final word on what was named.
  IF v_chain_expires <= clock_timestamp() OR NOT memory.erasure_authority_covers(c.authority_id, v_actor, r.id) THEN
    RAISE EXCEPTION 'the authority this challenge was issued under does not cover everything erased' USING ERRCODE = '55000';
  END IF;

  v_counts := v_counts || jsonb_build_object('verified', true, 'memories_named', cardinality(v_ids));
  PERFORM set_config('engramport.erasure_decision', r.id::text, true);
  UPDATE memory.erasure_requests
  SET state = 'completed', completed_at = clock_timestamp(), decided_by_actor_id = v_actor,
      authority_id = c.authority_id, challenge_id = c.id, evidence = v_counts
  WHERE id = r.id;
  PERFORM set_config('engramport.erasure_decision', '', true);
  RETURN v_counts;
END
$$;

-- A failed attempt rolls back everything, so the server notes it afterwards:
-- which request, when, and the error class. The note changes nothing else.
CREATE FUNCTION memory.note_erasure_failure(p_request_id uuid, p_sqlstate text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF p_sqlstate IS NULL OR p_sqlstate !~ '^[0-9A-Z]{5}$' THEN
    RAISE EXCEPTION 'pass a five-character SQLSTATE' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM memory.erasure_requests r WHERE r.id = p_request_id AND r.state = 'proposed') THEN
    RAISE EXCEPTION 'no open erasure request with that id' USING ERRCODE = 'P0002';
  END IF;
  INSERT INTO memory.erasure_attempts (request_id, sqlstate) VALUES (p_request_id, p_sqlstate);
END
$$;

-- ── Restoring ───────────────────────────────────────────────────────────────

-- After a restore from a backup taken before some erasures, re-erase every
-- memory in the ledger of tombstones kept outside the database. Idempotent.
-- For the database owner only, as a step of the restore runbook: not the app,
-- and not the content-blind admin, who must never be able to destroy content.
CREATE FUNCTION memory.reapply_erasures(p_memory_ids uuid[]) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v uuid;
  v_done integer := 0;
  v_missing integer := 0;
  v_part jsonb;
BEGIN
  FOREACH v IN ARRAY coalesce(p_memory_ids, '{}') LOOP
    IF NOT EXISTS (SELECT 1 FROM memory.memories m WHERE m.id = v) THEN
      v_missing := v_missing + 1;
      CONTINUE;
    END IF;
    v_part := memory.erase_chain(v, NULL, 'restore');
    v_done := v_done + (v_part ->> 'versions')::integer;
  END LOOP;
  RETURN jsonb_build_object('versions_erased', v_done, 'not_in_this_database', v_missing);
END
$$;
REVOKE ALL ON FUNCTION memory.reapply_erasures(uuid[]) FROM PUBLIC;

-- ── Access ──────────────────────────────────────────────────────────────────

ALTER TABLE memory.erasure_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.erasure_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.erasure_request_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.erasure_request_items FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.erasure_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.erasure_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.erasures ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.erasures FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.erasure_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.erasure_attempts FORCE ROW LEVEL SECURITY;

-- The admin reads who asked, who decided, when, under which authority, what
-- was counted, and the tombstones: ids and times, never text or secrets.
GRANT SELECT ON memory.erasure_requests, memory.erasure_request_items, memory.erasures, memory.erasure_attempts
  TO engramport_admin;
GRANT SELECT (id, request_id, actor_id, authority_id, issued_at, expires_at) ON memory.erasure_challenges
  TO engramport_admin;
CREATE POLICY erasure_requests_admin ON memory.erasure_requests FOR SELECT TO engramport_admin USING (true);
CREATE POLICY erasure_request_items_admin ON memory.erasure_request_items FOR SELECT TO engramport_admin USING (true);
CREATE POLICY erasure_challenges_admin ON memory.erasure_challenges FOR SELECT TO engramport_admin USING (true);
CREATE POLICY erasures_admin ON memory.erasures FOR SELECT TO engramport_admin USING (true);
CREATE POLICY erasure_attempts_admin ON memory.erasure_attempts FOR SELECT TO engramport_admin USING (true);

REVOKE ALL ON FUNCTION memory.request_erasure(uuid[], memory.erasure_reason) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.erasure_review(uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.issue_erasure_challenge(uuid, uuid, uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.decide_erasure_challenge(uuid, uuid, uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.note_erasure_failure(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.request_erasure(uuid[], memory.erasure_reason),
  memory.erasure_review(uuid, uuid, uuid), memory.issue_erasure_challenge(uuid, uuid, uuid, text),
  memory.decide_erasure_challenge(uuid, uuid, uuid, text), memory.note_erasure_failure(uuid, text)
  TO engramport_app;

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
