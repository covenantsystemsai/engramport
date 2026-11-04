-- Approval events: asking for approval, and a person approving or rejecting.
-- Forward-only; applied by db/migrate.sh in one transaction.
--
-- This is the one way a memory's approval_state changes (0014 refused every
-- change until now). Founder decision D-03, rules 4, 7, 8, 9 and 10:
--
--   * An agent, or any writer, asks for approval of a memory in its own
--     namespace. That marks it pending. Asking approves nothing.
--   * A person approves or rejects with their own fresh, single-use Google
--     sign-in (0015). No key or token is proof of a person, so an agent cannot
--     approve its own memory or stand in for a person.
--   * The decision binds to the exact memory id (each version is its own row,
--     so the id pins the version), its content digest, the action and the
--     namespace. The person passes the digest of the text they were shown; if
--     the memory is no longer that text, or no longer the active version,
--     nothing is recorded.
--   * A changed memory is a new version with a new id, which starts unapproved
--     (0014). A decision is made once per version and never edited.
--   * The authority is checked at the moment of the decision, up its whole
--     delegation chain. A revoked or expired authority approves nothing from
--     then on. Nothing is held for later use: a decision applies at once or not
--     at all, so there is no unused approval to replay.
--   * The scope comes from where the memory lives:
--       a client cell        cell_knowledge, granted on that cell
--       a company cell       company_governance, on that cell or above it
--       any tower or city    promotion, on that tower or city or above it
--     So tower and city knowledge always needs its own promotion authority.
--   * The admin reads who decided, what, where and when. Never the text, and
--     not its digest either.

CREATE TYPE memory.approval_action AS ENUM ('approve', 'reject');

-- The scope a memory in this namespace is approved under.
CREATE FUNCTION memory.approval_scope_for(p_namespace_id uuid) RETURNS memory.approval_scope
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT CASE
    WHEN n.level = 'cell' AND n.purpose = 'client' THEN 'cell_knowledge'::memory.approval_scope
    WHEN n.level = 'cell' AND n.purpose = 'company' THEN 'company_governance'::memory.approval_scope
    ELSE 'promotion'::memory.approval_scope
  END
  FROM memory.namespaces n WHERE n.id = p_namespace_id
$$;

-- A namespace and every namespace above it.
CREATE FUNCTION memory.namespace_and_ancestors(p_namespace_id uuid) RETURNS SETOF uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  WITH RECURSIVE up AS (
    SELECT n.id, n.parent_id FROM memory.namespaces n WHERE n.id = p_namespace_id
    UNION ALL
    SELECT p.id, p.parent_id FROM memory.namespaces p JOIN up ON p.id = up.parent_id
  )
  SELECT id FROM up
$$;

-- One request per memory version. Asking twice returns the first request.
CREATE TABLE memory.approval_requests (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  memory_id uuid NOT NULL UNIQUE REFERENCES memory.memories(id),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  requested_by_actor_id uuid NOT NULL REFERENCES memory.actors(id),
  api_key_id uuid NOT NULL REFERENCES memory.api_keys(id),
  txid bigint NOT NULL DEFAULT txid_current(),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX approval_requests_namespace ON memory.approval_requests (namespace_id, created_at);
CREATE INDEX approval_requests_actor ON memory.approval_requests (requested_by_actor_id);
CREATE INDEX approval_requests_key ON memory.approval_requests (api_key_id);

-- One decision per memory version.
CREATE TABLE memory.approvals (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  memory_id uuid NOT NULL UNIQUE REFERENCES memory.memories(id),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  action memory.approval_action NOT NULL,
  scope memory.approval_scope NOT NULL,
  claim_type memory.claim_type NOT NULL,
  content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  decided_by_actor_id uuid NOT NULL REFERENCES memory.actors(id),
  authority_id uuid NOT NULL REFERENCES memory.approval_authorities(id),
  request_id uuid REFERENCES memory.approval_requests(id),
  sign_in_hash bytea NOT NULL UNIQUE REFERENCES memory.human_sign_ins_used(session_hash),
  txid bigint NOT NULL DEFAULT txid_current(),
  decided_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX approvals_namespace ON memory.approvals (namespace_id, decided_at);
CREATE INDEX approvals_actor ON memory.approvals (decided_by_actor_id);
CREATE INDEX approvals_authority ON memory.approvals (authority_id);
CREATE INDEX approvals_request ON memory.approvals (request_id) WHERE request_id IS NOT NULL;

-- Both are a record: rows are never changed or removed, by any role.
CREATE FUNCTION memory.approval_records_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION '% is a record and does not change', TG_TABLE_NAME USING ERRCODE = '42501';
END
$$;
CREATE TRIGGER approval_requests_append_only BEFORE UPDATE OR DELETE ON memory.approval_requests
  FOR EACH ROW EXECUTE FUNCTION memory.approval_records_append_only();
CREATE TRIGGER approvals_append_only BEFORE UPDATE OR DELETE ON memory.approvals
  FOR EACH ROW EXECUTE FUNCTION memory.approval_records_append_only();
REVOKE ALL ON FUNCTION memory.approval_records_append_only() FROM PUBLIC;

-- The trust guard from 0014, with one way through: approval_state may move
-- only to match an event recorded for this memory in this same transaction.
-- Claim type and verification still never change in place.
CREATE OR REPLACE FUNCTION memory.memories_trust_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.approval_state <> 'none' OR NEW.verification_state <> 'unverified' THEN
      RAISE EXCEPTION 'a write cannot approve or verify a memory'
        USING ERRCODE = '42501',
              HINT = 'approval and verification are recorded as their own events, not set by the writer';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.verification_state IS DISTINCT FROM OLD.verification_state
     OR NEW.claim_type IS DISTINCT FROM OLD.claim_type THEN
    RAISE EXCEPTION 'claim type, approval and verification do not change in place'
      USING ERRCODE = '42501';
  END IF;
  IF NEW.approval_state IS DISTINCT FROM OLD.approval_state THEN
    IF OLD.approval_state = 'none' AND NEW.approval_state = 'pending'
       AND EXISTS (SELECT 1 FROM memory.approval_requests r
                   WHERE r.memory_id = NEW.id AND r.txid = txid_current()) THEN
      RETURN NEW;
    END IF;
    IF OLD.approval_state IN ('none', 'pending') AND NEW.approval_state IN ('approved', 'rejected')
       AND EXISTS (SELECT 1 FROM memory.approvals a
                   WHERE a.memory_id = NEW.id AND a.txid = txid_current()
                     AND a.action = CASE NEW.approval_state WHEN 'approved' THEN 'approve'::memory.approval_action
                                                            ELSE 'reject'::memory.approval_action END) THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'claim type, approval and verification do not change in place'
      USING ERRCODE = '42501',
            HINT = 'a memory is approved or rejected only by a person, through memory.record_approval';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION memory.memories_trust_guard() FROM PUBLIC;

-- ── Asking ──────────────────────────────────────────────────────────────────

-- A writer asks for approval of an active memory in its key's own namespace.
-- Returns the request. Asking again for a pending memory returns the same one.
CREATE FUNCTION memory.request_approval(p_memory_id uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  k record;
  m record;
  v_id uuid;
BEGIN
  SELECT * INTO k FROM memory.current_key();
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no valid key for this transaction' USING ERRCODE = '42501';
  END IF;
  IF NOT ('write' = ANY (k.scopes)) THEN
    RAISE EXCEPTION 'this key is read-only' USING ERRCODE = '42501';
  END IF;
  SELECT mm.id, mm.namespace_id, mm.status, mm.approval_state INTO m
  FROM memory.memories mm WHERE mm.id = p_memory_id FOR UPDATE;
  IF NOT FOUND OR m.namespace_id NOT IN (SELECT memory.readable_namespaces()) THEN
    RAISE EXCEPTION 'memory not found' USING ERRCODE = 'P0002';
  END IF;
  IF m.namespace_id <> k.namespace_id THEN
    RAISE EXCEPTION 'only memories in this key''s own namespace can be put up for approval' USING ERRCODE = '42501';
  END IF;
  IF m.status <> 'active' THEN
    RAISE EXCEPTION 'only the active version of a memory can be put up for approval' USING ERRCODE = '55000';
  END IF;
  IF m.approval_state IN ('approved', 'rejected') THEN
    RAISE EXCEPTION 'this memory was already %; a changed version can be put up again', m.approval_state
      USING ERRCODE = '55000';
  END IF;
  SELECT r.id INTO v_id FROM memory.approval_requests r WHERE r.memory_id = p_memory_id;
  IF FOUND THEN
    RETURN v_id;
  END IF;
  INSERT INTO memory.approval_requests (memory_id, namespace_id, requested_by_actor_id, api_key_id)
  VALUES (p_memory_id, m.namespace_id, k.actor_id, k.api_key_id)
  RETURNING id INTO v_id;
  UPDATE memory.memories SET approval_state = 'pending' WHERE id = p_memory_id;
  RETURN v_id;
END
$$;

-- ── Deciding ────────────────────────────────────────────────────────────────

-- A person approves or rejects one memory version, with their own fresh
-- sign-in and the digest of the text they were shown. Returns the decision.
CREATE FUNCTION memory.record_approval(
  p_user_id uuid,
  p_session_id uuid,
  p_memory_id uuid,
  p_action memory.approval_action,
  p_content_sha256 text
) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  m record;
  v_scope memory.approval_scope;
  v_authority uuid;
  v_id uuid;
BEGIN
  IF p_action IS NULL THEN
    RAISE EXCEPTION 'say whether to approve or reject' USING ERRCODE = '22023';
  END IF;
  IF p_content_sha256 IS NULL OR p_content_sha256 !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'pass the sha256 of the text you were shown, as 64 lowercase hex digits' USING ERRCODE = '22023';
  END IF;
  v_actor := memory.consume_human_sign_in(p_user_id, p_session_id, 'approve');

  -- Whether the memory exists and whether this person may decide on it give
  -- the same answer, so someone without authority learns nothing about it.
  SELECT mm.id, mm.namespace_id, mm.status, mm.approval_state, mm.claim_type, mm.content_sha256 INTO m
  FROM memory.memories mm WHERE mm.id = p_memory_id FOR UPDATE;
  IF FOUND THEN
    v_scope := memory.approval_scope_for(m.namespace_id);
    SELECT a.id INTO v_authority
    FROM memory.approval_authorities a
    WHERE a.actor_id = v_actor
      AND a.scope = v_scope
      AND a.namespace_id IN (SELECT memory.namespace_and_ancestors(m.namespace_id))
      AND (a.claim_types IS NULL OR m.claim_type = ANY (a.claim_types))
      AND memory.approval_authority_valid(a.id)
    ORDER BY (a.parent_id IS NOT NULL), a.created_at
    LIMIT 1;
  END IF;
  IF v_authority IS NULL THEN
    RAISE EXCEPTION 'memory not found, or you have no valid authority to decide on it' USING ERRCODE = '42501';
  END IF;
  IF m.status <> 'active' THEN
    RAISE EXCEPTION 'this version is no longer active; review the current one' USING ERRCODE = '55000';
  END IF;
  IF m.approval_state IN ('approved', 'rejected') THEN
    RAISE EXCEPTION 'this memory was already %', m.approval_state USING ERRCODE = '55000';
  END IF;
  IF m.content_sha256 <> p_content_sha256 THEN
    RAISE EXCEPTION 'this memory is not the text you were shown' USING ERRCODE = '55000';
  END IF;

  INSERT INTO memory.approvals (memory_id, namespace_id, action, scope, claim_type, content_sha256,
      decided_by_actor_id, authority_id, request_id, sign_in_hash)
  VALUES (m.id, m.namespace_id, p_action, v_scope, m.claim_type, m.content_sha256, v_actor, v_authority,
      (SELECT r.id FROM memory.approval_requests r WHERE r.memory_id = m.id),
      sha256(uuid_send(p_session_id)))
  RETURNING id INTO v_id;
  UPDATE memory.memories
  SET approval_state = CASE p_action WHEN 'approve' THEN 'approved'::memory.approval_state
                                     ELSE 'rejected'::memory.approval_state END
  WHERE id = m.id;
  RETURN v_id;
END
$$;

-- ── Who sees what ───────────────────────────────────────────────────────────

ALTER TABLE memory.approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.approval_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.approvals FORCE ROW LEVEL SECURITY;

-- The server sees the trail for memories its key can read. It writes only
-- through the functions above.
GRANT SELECT (id, memory_id, namespace_id, requested_by_actor_id, created_at)
  ON memory.approval_requests TO engramport_app;
GRANT SELECT (id, memory_id, namespace_id, action, scope, decided_by_actor_id, decided_at)
  ON memory.approvals TO engramport_app;
CREATE POLICY approval_requests_app_read ON memory.approval_requests FOR SELECT TO engramport_app
  USING (namespace_id IN (SELECT memory.readable_namespaces()));
CREATE POLICY approvals_app_read ON memory.approvals FOR SELECT TO engramport_app
  USING (namespace_id IN (SELECT memory.readable_namespaces()));

-- The admin audits: who asked and who decided, what, where, under which
-- authority and when. No text, no digest, no sign-in.
GRANT SELECT (id, memory_id, namespace_id, requested_by_actor_id, api_key_id, created_at)
  ON memory.approval_requests TO engramport_admin;
GRANT SELECT (id, memory_id, namespace_id, action, scope, claim_type, decided_by_actor_id, authority_id,
              request_id, decided_at)
  ON memory.approvals TO engramport_admin;
CREATE POLICY approval_requests_admin_read ON memory.approval_requests FOR SELECT TO engramport_admin
  USING (true);
CREATE POLICY approvals_admin_read ON memory.approvals FOR SELECT TO engramport_admin
  USING (true);

REVOKE ALL ON FUNCTION memory.approval_scope_for(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.namespace_and_ancestors(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.request_approval(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.record_approval(uuid, uuid, uuid, memory.approval_action, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.request_approval(uuid) TO engramport_app;
GRANT EXECUTE ON FUNCTION memory.record_approval(uuid, uuid, uuid, memory.approval_action, text) TO engramport_app;

DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE ALL ON memory.approval_requests, memory.approvals FROM %I', r);
      EXECUTE format('REVOKE ALL ON FUNCTION memory.request_approval(uuid), '
                     'memory.record_approval(uuid, uuid, uuid, memory.approval_action, text), '
                     'memory.approval_scope_for(uuid), memory.namespace_and_ancestors(uuid) FROM %I', r);
    END IF;
  END LOOP;
END
$$;
