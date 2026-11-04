-- D-02.1 and D-02.1a: whole-cell erasure, started by the cell's owner and
-- confirmed by a different person holding the dedicated cell-erasure-confirmer
-- role. Forward-only; applied by db/migrate.sh in one transaction.
--
-- Founder decisions behind it:
--   D-02.1: "The authenticated namespace owner initiates the request. A
--     different authenticated human with explicitly assigned AN2B governance
--     authority must confirm after reviewing the impact preview. The initiator
--     cannot serve as the second approver."
--   D-02.1a (Nov 4): that authority is a dedicated cell-erasure-confirmer role,
--     "explicitly assigned to a named human, independently accepted through
--     authenticated sign-in, scoped to the relevant authority, expiring or
--     revocable, and separate from general memory-governance permissions."
--     "The confirmer has no implicit access to customer memory contents and
--     cannot initiate or approve their own erasure request." "Preserve
--     complete authorization and execution audit evidence without retaining
--     erased content."
--
-- The confirmer role (memory.cell_erasure_confirmers):
--   * The admin assigns it to one named, enabled person who belongs to AN2B
--     (holds an unrevoked sign-in membership of a company namespace), over a
--     scope (a namespace; it covers the cells at or under it), for at most a
--     year. The admin can revoke it.
--   * It counts only once that person accepts its exact terms with their own
--     fresh sign-in, and only while it is unrevoked, unexpired, and the person
--     is still enabled and still belongs to AN2B.
--   * It grants nothing else: no approval, no reading of memories. It is not
--     an approval authority and no approval authority makes someone a
--     confirmer.
--
-- A whole-cell erasure:
--   1. The owner previews it (counts only) and starts it with their own fresh
--      sign-in. "Owner" means a direct, unrestricted, valid approval authority
--      over the cell; a delegate or a grant holder can't start one. One open
--      request per cell; it lapses after 7 days.
--   2. While it is open the cell is frozen: nothing new (memories, revisions,
--      embeddings, graph rows) is written to it, so the operation confirmed is
--      the one previewed.
--   3. A confirmer whose role covers the cell, who is not the owner who started
--      it, reviews a fresh preview (counts and a digest of every object it will
--      erase, never content), takes a single-use challenge bound to that
--      digest, and confirms with their own fresh sign-in.
--   4. The decision spends the sign-in and challenge, holds the role, the
--      confirmer, the owner's authority chain and the cell still, checks
--      everything again by the wall clock, erases every memory version (with a
--      content-free tombstone each), every embedding and every graph row in the
--      cell, scrubs the cell's provenance of anything content-derived, verifies
--      nothing is left, and records the counts. All of it, or none of it.
-- The records name who started, who confirmed, under which authority and
-- role, the digest that was confirmed, and what was removed. None holds text
-- or a digest of text.

ALTER TABLE memory.human_sign_ins_used DROP CONSTRAINT human_sign_ins_used_purpose_check;
ALTER TABLE memory.human_sign_ins_used ADD CONSTRAINT human_sign_ins_used_purpose_check
  CHECK (purpose IN ('approve', 'delegate', 'revoke', 'connect', 'accept', 'erase', 'export', 'grant', 'restore',
                     'cell_erase', 'cell_confirm'));

-- ── The confirmer role ──────────────────────────────────────────────────────

CREATE TABLE memory.cell_erasure_confirmers (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  actor_id uuid NOT NULL REFERENCES memory.actors(id),
  scope_namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  assigned_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  accepted_at timestamptz,
  rejected_at timestamptz,
  decision_sign_in_hash bytea CHECK (octet_length(decision_sign_in_hash) = 32),
  revoked_at timestamptz,
  revoke_reason text CHECK (revoke_reason ~ '^[a-z][a-z0-9_]{0,39}$'),
  CHECK (expires_at > assigned_at AND expires_at <= assigned_at + interval '366 days'),
  CHECK (accepted_at IS NULL OR rejected_at IS NULL),
  CHECK ((accepted_at IS NULL AND rejected_at IS NULL) = (decision_sign_in_hash IS NULL)),
  CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE INDEX cell_erasure_confirmers_actor ON memory.cell_erasure_confirmers (actor_id);
CREATE INDEX cell_erasure_confirmers_scope ON memory.cell_erasure_confirmers (scope_namespace_id);

-- Whether a person belongs to AN2B: an enabled human with an unrevoked sign-in
-- membership of a company namespace.
CREATE FUNCTION memory.is_an2b_person(p_actor uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT EXISTS (
    SELECT 1 FROM memory.actors a
    JOIN memory.oauth_members m ON m.actor_id = a.id AND m.revoked_at IS NULL
    JOIN memory.namespaces n ON n.id = m.namespace_id AND n.purpose = 'company'
    WHERE a.id = p_actor AND a.kind = 'human' AND a.disabled_at IS NULL)
$$;
REVOKE ALL ON FUNCTION memory.is_an2b_person(uuid) FROM PUBLIC;
-- The role's guard runs as whoever writes the row, the admin included.
GRANT EXECUTE ON FUNCTION memory.is_an2b_person(uuid) TO engramport_admin;

-- A role is assigned by the admin to a person who belongs to AN2B, starts
-- undecided and unrevoked, and is then a record: decided once by the person
-- it names inside memory.decide_confirmer_role, and revoked once by the admin.
CREATE FUNCTION memory.confirmer_role_kept() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  v_terms text[] := ARRAY['accepted_at', 'rejected_at', 'decision_sign_in_hash', 'revoked_at', 'revoke_reason'];
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.accepted_at IS NOT NULL OR NEW.rejected_at IS NOT NULL OR NEW.decision_sign_in_hash IS NOT NULL
       OR NEW.revoked_at IS NOT NULL OR NEW.revoke_reason IS NOT NULL THEN
      RAISE EXCEPTION 'a confirmer role starts undecided and unrevoked' USING ERRCODE = '23514';
    END IF;
    IF NOT memory.is_an2b_person(NEW.actor_id) THEN
      RAISE EXCEPTION 'the cell-erasure-confirmer role goes only to an enabled person who belongs to AN2B'
        USING ERRCODE = '42501';
    END IF;
    NEW.assigned_at := now();
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE' AND (to_jsonb(NEW) - v_terms) = (to_jsonb(OLD) - v_terms) THEN
    IF OLD.accepted_at IS NULL AND OLD.rejected_at IS NULL AND OLD.revoked_at IS NULL
       AND (NEW.accepted_at IS NULL) <> (NEW.rejected_at IS NULL) AND NEW.decision_sign_in_hash IS NOT NULL
       AND NEW.revoked_at IS NULL AND NEW.revoke_reason IS NULL
       AND current_setting('engramport.confirmer_step', true) = OLD.id::text THEN
      RETURN NEW;
    END IF;
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
       AND NEW.accepted_at IS NOT DISTINCT FROM OLD.accepted_at AND NEW.rejected_at IS NOT DISTINCT FROM OLD.rejected_at
       AND NEW.decision_sign_in_hash IS NOT DISTINCT FROM OLD.decision_sign_in_hash
       AND current_user = 'engramport_admin' THEN
      NEW.revoked_at := now();
      RETURN NEW;
    END IF;
  END IF;
  RAISE EXCEPTION 'cell_erasure_confirmers is a record; a role is decided and revoked only through its own steps'
    USING ERRCODE = '42501';
END
$$;
CREATE TRIGGER cell_erasure_confirmers_kept BEFORE INSERT OR UPDATE OR DELETE ON memory.cell_erasure_confirmers
  FOR EACH ROW EXECUTE FUNCTION memory.confirmer_role_kept();
CREATE TRIGGER cell_erasure_confirmers_kept_all BEFORE TRUNCATE ON memory.cell_erasure_confirmers
  FOR EACH STATEMENT EXECUTE FUNCTION memory.confirmer_role_kept();
REVOKE ALL ON FUNCTION memory.confirmer_role_kept() FROM PUBLIC;

CREATE FUNCTION memory.confirmer_role_valid(p_role_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT coalesce((
    SELECT r.accepted_at IS NOT NULL AND r.rejected_at IS NULL AND r.revoked_at IS NULL
       AND r.expires_at > now() AND memory.is_an2b_person(r.actor_id)
    FROM memory.cell_erasure_confirmers r WHERE r.id = p_role_id), false)
$$;
REVOKE ALL ON FUNCTION memory.confirmer_role_valid(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.confirmer_role_valid(uuid) TO engramport_admin;

CREATE FUNCTION memory.confirmer_role_covers(p_role_id uuid, p_actor uuid, p_namespace_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT coalesce((
    SELECT r.actor_id = p_actor AND memory.confirmer_role_valid(r.id)
       AND r.scope_namespace_id IN (SELECT memory.namespace_and_ancestors(p_namespace_id))
    FROM memory.cell_erasure_confirmers r WHERE r.id = p_role_id), false)
$$;
REVOKE ALL ON FUNCTION memory.confirmer_role_covers(uuid, uuid, uuid) FROM PUBLIC;

CREATE FUNCTION memory.confirmer_role_for(p_actor uuid, p_namespace_id uuid) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT r.id FROM memory.cell_erasure_confirmers r
  WHERE r.actor_id = p_actor AND memory.confirmer_role_covers(r.id, p_actor, p_namespace_id)
  ORDER BY r.assigned_at
  LIMIT 1
$$;
REVOKE ALL ON FUNCTION memory.confirmer_role_for(uuid, uuid) FROM PUBLIC;

-- The fingerprint of a role's exact terms, which the person accepts.
CREATE FUNCTION memory.confirmer_role_sha256(p_role_id uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog SET timezone = 'UTC' AS $$
  SELECT encode(sha256(convert_to(jsonb_build_object(
           'role', 'cell-erasure-confirmer',
           'id', r.id,
           'holder', r.actor_id,
           'scope', n.path,
           'expires_at', to_char(r.expires_at, 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))::text, 'UTF8')), 'hex')
  FROM memory.cell_erasure_confirmers r JOIN memory.namespaces n ON n.id = r.scope_namespace_id
  WHERE r.id = p_role_id
$$;
REVOKE ALL ON FUNCTION memory.confirmer_role_sha256(uuid) FROM PUBLIC;

-- The roles waiting for this person's decision, with the exact terms.
CREATE FUNCTION memory.pending_confirmer_roles(p_user_id uuid, p_session_id uuid)
RETURNS TABLE (role_id uuid, scope_path text, assigned_at timestamptz, expires_at timestamptz, terms_sha256 text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid := memory.unspent_human_sign_in(p_user_id, p_session_id);
BEGIN
  RETURN QUERY
  SELECT r.id, n.path, r.assigned_at, r.expires_at, memory.confirmer_role_sha256(r.id)
  FROM memory.cell_erasure_confirmers r JOIN memory.namespaces n ON n.id = r.scope_namespace_id
  WHERE r.actor_id = v_actor AND r.accepted_at IS NULL AND r.rejected_at IS NULL AND r.revoked_at IS NULL
    AND r.expires_at > now()
  ORDER BY r.assigned_at;
END
$$;

-- The person accepts or rejects the role, with their own fresh sign-in,
-- against the fingerprint of the terms they were shown.
CREATE FUNCTION memory.decide_confirmer_role(p_user_id uuid, p_session_id uuid, p_role_id uuid, p_decision text,
                                             p_terms_sha256 text) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  r memory.cell_erasure_confirmers;
BEGIN
  IF p_decision IS NULL OR p_decision NOT IN ('accept', 'reject') THEN
    RAISE EXCEPTION 'decide accept or reject' USING ERRCODE = '22023';
  END IF;
  v_actor := memory.consume_human_sign_in(p_user_id, p_session_id, 'accept');
  SELECT * INTO r FROM memory.cell_erasure_confirmers x WHERE x.id = p_role_id FOR UPDATE;
  IF NOT FOUND OR r.actor_id <> v_actor THEN
    RAISE EXCEPTION 'no such role for you' USING ERRCODE = '42501';
  END IF;
  IF r.accepted_at IS NOT NULL OR r.rejected_at IS NOT NULL OR r.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'this role was already decided or revoked' USING ERRCODE = '55000';
  END IF;
  IF r.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'this role has expired' USING ERRCODE = '55000';
  END IF;
  IF p_terms_sha256 IS DISTINCT FROM memory.confirmer_role_sha256(r.id) THEN
    RAISE EXCEPTION 'these are not the terms you were shown' USING ERRCODE = '55000';
  END IF;
  PERFORM set_config('engramport.confirmer_step', r.id::text, true);
  UPDATE memory.cell_erasure_confirmers
  SET accepted_at = CASE WHEN p_decision = 'accept' THEN clock_timestamp() END,
      rejected_at = CASE WHEN p_decision = 'reject' THEN clock_timestamp() END,
      decision_sign_in_hash = sha256(uuid_send(p_session_id))
  WHERE id = r.id;
  PERFORM set_config('engramport.confirmer_step', '', true);
  RETURN p_decision || 'ed';
END
$$;

-- ── Requests ────────────────────────────────────────────────────────────────

CREATE TYPE memory.cell_erasure_state AS ENUM ('proposed', 'completed', 'cancelled');

CREATE TABLE memory.cell_erasure_requests (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  reason memory.erasure_reason NOT NULL,
  initiated_by_actor_id uuid NOT NULL REFERENCES memory.actors(id),
  authority_id uuid NOT NULL REFERENCES memory.approval_authorities(id),
  initiate_sign_in_hash bytea NOT NULL UNIQUE CHECK (octet_length(initiate_sign_in_hash) = 32),
  -- What the owner was shown when starting it: counts only.
  preview jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  state memory.cell_erasure_state NOT NULL DEFAULT 'proposed',
  confirmed_by_actor_id uuid REFERENCES memory.actors(id),
  confirmer_role_id uuid REFERENCES memory.cell_erasure_confirmers(id),
  challenge_id uuid UNIQUE,
  completed_at timestamptz,
  evidence jsonb,
  cancelled_at timestamptz,
  cancel_reason text CHECK (cancel_reason ~ '^[a-z][a-z0-9_]{0,39}$'),
  CHECK (expires_at > created_at),
  CHECK ((state = 'completed') = (completed_at IS NOT NULL AND confirmed_by_actor_id IS NOT NULL
                                  AND confirmer_role_id IS NOT NULL AND challenge_id IS NOT NULL AND evidence IS NOT NULL)),
  CHECK ((state = 'cancelled') = (cancelled_at IS NOT NULL AND cancel_reason IS NOT NULL)),
  CHECK (confirmed_by_actor_id IS DISTINCT FROM initiated_by_actor_id)
);
CREATE INDEX cell_erasure_requests_open ON memory.cell_erasure_requests (namespace_id) WHERE state = 'proposed';
CREATE INDEX cell_erasure_requests_ns ON memory.cell_erasure_requests (namespace_id, created_at);
CREATE INDEX cell_erasure_requests_initiator ON memory.cell_erasure_requests (initiated_by_actor_id);
CREATE INDEX cell_erasure_requests_authority ON memory.cell_erasure_requests (authority_id);
CREATE INDEX cell_erasure_requests_confirmer ON memory.cell_erasure_requests (confirmed_by_actor_id);
CREATE INDEX cell_erasure_requests_role ON memory.cell_erasure_requests (confirmer_role_id);

CREATE TABLE memory.cell_erasure_challenges (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  request_id uuid NOT NULL REFERENCES memory.cell_erasure_requests(id),
  actor_id uuid NOT NULL REFERENCES memory.actors(id),
  role_id uuid NOT NULL REFERENCES memory.cell_erasure_confirmers(id),
  -- A digest of the ids of every object the erasure removes: never content.
  objects_sha256 text NOT NULL CHECK (objects_sha256 ~ '^[0-9a-f]{64}$'),
  secret_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(secret_sha256) = 32),
  sign_in_hash bytea NOT NULL UNIQUE CHECK (octet_length(sign_in_hash) = 32),
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  CHECK (expires_at > issued_at)
);
CREATE INDEX cell_erasure_challenges_request ON memory.cell_erasure_challenges (request_id);
CREATE INDEX cell_erasure_challenges_actor ON memory.cell_erasure_challenges (actor_id);
CREATE INDEX cell_erasure_challenges_role ON memory.cell_erasure_challenges (role_id);
ALTER TABLE memory.cell_erasure_requests ADD CONSTRAINT cell_erasure_requests_challenge
  FOREIGN KEY (challenge_id) REFERENCES memory.cell_erasure_challenges(id);

-- Requests are records: completed once inside the decision, or cancelled
-- once by the admin, and nothing else. Challenges never change.
CREATE FUNCTION memory.cell_erasure_records_kept() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  v_done text[] := ARRAY['state', 'confirmed_by_actor_id', 'confirmer_role_id', 'challenge_id', 'completed_at', 'evidence'];
  v_cancel text[] := ARRAY['state', 'cancelled_at', 'cancel_reason'];
BEGIN
  -- Nested, so a field only requests have is read only for a request.
  IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'cell_erasure_requests' THEN
    IF to_jsonb(OLD) ->> 'state' = 'proposed' THEN
      IF to_jsonb(NEW) ->> 'state' = 'completed' AND (to_jsonb(NEW) - v_done) = (to_jsonb(OLD) - v_done)
         AND current_setting('engramport.cell_step', true) = OLD.id::text THEN
        RETURN NEW;
      END IF;
      IF to_jsonb(NEW) ->> 'state' = 'cancelled' AND (to_jsonb(NEW) - v_cancel) = (to_jsonb(OLD) - v_cancel)
         AND current_user = 'engramport_admin' THEN
        NEW := jsonb_populate_record(NEW, jsonb_build_object('cancelled_at', now()));
        RETURN NEW;
      END IF;
    END IF;
  END IF;
  RAISE EXCEPTION '% is a record and is never changed or deleted', TG_TABLE_NAME USING ERRCODE = '42501';
END
$$;
CREATE TRIGGER cell_erasure_requests_kept BEFORE UPDATE OR DELETE ON memory.cell_erasure_requests
  FOR EACH ROW EXECUTE FUNCTION memory.cell_erasure_records_kept();
CREATE TRIGGER cell_erasure_requests_kept_all BEFORE TRUNCATE ON memory.cell_erasure_requests
  FOR EACH STATEMENT EXECUTE FUNCTION memory.cell_erasure_records_kept();
CREATE TRIGGER cell_erasure_challenges_kept BEFORE UPDATE OR DELETE ON memory.cell_erasure_challenges
  FOR EACH ROW EXECUTE FUNCTION memory.cell_erasure_records_kept();
CREATE TRIGGER cell_erasure_challenges_kept_all BEFORE TRUNCATE ON memory.cell_erasure_challenges
  FOR EACH STATEMENT EXECUTE FUNCTION memory.cell_erasure_records_kept();
REVOKE ALL ON FUNCTION memory.cell_erasure_records_kept() FROM PUBLIC;

-- Tombstones now also come from a whole-cell erasure, which they name. The
-- request is taken from the transaction's own setting, set only inside the
-- decision.
ALTER TABLE memory.erasures DROP CONSTRAINT erasures_source_check;
ALTER TABLE memory.erasures ADD CONSTRAINT erasures_source_check CHECK (source IN ('request', 'restore', 'cell'));
ALTER TABLE memory.erasures
  ADD COLUMN cell_request_id uuid REFERENCES memory.cell_erasure_requests(id)
    DEFAULT nullif(current_setting('engramport.cell_erasure', true), '')::uuid;
ALTER TABLE memory.erasures ADD CONSTRAINT erasures_cell_check CHECK ((source = 'cell') = (cell_request_id IS NOT NULL));
CREATE INDEX erasures_cell_request ON memory.erasures (cell_request_id);

-- ── Freezing the cell while a request is open ───────────────────────────────

CREATE FUNCTION memory.cell_open_erasure(p_namespace_id uuid) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT r.id FROM memory.cell_erasure_requests r
  WHERE r.namespace_id = p_namespace_id AND r.state = 'proposed' AND r.expires_at > now()
  ORDER BY r.created_at LIMIT 1
$$;
REVOKE ALL ON FUNCTION memory.cell_open_erasure(uuid) FROM PUBLIC;

-- Every write into a cell shares a lock on the cell's row with the other
-- writes, and conflicts with the one request_cell_erasure and the decision
-- take. So a write already under way finishes before a request is made, and
-- is counted, previewed and erased with the rest; a write that comes after
-- waits, then sees the open request and is refused.
CREATE FUNCTION memory.cell_frozen_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  PERFORM 1 FROM memory.namespaces n WHERE n.id = NEW.namespace_id FOR SHARE;
  IF memory.cell_open_erasure(NEW.namespace_id) IS NOT NULL THEN
    RAISE EXCEPTION 'this cell is waiting for whole-cell erasure; nothing new is written to it until that is decided'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION memory.cell_frozen_guard() FROM PUBLIC;
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['memories', 'memory_embeddings', 'entities', 'entity_aliases', 'entity_mentions',
                           'relations', 'memory_links'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE INSERT ON memory.%I FOR EACH ROW EXECUTE FUNCTION memory.cell_frozen_guard()',
                   t || '_cell_frozen', t);
  END LOOP;
END
$$;

-- ── Who, what and whether ───────────────────────────────────────────────────

-- The owner's authority over a cell that may start a whole-cell erasure: a
-- direct, valid grant over every claim type, of the cell's scope, on the cell
-- or above it.
CREATE FUNCTION memory.cell_owner_authority_covers(p_authority uuid, p_actor uuid, p_namespace_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT coalesce((
    SELECT a.actor_id = p_actor AND a.parent_id IS NULL AND a.claim_types IS NULL
       AND a.scope = memory.approval_scope_for(p_namespace_id)
       AND a.namespace_id IN (SELECT memory.namespace_and_ancestors(p_namespace_id))
       AND memory.approval_authority_valid(a.id)
    FROM memory.approval_authorities a WHERE a.id = p_authority), false)
$$;
REVOKE ALL ON FUNCTION memory.cell_owner_authority_covers(uuid, uuid, uuid) FROM PUBLIC;

CREATE FUNCTION memory.cell_owner_authority_for(p_actor uuid, p_namespace_id uuid) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT a.id FROM memory.approval_authorities a
  WHERE a.actor_id = p_actor AND memory.cell_owner_authority_covers(a.id, p_actor, p_namespace_id)
  ORDER BY a.created_at
  LIMIT 1
$$;
REVOKE ALL ON FUNCTION memory.cell_owner_authority_for(uuid, uuid) FROM PUBLIC;

-- What a whole-cell erasure would remove now: counts only.
CREATE FUNCTION memory.cell_erasure_counts(p_namespace_id uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT jsonb_build_object(
    'memories', (SELECT count(*) FROM memory.memories x WHERE x.namespace_id = p_namespace_id AND x.status <> 'erased'),
    'active', (SELECT count(*) FROM memory.memories x WHERE x.namespace_id = p_namespace_id AND x.status = 'active'),
    'approved', (SELECT count(*) FROM memory.memories x
                 WHERE x.namespace_id = p_namespace_id AND x.status <> 'erased' AND x.approval_state = 'approved'),
    'embeddings', (SELECT count(*) FROM memory.memory_embeddings x WHERE x.namespace_id = p_namespace_id),
    'entities', (SELECT count(*) FROM memory.entities x WHERE x.namespace_id = p_namespace_id),
    'aliases', (SELECT count(*) FROM memory.entity_aliases x WHERE x.namespace_id = p_namespace_id),
    'relations', (SELECT count(*) FROM memory.relations x WHERE x.namespace_id = p_namespace_id),
    'mentions', (SELECT count(*) FROM memory.entity_mentions x WHERE x.namespace_id = p_namespace_id),
    'links', (SELECT count(*) FROM memory.memory_links x WHERE x.namespace_id = p_namespace_id))
$$;
REVOKE ALL ON FUNCTION memory.cell_erasure_counts(uuid) FROM PUBLIC;

-- A digest of the ids of everything a whole-cell erasure would remove, bound
-- to the request. Ids only, never content.
CREATE FUNCTION memory.cell_erasure_objects_sha256(p_request_id uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT encode(sha256(convert_to(concat_ws('|', r.id::text,
    (SELECT string_agg(x.id::text, ',' ORDER BY x.id) FROM memory.memories x
     WHERE x.namespace_id = r.namespace_id AND x.status <> 'erased'),
    (SELECT string_agg(x.memory_id::text, ',' ORDER BY x.memory_id) FROM memory.memory_embeddings x
     WHERE x.namespace_id = r.namespace_id),
    (SELECT string_agg(x.id::text, ',' ORDER BY x.id) FROM memory.entities x WHERE x.namespace_id = r.namespace_id),
    (SELECT string_agg(x.id::text, ',' ORDER BY x.id) FROM memory.entity_aliases x WHERE x.namespace_id = r.namespace_id),
    (SELECT string_agg(x.id::text, ',' ORDER BY x.id) FROM memory.relations x WHERE x.namespace_id = r.namespace_id),
    (SELECT string_agg(x.memory_id::text || ':' || x.entity_id::text, ',' ORDER BY x.memory_id, x.entity_id)
     FROM memory.entity_mentions x WHERE x.namespace_id = r.namespace_id),
    (SELECT string_agg(x.id::text, ',' ORDER BY x.id) FROM memory.memory_links x WHERE x.namespace_id = r.namespace_id)
  ), 'UTF8')), 'hex')
  FROM memory.cell_erasure_requests r WHERE r.id = p_request_id
$$;
REVOKE ALL ON FUNCTION memory.cell_erasure_objects_sha256(uuid) FROM PUBLIC;

-- Erase everything in a cell: every memory version (with a tombstone of the
-- given source), its embeddings and every graph row, and scrub the cell's
-- provenance of anything content-derived. Returns the counts. The decision
-- passes no cutoff and erases everything, whatever its timestamps say; only
-- the backup reconcile below passes one (p_before), to keep what was written
-- after the erasure. Called only by those two.
CREATE FUNCTION memory.erase_cell_contents(p_namespace_id uuid, p_before timestamptz, p_source text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v uuid;
  v_part jsonb;
  v_key text;
  v_counts jsonb := jsonb_build_object('versions', 0, 'embeddings', 0, 'mentions', 0, 'links', 0, 'relations', 0,
                                       'entities', 0, 'aliases', 0, 'approval_digests', 0, 'challenge_digests', 0,
                                       'provenance_scrubbed', 0);
  n bigint;
BEGIN
  FOR v IN SELECT m.id FROM memory.memories m
           WHERE m.namespace_id = p_namespace_id AND m.status <> 'erased' AND (p_before IS NULL OR m.created_at <= p_before)
           ORDER BY m.id LOOP
    CONTINUE WHEN (SELECT m.status FROM memory.memories m WHERE m.id = v) = 'erased';
    v_part := memory.erase_chain(v, NULL, p_source);
    FOR v_key IN SELECT jsonb_object_keys(v_part) LOOP
      v_counts := jsonb_set(v_counts, ARRAY[v_key],
                            to_jsonb(coalesce((v_counts ->> v_key)::bigint, 0) + (v_part ->> v_key)::bigint));
    END LOOP;
  END LOOP;

  DELETE FROM memory.entity_mentions WHERE namespace_id = p_namespace_id AND (p_before IS NULL OR created_at <= p_before);
  GET DIAGNOSTICS n = ROW_COUNT;
  v_counts := jsonb_set(v_counts, '{mentions}', to_jsonb((v_counts ->> 'mentions')::bigint + n));
  DELETE FROM memory.relations WHERE namespace_id = p_namespace_id AND (p_before IS NULL OR created_at <= p_before);
  GET DIAGNOSTICS n = ROW_COUNT;
  v_counts := jsonb_set(v_counts, '{relations}', to_jsonb((v_counts ->> 'relations')::bigint + n));
  DELETE FROM memory.memory_links WHERE namespace_id = p_namespace_id AND (p_before IS NULL OR created_at <= p_before);
  GET DIAGNOSTICS n = ROW_COUNT;
  v_counts := jsonb_set(v_counts, '{links}', to_jsonb((v_counts ->> 'links')::bigint + n));
  DELETE FROM memory.entity_aliases WHERE namespace_id = p_namespace_id AND (p_before IS NULL OR created_at <= p_before);
  GET DIAGNOSTICS n = ROW_COUNT;
  v_counts := jsonb_set(v_counts, '{aliases}', to_jsonb(n));
  DELETE FROM memory.entities WHERE namespace_id = p_namespace_id AND (p_before IS NULL OR created_at <= p_before);
  GET DIAGNOSTICS n = ROW_COUNT;
  v_counts := jsonb_set(v_counts, '{entities}', to_jsonb((v_counts ->> 'entities')::bigint + n));
  UPDATE memory.provenance SET source_ref = NULL, claimed = '{}', content_sha256 = NULL
  WHERE namespace_id = p_namespace_id AND (p_before IS NULL OR created_at <= p_before)
    AND (source_ref IS NOT NULL OR claimed <> '{}' OR content_sha256 IS NOT NULL);
  GET DIAGNOSTICS n = ROW_COUNT;
  v_counts := jsonb_set(v_counts, '{provenance_scrubbed}', to_jsonb(n));
  RETURN v_counts;
END
$$;
REVOKE ALL ON FUNCTION memory.erase_cell_contents(uuid, timestamptz, text) FROM PUBLIC;

-- Nothing that was in the cell is left anywhere retrievable (with no cutoff,
-- nothing at all is left in it).
CREATE FUNCTION memory.cell_erasure_verified(p_namespace_id uuid, p_before timestamptz) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT memory.erasure_verified(coalesce((SELECT array_agg(m.id) FROM memory.memories m
                                           WHERE m.namespace_id = p_namespace_id AND (p_before IS NULL OR m.created_at <= p_before)), '{}'))
     AND NOT EXISTS (SELECT 1 FROM memory.memory_embeddings x WHERE x.namespace_id = p_namespace_id AND (p_before IS NULL OR x.created_at <= p_before))
     AND NOT EXISTS (SELECT 1 FROM memory.entities x WHERE x.namespace_id = p_namespace_id AND (p_before IS NULL OR x.created_at <= p_before))
     AND NOT EXISTS (SELECT 1 FROM memory.entity_aliases x WHERE x.namespace_id = p_namespace_id AND (p_before IS NULL OR x.created_at <= p_before))
     AND NOT EXISTS (SELECT 1 FROM memory.relations x WHERE x.namespace_id = p_namespace_id AND (p_before IS NULL OR x.created_at <= p_before))
     AND NOT EXISTS (SELECT 1 FROM memory.entity_mentions x WHERE x.namespace_id = p_namespace_id AND (p_before IS NULL OR x.created_at <= p_before))
     AND NOT EXISTS (SELECT 1 FROM memory.memory_links x WHERE x.namespace_id = p_namespace_id AND (p_before IS NULL OR x.created_at <= p_before))
     AND NOT EXISTS (SELECT 1 FROM memory.provenance p WHERE p.namespace_id = p_namespace_id AND (p_before IS NULL OR p.created_at <= p_before)
                       AND (p.source_ref IS NOT NULL OR p.claimed <> '{}' OR p.content_sha256 IS NOT NULL))
$$;
REVOKE ALL ON FUNCTION memory.cell_erasure_verified(uuid, timestamptz) FROM PUBLIC;

-- ── The owner starts it ─────────────────────────────────────────────────────

-- What the owner sees before starting: counts only, and whether one is open.
CREATE FUNCTION memory.cell_erasure_preview(p_user_id uuid, p_session_id uuid, p_namespace_id uuid)
RETURNS TABLE (namespace_path text, counts jsonb, open_request_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid := memory.unspent_human_sign_in(p_user_id, p_session_id);
BEGIN
  IF NOT EXISTS (SELECT 1 FROM memory.namespaces n WHERE n.id = p_namespace_id AND n.level = 'cell')
     OR memory.cell_owner_authority_for(v_actor, p_namespace_id) IS NULL THEN
    RAISE EXCEPTION 'cell not found, or you are not its owner' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY SELECT n.path, memory.cell_erasure_counts(n.id), memory.cell_open_erasure(n.id)
  FROM memory.namespaces n WHERE n.id = p_namespace_id;
END
$$;

-- The owner starts it with their own fresh sign-in. The cell is frozen from
-- here until it is confirmed, cancelled, or lapses after 7 days.
CREATE FUNCTION memory.request_cell_erasure(p_user_id uuid, p_session_id uuid, p_namespace_id uuid,
                                            p_reason memory.erasure_reason) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  v_authority uuid;
  v_id uuid;
BEGIN
  IF p_reason IS NULL THEN
    RAISE EXCEPTION 'give a reason: owner_request, stored_in_error or legal' USING ERRCODE = '22023';
  END IF;
  v_actor := memory.consume_human_sign_in(p_user_id, p_session_id, 'cell_erase');
  -- One open request per cell: requests and decisions for a cell queue on its
  -- row, and wait for writes under way in it (see memory.cell_frozen_guard).
  PERFORM 1 FROM memory.namespaces n WHERE n.id = p_namespace_id AND n.level = 'cell' FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'cell not found, or you are not its owner' USING ERRCODE = '42501';
  END IF;
  v_authority := memory.cell_owner_authority_for(v_actor, p_namespace_id);
  IF v_authority IS NULL THEN
    RAISE EXCEPTION 'cell not found, or you are not its owner' USING ERRCODE = '42501';
  END IF;
  IF memory.cell_open_erasure(p_namespace_id) IS NOT NULL THEN
    RAISE EXCEPTION 'a whole-cell erasure of this cell is already waiting for confirmation' USING ERRCODE = '55000';
  END IF;
  INSERT INTO memory.cell_erasure_requests (namespace_id, reason, initiated_by_actor_id, authority_id,
      initiate_sign_in_hash, preview, expires_at)
  VALUES (p_namespace_id, p_reason, v_actor, v_authority, sha256(uuid_send(p_session_id)),
          memory.cell_erasure_counts(p_namespace_id), now() + interval '7 days')
  RETURNING id INTO v_id;
  RETURN v_id;
END
$$;

-- ── A confirmer confirms ────────────────────────────────────────────────────

-- The open requests this person may confirm: in their role's scope, not their own.
CREATE FUNCTION memory.pending_cell_erasures(p_user_id uuid, p_session_id uuid)
RETURNS TABLE (request_id uuid, namespace_path text, reason memory.erasure_reason, initiated_by text,
               created_at timestamptz, expires_at timestamptz, preview jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid := memory.unspent_human_sign_in(p_user_id, p_session_id);
BEGIN
  RETURN QUERY
  SELECT r.id, n.path, r.reason, a.slug, r.created_at, r.expires_at, r.preview
  FROM memory.cell_erasure_requests r
  JOIN memory.namespaces n ON n.id = r.namespace_id
  JOIN memory.actors a ON a.id = r.initiated_by_actor_id
  WHERE r.state = 'proposed' AND r.expires_at > now() AND r.initiated_by_actor_id <> v_actor
    AND memory.confirmer_role_for(v_actor, r.namespace_id) IS NOT NULL
  ORDER BY r.created_at;
END
$$;

-- What the confirmer reviews: fresh counts and the digest of what will go.
CREATE FUNCTION memory.cell_erasure_review(p_user_id uuid, p_session_id uuid, p_request_id uuid)
RETURNS TABLE (request_id uuid, namespace_path text, reason memory.erasure_reason, initiated_by text,
               created_at timestamptz, expires_at timestamptz, counts jsonb, objects_sha256 text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid := memory.unspent_human_sign_in(p_user_id, p_session_id);
  r memory.cell_erasure_requests;
BEGIN
  SELECT * INTO r FROM memory.cell_erasure_requests x WHERE x.id = p_request_id;
  IF NOT FOUND OR memory.confirmer_role_for(v_actor, r.namespace_id) IS NULL THEN
    RAISE EXCEPTION 'request not found, or you hold no cell-erasure-confirmer role for it' USING ERRCODE = '42501';
  END IF;
  IF r.initiated_by_actor_id = v_actor THEN
    RAISE EXCEPTION 'you started this erasure; a different person must confirm it' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT r.id, n.path, r.reason, a.slug, r.created_at, r.expires_at, memory.cell_erasure_counts(r.namespace_id),
         memory.cell_erasure_objects_sha256(r.id)
  FROM memory.namespaces n, memory.actors a
  WHERE n.id = r.namespace_id AND a.id = r.initiated_by_actor_id;
END
$$;

CREATE FUNCTION memory.issue_cell_erasure_challenge(p_user_id uuid, p_session_id uuid, p_request_id uuid,
                                                    p_objects_sha256 text)
RETURNS TABLE (challenge_id uuid, secret text, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid := memory.unspent_human_sign_in(p_user_id, p_session_id);
  r memory.cell_erasure_requests;
  v_role uuid;
  v_secret bytea;
  v_id uuid;
  v_expires timestamptz;
BEGIN
  IF p_objects_sha256 IS NULL OR p_objects_sha256 !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'pass the digest of the erasure you were shown, as 64 lowercase hex digits' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO r FROM memory.cell_erasure_requests x WHERE x.id = p_request_id;
  IF FOUND THEN
    v_role := memory.confirmer_role_for(v_actor, r.namespace_id);
  END IF;
  IF v_role IS NULL THEN
    RAISE EXCEPTION 'request not found, or you hold no cell-erasure-confirmer role for it' USING ERRCODE = '42501';
  END IF;
  IF r.initiated_by_actor_id = v_actor THEN
    RAISE EXCEPTION 'you started this erasure; a different person must confirm it' USING ERRCODE = '42501';
  END IF;
  IF r.state <> 'proposed' THEN
    RAISE EXCEPTION 'this erasure is no longer open: %', r.state USING ERRCODE = '55000';
  END IF;
  IF r.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'this erasure request has lapsed; the owner must start it again' USING ERRCODE = '55000';
  END IF;
  IF memory.cell_erasure_objects_sha256(r.id) <> p_objects_sha256 THEN
    RAISE EXCEPTION 'the cell changed since you reviewed it; review it again' USING ERRCODE = '55000';
  END IF;
  v_secret := uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid());
  v_expires := now() + interval '10 minutes';
  BEGIN
    INSERT INTO memory.cell_erasure_challenges (request_id, actor_id, role_id, objects_sha256, secret_sha256,
        sign_in_hash, expires_at)
    VALUES (r.id, v_actor, v_role, p_objects_sha256, sha256(v_secret), sha256(uuid_send(p_session_id)), v_expires)
    RETURNING id INTO v_id;
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'this sign-in was already used; sign in again' USING ERRCODE = '42501';
  END;
  RETURN QUERY SELECT v_id, encode(v_secret, 'hex'), v_expires;
END
$$;

-- The decision. All of it, or none of it.
CREATE FUNCTION memory.decide_cell_erasure_challenge(p_user_id uuid, p_session_id uuid, p_challenge_id uuid,
                                                     p_secret text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  c memory.cell_erasure_challenges;
  r memory.cell_erasure_requests;
  v_role memory.cell_erasure_confirmers;
  v_expires timestamptz;
  v_at timestamptz;
  v_counts jsonb;
BEGIN
  IF p_secret IS NULL OR p_secret !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'pass the challenge secret, as 64 lowercase hex digits' USING ERRCODE = '22023';
  END IF;
  v_actor := memory.consume_human_sign_in(p_user_id, p_session_id, 'cell_confirm');
  SELECT * INTO c FROM memory.cell_erasure_challenges x WHERE x.id = p_challenge_id FOR UPDATE;
  IF NOT FOUND OR c.actor_id <> v_actor
     OR c.sign_in_hash <> sha256(uuid_send(p_session_id))
     OR c.secret_sha256 <> sha256(decode(p_secret, 'hex')) THEN
    RAISE EXCEPTION 'no such challenge for this sign-in' USING ERRCODE = '42501';
  END IF;
  -- The cell first, then the request, as request_cell_erasure takes them. This
  -- waits for any write under way in the cell.
  PERFORM 1 FROM memory.namespaces n
  WHERE n.id = (SELECT x.namespace_id FROM memory.cell_erasure_requests x WHERE x.id = c.request_id) FOR NO KEY UPDATE;
  SELECT * INTO r FROM memory.cell_erasure_requests x WHERE x.id = c.request_id FOR UPDATE;
  IF r.state <> 'proposed' THEN
    RAISE EXCEPTION 'this erasure is no longer open: %', r.state USING ERRCODE = '55000';
  END IF;
  IF r.initiated_by_actor_id = v_actor THEN
    RAISE EXCEPTION 'you started this erasure; a different person must confirm it' USING ERRCODE = '42501';
  END IF;
  IF c.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'this challenge has expired; review the erasure again' USING ERRCODE = '55000';
  END IF;
  IF r.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'this erasure request has lapsed; the owner must start it again' USING ERRCODE = '55000';
  END IF;

  -- Hold the confirmer's role, the confirmer and their AN2B membership, and
  -- the owner's authority chain with each person on it, until it is recorded.
  SELECT * INTO v_role FROM memory.cell_erasure_confirmers x WHERE x.id = c.role_id FOR SHARE;
  PERFORM 1 FROM memory.actors x WHERE x.id = v_actor FOR SHARE;
  PERFORM 1 FROM memory.oauth_members m WHERE m.actor_id = v_actor FOR SHARE;
  v_expires := memory.lock_data_power(r.authority_id, NULL, r.initiated_by_actor_id);
  IF NOT memory.confirmer_role_covers(c.role_id, v_actor, r.namespace_id) OR v_role.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'your cell-erasure-confirmer role no longer covers this cell' USING ERRCODE = '55000';
  END IF;
  IF NOT memory.cell_owner_authority_covers(r.authority_id, r.initiated_by_actor_id, r.namespace_id)
     OR v_expires <= clock_timestamp() THEN
    RAISE EXCEPTION 'the owner''s authority this erasure was started under is no longer valid' USING ERRCODE = '55000';
  END IF;
  IF memory.cell_erasure_objects_sha256(r.id) <> c.objects_sha256 THEN
    RAISE EXCEPTION 'the cell changed since you reviewed it; review it again' USING ERRCODE = '55000';
  END IF;

  v_at := clock_timestamp();
  PERFORM set_config('engramport.cell_erasure', r.id::text, true);
  v_counts := memory.erase_cell_contents(r.namespace_id, NULL, 'cell');
  PERFORM set_config('engramport.cell_erasure', '', true);
  IF NOT memory.cell_erasure_verified(r.namespace_id, NULL) THEN
    RAISE EXCEPTION 'erasure could not be verified; nothing was changed' USING ERRCODE = 'XX000';
  END IF;
  -- The wall clock once more, now that everything is erased and held.
  IF c.expires_at <= clock_timestamp() OR v_role.expires_at <= clock_timestamp() OR v_expires <= clock_timestamp() THEN
    RAISE EXCEPTION 'an authority or challenge expired while the cell was being erased; nothing was changed'
      USING ERRCODE = '55000';
  END IF;

  v_counts := v_counts || jsonb_build_object('verified', true, 'objects_sha256', c.objects_sha256);
  PERFORM set_config('engramport.cell_step', r.id::text, true);
  UPDATE memory.cell_erasure_requests
  SET state = 'completed', confirmed_by_actor_id = v_actor, confirmer_role_id = c.role_id, challenge_id = c.id,
      completed_at = v_at, evidence = v_counts
  WHERE id = r.id;
  PERFORM set_config('engramport.cell_step', '', true);
  RETURN v_counts;
END
$$;

-- ── Backups ─────────────────────────────────────────────────────────────────

-- After restoring a backup taken before a whole-cell erasure, erase again what
-- was in the cell when it was erased. For the database owner only, with the
-- cell and completed_at from the ledger kept outside the database. Safe to
-- run twice.
CREATE FUNCTION memory.reapply_cell_erasure(p_namespace_id uuid, p_completed_at timestamptz) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_counts jsonb;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM memory.namespaces n WHERE n.id = p_namespace_id) THEN
    RETURN jsonb_build_object('not_in_this_database', true);
  END IF;
  IF p_completed_at IS NULL THEN
    RAISE EXCEPTION 'give the time the erasure completed, from the ledger' USING ERRCODE = '22023';
  END IF;
  v_counts := memory.erase_cell_contents(p_namespace_id, p_completed_at, 'restore');
  IF NOT memory.cell_erasure_verified(p_namespace_id, p_completed_at) THEN
    RAISE EXCEPTION 'erasure could not be verified; nothing was changed' USING ERRCODE = 'XX000';
  END IF;
  RETURN v_counts;
END
$$;
REVOKE ALL ON FUNCTION memory.reapply_cell_erasure(uuid, timestamptz) FROM PUBLIC;

-- ── Access ──────────────────────────────────────────────────────────────────

ALTER TABLE memory.cell_erasure_confirmers ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.cell_erasure_confirmers FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.cell_erasure_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.cell_erasure_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.cell_erasure_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.cell_erasure_challenges FORCE ROW LEVEL SECURITY;

-- The admin assigns and revokes roles, sees requests and cancels an open one,
-- and sees challenges without secrets or sign-ins. It can't start or confirm
-- an erasure, and sees no content.
GRANT SELECT (id, actor_id, scope_namespace_id, assigned_at, expires_at, accepted_at, rejected_at, revoked_at,
              revoke_reason)
  ON memory.cell_erasure_confirmers TO engramport_admin;
GRANT INSERT (actor_id, scope_namespace_id, expires_at) ON memory.cell_erasure_confirmers TO engramport_admin;
GRANT UPDATE (revoked_at, revoke_reason) ON memory.cell_erasure_confirmers TO engramport_admin;
CREATE POLICY cell_erasure_confirmers_admin_read ON memory.cell_erasure_confirmers FOR SELECT TO engramport_admin
  USING (true);
CREATE POLICY cell_erasure_confirmers_admin_assign ON memory.cell_erasure_confirmers FOR INSERT TO engramport_admin
  WITH CHECK (true);
CREATE POLICY cell_erasure_confirmers_admin_revoke ON memory.cell_erasure_confirmers FOR UPDATE TO engramport_admin
  USING (revoked_at IS NULL) WITH CHECK (revoked_at IS NOT NULL);
GRANT SELECT (id, namespace_id, reason, initiated_by_actor_id, authority_id, preview, created_at, expires_at, state,
              confirmed_by_actor_id, confirmer_role_id, challenge_id, completed_at, evidence, cancelled_at,
              cancel_reason)
  ON memory.cell_erasure_requests TO engramport_admin;
GRANT UPDATE (state, cancelled_at, cancel_reason) ON memory.cell_erasure_requests TO engramport_admin;
CREATE POLICY cell_erasure_requests_admin_read ON memory.cell_erasure_requests FOR SELECT TO engramport_admin
  USING (true);
CREATE POLICY cell_erasure_requests_admin_cancel ON memory.cell_erasure_requests FOR UPDATE TO engramport_admin
  USING (state = 'proposed') WITH CHECK (state = 'cancelled');
GRANT SELECT (id, request_id, actor_id, role_id, issued_at, expires_at) ON memory.cell_erasure_challenges
  TO engramport_admin;
CREATE POLICY cell_erasure_challenges_admin_read ON memory.cell_erasure_challenges FOR SELECT TO engramport_admin
  USING (true);
GRANT SELECT (cell_request_id) ON memory.erasures TO engramport_admin;

REVOKE ALL ON FUNCTION memory.pending_confirmer_roles(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.decide_confirmer_role(uuid, uuid, uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.cell_erasure_preview(uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.request_cell_erasure(uuid, uuid, uuid, memory.erasure_reason) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.pending_cell_erasures(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.cell_erasure_review(uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.issue_cell_erasure_challenge(uuid, uuid, uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.decide_cell_erasure_challenge(uuid, uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.pending_confirmer_roles(uuid, uuid),
  memory.decide_confirmer_role(uuid, uuid, uuid, text, text),
  memory.cell_erasure_preview(uuid, uuid, uuid),
  memory.request_cell_erasure(uuid, uuid, uuid, memory.erasure_reason),
  memory.pending_cell_erasures(uuid, uuid),
  memory.cell_erasure_review(uuid, uuid, uuid),
  memory.issue_cell_erasure_challenge(uuid, uuid, uuid, text),
  memory.decide_cell_erasure_challenge(uuid, uuid, uuid, text) TO engramport_app;

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
