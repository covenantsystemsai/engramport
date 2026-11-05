-- D-02.3: a retracted memory can be restored by a person for 30 days, and
-- after that the retraction is final. Forward-only; applied by db/migrate.sh
-- in one transaction.
--
-- Founder decision D-02.3, in his words: "A retracted memory immediately
-- loses ordinary retrieval and authoritative status. Only an authorized human
-- may restore it within 30 days. After 30 days, retraction is final and cannot
-- be reversed through the normal restore operation. Retraction does not
-- automatically trigger physical erasure."
--
-- What this adds:
--   * Each memory records when it was retracted and what it was before
--     (retracted_at, retracted_from). The database stamps both itself when the
--     status turns to retracted; no role can set or move them, so the window
--     can't be stretched. Memories retracted before this migration have no
--     stamp and stay final.
--   * Restoring takes the same three steps as approving, with the person's own
--     fresh sign-in: review (memory.restore_review shows the memory, when it
--     was retracted and until when it can come back), a single-use challenge
--     bound to the person, the memory, its retraction and the authority
--     (memory.issue_restore_challenge), and the decision, which spends the
--     sign-in and the challenge together (memory.decide_restore_challenge).
--   * Who may restore: a person holding approval authority that covers the
--     memory's namespace and claim type, the same people who may approve it.
--     No agent and no key can restore; nothing here is an MCP tool.
--   * What comes back: the memory returns to what it was retracted from,
--     with its approval state unchanged. A current version (active) comes back
--     only if no other current memory now holds its key. A proposed revision
--     comes back only while the version it revises is still the current
--     approved one. A version that was already superseded when it was
--     retracted is not restored: there is nothing to come back to.
--   * The window is 30 days by the wall clock from the retraction, checked
--     when the challenge is issued and again when the decision is written.
--     After that, nothing restores it. Retraction never erases anything; an
--     erased memory stays erased.
--   * The record: every restoration names the memory, the person, the
--     authority, the challenge and the retraction it reversed. Challenges and
--     restorations are never changed or deleted. Neither holds the memory's
--     text or a digest of it, so erasing the memory later leaves no
--     fingerprint here. The admin sees who restored what and when, never the
--     text.

ALTER TABLE memory.human_sign_ins_used DROP CONSTRAINT human_sign_ins_used_purpose_check;
ALTER TABLE memory.human_sign_ins_used ADD CONSTRAINT human_sign_ins_used_purpose_check
  CHECK (purpose IN ('approve', 'delegate', 'revoke', 'connect', 'accept', 'erase', 'export', 'grant', 'restore'));

ALTER TABLE memory.memories
  ADD COLUMN retracted_at timestamptz,
  ADD COLUMN retracted_from memory.memory_status,
  ADD CONSTRAINT memories_retraction_stamp CHECK ((retracted_at IS NULL) = (retracted_from IS NULL)),
  ADD CONSTRAINT memories_retracted_from CHECK (retracted_from IS NULL OR retracted_from IN ('active', 'proposed', 'superseded'));

-- The database stamps a retraction itself. Whatever a writer puts in these
-- columns is replaced: set when the status turns to retracted, cleared when a
-- restoration brings it back, and otherwise left as it was.
CREATE FUNCTION memory.memories_retraction_stamp() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.retracted_at := NULL;
    NEW.retracted_from := NULL;
  ELSIF NEW.status = 'retracted' AND OLD.status IS DISTINCT FROM 'retracted' THEN
    NEW.retracted_at := clock_timestamp();
    NEW.retracted_from := OLD.status;
  ELSIF OLD.status = 'retracted' AND NEW.status IN ('active', 'proposed') THEN
    NEW.retracted_at := NULL;
    NEW.retracted_from := NULL;
  ELSE
    NEW.retracted_at := OLD.retracted_at;
    NEW.retracted_from := OLD.retracted_from;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER memories_retraction_stamp BEFORE INSERT OR UPDATE ON memory.memories
  FOR EACH ROW EXECUTE FUNCTION memory.memories_retraction_stamp();
REVOKE ALL ON FUNCTION memory.memories_retraction_stamp() FROM PUBLIC;

-- 0022's lifecycle guard, now also letting a restoration bring a retracted
-- memory back to what it was.
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
    -- Restored (D-02.3): back to what it was retracted from, only inside
    -- memory.decide_restore_challenge, which checks the person and the window.
    -- The proof is the restoration record that decision writes first, in this
    -- same transaction: no role but the decision can write one.
    IF OLD.status = 'retracted' AND NEW.status = OLD.retracted_from AND NEW.status IN ('active', 'proposed')
       AND EXISTS (SELECT 1 FROM memory.restorations x
                   WHERE x.memory_id = OLD.id AND x.txid = txid_current() AND x.retracted_at = OLD.retracted_at
                     AND x.restored_to = NEW.status) THEN
      RETURN NEW;
    END IF;
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

-- ── Records ─────────────────────────────────────────────────────────────────

CREATE TABLE memory.restore_challenges (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  memory_id uuid NOT NULL REFERENCES memory.memories(id),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  actor_id uuid NOT NULL REFERENCES memory.actors(id),
  authority_id uuid NOT NULL REFERENCES memory.approval_authorities(id),
  retracted_at timestamptz NOT NULL,
  secret_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(secret_sha256) = 32),
  sign_in_hash bytea NOT NULL UNIQUE CHECK (octet_length(sign_in_hash) = 32),
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  CHECK (expires_at > issued_at)
);
CREATE INDEX restore_challenges_memory ON memory.restore_challenges (memory_id);
CREATE INDEX restore_challenges_namespace ON memory.restore_challenges (namespace_id, issued_at);
CREATE INDEX restore_challenges_actor ON memory.restore_challenges (actor_id);
CREATE INDEX restore_challenges_authority ON memory.restore_challenges (authority_id);

CREATE TABLE memory.restorations (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  memory_id uuid NOT NULL REFERENCES memory.memories(id),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  restored_by_actor_id uuid NOT NULL REFERENCES memory.actors(id),
  authority_id uuid NOT NULL REFERENCES memory.approval_authorities(id),
  challenge_id uuid NOT NULL UNIQUE REFERENCES memory.restore_challenges(id),
  retracted_at timestamptz NOT NULL,
  restored_to memory.memory_status NOT NULL CHECK (restored_to IN ('active', 'proposed')),
  restored_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  -- How the lifecycle guard knows a restoration is under way in this transaction.
  txid bigint NOT NULL DEFAULT txid_current(),
  CHECK (restored_at < retracted_at + interval '30 days')
);
CREATE INDEX restorations_memory ON memory.restorations (memory_id);
CREATE INDEX restorations_namespace ON memory.restorations (namespace_id, restored_at);
CREATE INDEX restorations_actor ON memory.restorations (restored_by_actor_id);
CREATE INDEX restorations_authority ON memory.restorations (authority_id);

CREATE FUNCTION memory.restore_record_kept() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION '% is a record and is never changed or deleted', TG_TABLE_NAME USING ERRCODE = '42501';
END
$$;
CREATE TRIGGER restore_challenges_kept BEFORE UPDATE OR DELETE ON memory.restore_challenges
  FOR EACH ROW EXECUTE FUNCTION memory.restore_record_kept();
CREATE TRIGGER restore_challenges_kept_all BEFORE TRUNCATE ON memory.restore_challenges
  FOR EACH STATEMENT EXECUTE FUNCTION memory.restore_record_kept();
CREATE TRIGGER restorations_kept BEFORE UPDATE OR DELETE ON memory.restorations
  FOR EACH ROW EXECUTE FUNCTION memory.restore_record_kept();
CREATE TRIGGER restorations_kept_all BEFORE TRUNCATE ON memory.restorations
  FOR EACH STATEMENT EXECUTE FUNCTION memory.restore_record_kept();
REVOKE ALL ON FUNCTION memory.restore_record_kept() FROM PUBLIC;

-- ── Who, and whether ────────────────────────────────────────────────────────

-- Whether this authority, held by this person, covers restoring this memory:
-- the same authority that would approve it.
CREATE FUNCTION memory.restore_authority_covers(p_authority uuid, p_actor uuid, p_memory_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT coalesce((
    SELECT a.actor_id = p_actor
       AND a.scope = memory.approval_scope_for(m.namespace_id)
       AND a.namespace_id IN (SELECT memory.namespace_and_ancestors(m.namespace_id))
       AND (a.claim_types IS NULL OR m.claim_type = ANY (a.claim_types))
       AND memory.approval_authority_valid(a.id)
    FROM memory.approval_authorities a, memory.memories m
    WHERE a.id = p_authority AND m.id = p_memory_id), false)
$$;
REVOKE ALL ON FUNCTION memory.restore_authority_covers(uuid, uuid, uuid) FROM PUBLIC;

-- Why this memory can't be restored right now, or NULL if it can.
CREATE FUNCTION memory.restore_refusal(p_memory_id uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT CASE
    WHEN m.status <> 'retracted' THEN 'this memory is not retracted'
    WHEN m.retracted_at IS NULL THEN 'this retraction is final: it was made before restoring was possible'
    WHEN m.retracted_at + interval '30 days' <= clock_timestamp()
      THEN 'this retraction is final: the 30 days to restore it have passed'
    WHEN m.retracted_from = 'superseded'
      THEN 'this version was already replaced when it was retracted; there is nothing to restore it to'
    WHEN m.retracted_from = 'active' AND m.dedup_key IS NOT NULL AND EXISTS (
           SELECT 1 FROM memory.memories x
           WHERE x.namespace_id = m.namespace_id AND x.dedup_key = m.dedup_key AND x.status = 'active')
      THEN 'another current memory now holds this memory''s key'
    WHEN m.retracted_from = 'proposed' AND NOT EXISTS (
           SELECT 1 FROM memory.memories t
           WHERE t.id = m.supersedes_id AND t.status = 'active' AND t.approval_state = 'approved'
             AND t.namespace_id = m.namespace_id)
      THEN 'the version this revision proposed to replace is no longer the current approved one'
  END
  FROM memory.memories m WHERE m.id = p_memory_id
$$;
REVOKE ALL ON FUNCTION memory.restore_refusal(uuid) FROM PUBLIC;

-- ── The three steps ─────────────────────────────────────────────────────────

-- Step 1: what the restore page shows a person with authority over the memory.
-- Nothing is spent or recorded.
CREATE FUNCTION memory.restore_review(p_user_id uuid, p_session_id uuid, p_memory_id uuid)
RETURNS TABLE (memory_id uuid, namespace_path text, kind memory.memory_kind, claim_type memory.claim_type,
               approval_state memory.approval_state, content text, retracted_from memory.memory_status,
               retracted_at timestamptz, restorable_until timestamptz, refusal text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid := memory.unspent_human_sign_in(p_user_id, p_session_id);
  m memory.memories;
BEGIN
  SELECT * INTO m FROM memory.memories x WHERE x.id = p_memory_id;
  IF NOT FOUND OR m.status = 'erased' OR memory.approval_authority_for(v_actor, m.namespace_id, m.claim_type) IS NULL THEN
    RAISE EXCEPTION 'memory not found, or you have no authority to restore it' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT m.id, n.path, m.kind, m.claim_type, m.approval_state, m.content, m.retracted_from, m.retracted_at,
         m.retracted_at + interval '30 days', memory.restore_refusal(m.id)
  FROM memory.namespaces n WHERE n.id = m.namespace_id;
END
$$;

-- Step 2: the person chose to restore it. The secret comes back once and is
-- never stored, only its hash. The challenge is bound to this retraction, so
-- if the memory is restored and retracted again it no longer fits.
CREATE FUNCTION memory.issue_restore_challenge(p_user_id uuid, p_session_id uuid, p_memory_id uuid,
                                               p_retracted_at timestamptz)
RETURNS TABLE (challenge_id uuid, secret text, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid := memory.unspent_human_sign_in(p_user_id, p_session_id);
  v_authority uuid;
  m memory.memories;
  v_refusal text;
  v_secret bytea;
  v_id uuid;
  v_expires timestamptz;
BEGIN
  SELECT * INTO m FROM memory.memories x WHERE x.id = p_memory_id;
  IF FOUND AND m.status <> 'erased' THEN
    v_authority := memory.approval_authority_for(v_actor, m.namespace_id, m.claim_type);
  END IF;
  IF v_authority IS NULL THEN
    RAISE EXCEPTION 'memory not found, or you have no authority to restore it' USING ERRCODE = '42501';
  END IF;
  v_refusal := memory.restore_refusal(m.id);
  IF v_refusal IS NOT NULL THEN
    RAISE EXCEPTION '%', v_refusal USING ERRCODE = '55000';
  END IF;
  IF p_retracted_at IS NULL OR m.retracted_at <> p_retracted_at THEN
    RAISE EXCEPTION 'this is not the retraction you were shown; review it again' USING ERRCODE = '55000';
  END IF;
  v_secret := uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid());
  v_expires := now() + interval '10 minutes';
  BEGIN
    INSERT INTO memory.restore_challenges (memory_id, namespace_id, actor_id, authority_id, retracted_at,
        secret_sha256, sign_in_hash, expires_at)
    VALUES (m.id, m.namespace_id, v_actor, v_authority, m.retracted_at, sha256(v_secret),
            sha256(uuid_send(p_session_id)), v_expires)
    RETURNING id INTO v_id;
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'this sign-in was already used; sign in again' USING ERRCODE = '42501';
  END;
  RETURN QUERY SELECT v_id, encode(v_secret, 'hex'), v_expires;
END
$$;

-- Step 3: spend the sign-in and the challenge together, hold the memory and
-- the authority still, check everything again by the wall clock, record the
-- restoration and bring the memory back. All of it, or none of it.
CREATE FUNCTION memory.decide_restore_challenge(p_user_id uuid, p_session_id uuid, p_challenge_id uuid,
                                                p_secret text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  c memory.restore_challenges;
  m memory.memories;
  v_expires timestamptz;
  v_refusal text;
  v_id uuid;
BEGIN
  IF p_secret IS NULL OR p_secret !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'pass the challenge secret, as 64 lowercase hex digits' USING ERRCODE = '22023';
  END IF;
  v_actor := memory.consume_human_sign_in(p_user_id, p_session_id, 'restore');
  SELECT * INTO c FROM memory.restore_challenges x WHERE x.id = p_challenge_id FOR UPDATE;
  IF NOT FOUND OR c.actor_id <> v_actor
     OR c.sign_in_hash <> sha256(uuid_send(p_session_id))
     OR c.secret_sha256 <> sha256(decode(p_secret, 'hex')) THEN
    RAISE EXCEPTION 'no such challenge for this sign-in' USING ERRCODE = '42501';
  END IF;
  IF EXISTS (SELECT 1 FROM memory.restorations r WHERE r.challenge_id = c.id) THEN
    RAISE EXCEPTION 'this challenge was already used' USING ERRCODE = '55000';
  END IF;
  IF c.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'this challenge has expired; review the memory again' USING ERRCODE = '55000';
  END IF;

  -- Hold the memory, and the authority chain with each person on it, until
  -- the restoration is recorded.
  SELECT * INTO m FROM memory.memories x WHERE x.id = c.memory_id FOR UPDATE;
  v_expires := memory.lock_data_power(c.authority_id, NULL, v_actor);
  IF m.retracted_from = 'proposed' THEN
    PERFORM 1 FROM memory.memories t WHERE t.id = m.supersedes_id FOR SHARE;
  END IF;
  IF NOT memory.restore_authority_covers(c.authority_id, v_actor, m.id) OR v_expires <= clock_timestamp() THEN
    RAISE EXCEPTION 'the authority this challenge was issued under is no longer valid' USING ERRCODE = '55000';
  END IF;
  IF m.status <> 'retracted' OR m.retracted_at IS DISTINCT FROM c.retracted_at THEN
    RAISE EXCEPTION 'this memory changed since you reviewed it; review it again' USING ERRCODE = '55000';
  END IF;
  v_refusal := memory.restore_refusal(m.id);
  IF v_refusal IS NOT NULL THEN
    RAISE EXCEPTION '%', v_refusal USING ERRCODE = '55000';
  END IF;

  -- The wall clock once more, now that everything is held.
  IF c.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'this challenge has expired; review the memory again' USING ERRCODE = '55000';
  END IF;
  IF v_expires <= clock_timestamp() THEN
    RAISE EXCEPTION 'the authority this challenge was issued under is no longer valid' USING ERRCODE = '55000';
  END IF;

  -- The record first: it is what lets the lifecycle guard accept the change.
  INSERT INTO memory.restorations (memory_id, namespace_id, restored_by_actor_id, authority_id, challenge_id,
      retracted_at, restored_to)
  VALUES (m.id, m.namespace_id, v_actor, c.authority_id, c.id, m.retracted_at, m.retracted_from)
  RETURNING id INTO v_id;
  UPDATE memory.memories SET status = m.retracted_from WHERE id = m.id;
  RETURN jsonb_build_object('restoration', v_id, 'memory', m.id, 'restored_to', m.retracted_from,
                            'retracted_at', m.retracted_at);
END
$$;

-- ── Access ──────────────────────────────────────────────────────────────────

ALTER TABLE memory.restore_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.restore_challenges FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.restorations ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.restorations FORCE ROW LEVEL SECURITY;
-- The admin audits restorations without content: who restored which memory,
-- when, under which authority. Never a secret or a sign-in.
GRANT SELECT (id, memory_id, namespace_id, restored_by_actor_id, authority_id, challenge_id, retracted_at, restored_to,
              restored_at)
  ON memory.restorations TO engramport_admin;
CREATE POLICY restorations_admin_read ON memory.restorations FOR SELECT TO engramport_admin USING (true);
GRANT SELECT (id, memory_id, namespace_id, actor_id, authority_id, retracted_at, issued_at, expires_at)
  ON memory.restore_challenges TO engramport_admin;
CREATE POLICY restore_challenges_admin_read ON memory.restore_challenges FOR SELECT TO engramport_admin USING (true);

REVOKE ALL ON FUNCTION memory.restore_review(uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.issue_restore_challenge(uuid, uuid, uuid, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.decide_restore_challenge(uuid, uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.restore_review(uuid, uuid, uuid),
  memory.issue_restore_challenge(uuid, uuid, uuid, timestamptz),
  memory.decide_restore_challenge(uuid, uuid, uuid, text) TO engramport_app;

DO $$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE ALL ON memory.restore_challenges, memory.restorations FROM %I', r);
      EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA memory FROM %I', r);
    END IF;
  END LOOP;
END
$$;
