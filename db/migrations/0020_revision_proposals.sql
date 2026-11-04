-- D-04: agents propose, people approve, history is kept.
-- Forward-only; applied by db/migrate.sh in one transaction.
--
-- Before this migration an agent could replace or retract a memory a person had
-- approved: writing new text under its dedup key, calling supersede_memory or
-- delete_memory all worked, and recall then showed only the unapproved text.
-- That was a defect: an agent-written revision must never silently displace a
-- human-approved decision.
--
-- Now:
--   - An approved memory stays current. An agent's revision of it is written
--     as its own row with status 'proposed', pointing (supersedes_id) at the
--     approved version it would replace, and is put up for approval at once.
--     Its id, provenance, text and digest are its own and never change.
--   - A person decides on the proposal through the D-03 approval page. The
--     challenge binds the proposal, its digest and version, the namespace, the
--     action and, new here, the approved version it would replace.
--   - Approving it makes the proposal active and approved and the old version
--     superseded, in the decision's own transaction. If the approved version
--     was replaced meanwhile (a competing proposal won), the decision is
--     refused as stale and needs a fresh review.
--   - Rejecting it leaves the approved version as it was; the proposal stays
--     on record, proposed and rejected. Its writer can withdraw an undecided
--     or rejected proposal (delete_memory), which retracts it and keeps the text.
--   - Competing proposals stay separate rows until each is decided.
--   - Recall and search return only active memories, so proposals, superseded,
--     rejected and withdrawn versions never come back by default; history and
--     fetch_memory show them, marked, to keys that can read the namespace.
--
-- A lifecycle guard enforces this for every role but the functions below:
-- superseded and retracted versions stay that way, a version's predecessor
-- never changes, an approved memory leaves 'active' only when a person's
-- approval of a revision of it is recorded in the same transaction, and a
-- proposal becomes active only when its own approval is.

CREATE FUNCTION memory.memories_lifecycle_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  t memory.memories;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status = 'active' THEN
      IF NEW.supersedes_id IS NOT NULL THEN
        SELECT * INTO t FROM memory.memories x WHERE x.id = NEW.supersedes_id;
        IF NOT FOUND OR t.status <> 'superseded' THEN
          RAISE EXCEPTION 'a new version can only follow a version that was already superseded' USING ERRCODE = '42501';
        END IF;
      END IF;
      RETURN NEW;
    END IF;
    IF NEW.status = 'proposed' THEN
      SELECT * INTO t FROM memory.memories x WHERE x.id = NEW.supersedes_id;
      IF NOT FOUND OR t.status <> 'active' OR t.approval_state <> 'approved' OR t.namespace_id <> NEW.namespace_id THEN
        RAISE EXCEPTION 'a revision can be proposed only for the current approved version, in its own namespace'
          USING ERRCODE = '42501';
      END IF;
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'a memory is written active, or proposed as a revision' USING ERRCODE = '42501';
  END IF;

  IF NEW.supersedes_id IS DISTINCT FROM OLD.supersedes_id THEN
    IF OLD.supersedes_id IS NOT NULL OR OLD.status <> 'active' THEN
      RAISE EXCEPTION 'the version a memory follows does not change' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO t FROM memory.memories x WHERE x.id = NEW.supersedes_id;
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
CREATE TRIGGER memories_lifecycle_guard BEFORE INSERT OR UPDATE ON memory.memories
  FOR EACH ROW EXECUTE FUNCTION memory.memories_lifecycle_guard();
REVOKE ALL ON FUNCTION memory.memories_lifecycle_guard() FROM PUBLIC;

-- The challenge records the approved version a proposal would replace.
ALTER TABLE memory.approval_challenges ADD COLUMN base_memory_id uuid REFERENCES memory.memories(id);
CREATE INDEX approval_challenges_base ON memory.approval_challenges (base_memory_id) WHERE base_memory_id IS NOT NULL;
GRANT SELECT (base_memory_id) ON memory.approval_challenges TO engramport_admin;

-- ── Proposing ───────────────────────────────────────────────────────────────

-- An agent's revision of an approved memory in its key's own namespace: the
-- same provenance as memory.remember, written as a proposal and put up for
-- approval in one step. Returns the proposal's id.
CREATE FUNCTION memory.propose_revision(
  p_base_id uuid,
  p_kind memory.memory_kind,
  p_content text,
  p_tool text,
  p_transport memory.transport,
  p_claim_type memory.claim_type,
  p_importance real DEFAULT 0.5,
  p_metadata jsonb DEFAULT '{}',
  p_dedup_key text DEFAULT NULL,
  p_request_id text DEFAULT NULL,
  p_source_kind text DEFAULT NULL,
  p_source_ref text DEFAULT NULL,
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
  INSERT INTO memory.provenance (namespace_id, api_key_id, actor_id, tool, transport, request_id,
      source_kind, source_ref, content_sha256, claimed)
  VALUES (k.namespace_id, k.api_key_id, k.actor_id, p_tool, p_transport, p_request_id,
      p_source_kind, p_source_ref, encode(sha256(convert_to(p_content, 'UTF8')), 'hex'), p_claimed)
  RETURNING id INTO prov_id;
  INSERT INTO memory.memories (namespace_id, kind, content, dedup_key, importance, metadata, provenance_id,
      claim_type, status, supersedes_id)
  VALUES (k.namespace_id, p_kind, p_content, p_dedup_key, p_importance, p_metadata, prov_id,
      coalesce(p_claim_type, 'observation'), 'proposed', p_base_id)
  RETURNING id INTO mem_id;
  PERFORM memory.request_approval(mem_id);
  RETURN mem_id;
END
$$;
REVOKE ALL ON FUNCTION memory.propose_revision(uuid, memory.memory_kind, text, text, memory.transport,
  memory.claim_type, real, jsonb, text, text, text, text, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.propose_revision(uuid, memory.memory_kind, text, text, memory.transport,
  memory.claim_type, real, jsonb, text, text, text, text, jsonb) TO engramport_app;

-- 0016's request, now also for a proposal. Same body otherwise.
CREATE OR REPLACE FUNCTION memory.request_approval(p_memory_id uuid) RETURNS uuid
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
  IF m.status NOT IN ('active', 'proposed') THEN
    RAISE EXCEPTION 'only the active version of a memory, or a proposed revision, can be put up for approval'
      USING ERRCODE = '55000';
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

-- ── Reviewing ───────────────────────────────────────────────────────────────

-- 0018's review, now also showing, for a proposal, the approved text it would
-- replace, so the person sees exactly what changes.
DROP FUNCTION memory.approval_review(uuid, uuid, uuid);
CREATE FUNCTION memory.approval_review(p_user_id uuid, p_session_id uuid, p_memory_id uuid)
RETURNS TABLE (memory_id uuid, namespace_path text, kind memory.memory_kind, claim_type memory.claim_type,
               content text, content_sha256 text, memory_version integer, status memory.memory_status,
               approval_state memory.approval_state, requested_at timestamptz, scope memory.approval_scope,
               created_at timestamptz, replaces_memory_id uuid, replaces_content text,
               replaces_content_sha256 text, replaces_current boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid := memory.unspent_human_sign_in(p_user_id, p_session_id);
  m memory.memories;
BEGIN
  SELECT * INTO m FROM memory.memories mm WHERE mm.id = p_memory_id;
  IF NOT FOUND OR memory.approval_authority_for(v_actor, m.namespace_id, m.claim_type) IS NULL THEN
    RAISE EXCEPTION 'memory not found, or you have no valid authority to decide on it' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT m.id, n.path, m.kind, m.claim_type, m.content, m.content_sha256, memory.memory_version(m.id),
         m.status, m.approval_state, (SELECT r.created_at FROM memory.approval_requests r WHERE r.memory_id = m.id),
         memory.approval_scope_for(m.namespace_id), m.created_at,
         b.id, b.content, b.content_sha256, (b.status = 'active' AND b.approval_state = 'approved')
  FROM memory.namespaces n
  LEFT JOIN memory.memories b ON m.status = 'proposed' AND b.id = m.supersedes_id
  WHERE n.id = m.namespace_id;
END
$$;

-- 0018's challenge, now also for a proposal, bound to the approved version it
-- would replace. Same body otherwise.
CREATE OR REPLACE FUNCTION memory.issue_approval_challenge(
  p_user_id uuid, p_session_id uuid, p_memory_id uuid, p_action memory.approval_action,
  p_content_sha256 text, p_memory_version integer
) RETURNS TABLE (challenge_id uuid, secret text, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  m memory.memories;
  b memory.memories;
  v_authority uuid;
  v_secret bytea;
  v_id uuid;
  v_expires timestamptz;
BEGIN
  IF p_action IS NULL THEN
    RAISE EXCEPTION 'say whether to approve or reject' USING ERRCODE = '22023';
  END IF;
  IF p_content_sha256 IS NULL OR p_content_sha256 !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'pass the sha256 of the text you were shown, as 64 lowercase hex digits' USING ERRCODE = '22023';
  END IF;
  IF p_memory_version IS NULL OR p_memory_version < 1 THEN
    RAISE EXCEPTION 'pass the version you were shown' USING ERRCODE = '22023';
  END IF;
  v_actor := memory.unspent_human_sign_in(p_user_id, p_session_id);

  SELECT * INTO m FROM memory.memories mm WHERE mm.id = p_memory_id;
  IF FOUND THEN
    v_authority := memory.approval_authority_for(v_actor, m.namespace_id, m.claim_type);
  END IF;
  IF v_authority IS NULL THEN
    RAISE EXCEPTION 'memory not found, or you have no valid authority to decide on it' USING ERRCODE = '42501';
  END IF;
  IF m.status NOT IN ('active', 'proposed') THEN
    RAISE EXCEPTION 'this version is no longer active; review the current one' USING ERRCODE = '55000';
  END IF;
  IF m.approval_state IN ('approved', 'rejected') THEN
    RAISE EXCEPTION 'this memory was already %', m.approval_state USING ERRCODE = '55000';
  END IF;
  IF m.content_sha256 <> p_content_sha256 OR memory.memory_version(m.id) <> p_memory_version THEN
    RAISE EXCEPTION 'this memory is not the text you were shown' USING ERRCODE = '55000';
  END IF;
  IF m.status = 'proposed' THEN
    SELECT * INTO b FROM memory.memories bb WHERE bb.id = m.supersedes_id;
    IF NOT FOUND OR b.status <> 'active' OR b.approval_state <> 'approved' OR b.namespace_id <> m.namespace_id THEN
      RAISE EXCEPTION 'the approved version this revision would replace has changed; review the current one'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  -- 256 random bits from the server's strong random source.
  v_secret := uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid());
  v_expires := now() + interval '10 minutes';
  BEGIN
    INSERT INTO memory.approval_challenges (actor_id, namespace_id, memory_id, memory_version, content_sha256,
        action, authority_id, secret_sha256, sign_in_hash, expires_at, base_memory_id)
    VALUES (v_actor, m.namespace_id, m.id, p_memory_version, m.content_sha256, p_action, v_authority,
        sha256(v_secret), sha256(uuid_send(p_session_id)), v_expires, b.id)
    RETURNING id INTO v_id;
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'this sign-in was already used; sign in again' USING ERRCODE = '42501';
  END;
  RETURN QUERY SELECT v_id, encode(v_secret, 'hex'), v_expires;
END
$$;

-- ── Deciding ────────────────────────────────────────────────────────────────

-- 0018's decision. For a proposal it also locks the approved version it would
-- replace, refuses a stale one, and on approval swaps the two.
CREATE OR REPLACE FUNCTION memory.decide_approval_challenge(
  p_user_id uuid, p_session_id uuid, p_challenge_id uuid, p_secret text
) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  c memory.approval_challenges;
  m memory.memories;
  b memory.memories;
  v_link uuid;
  v_chain_expires timestamptz;
  l record;
  v_id uuid;
BEGIN
  IF p_secret IS NULL OR p_secret !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'pass the challenge secret, as 64 lowercase hex digits' USING ERRCODE = '22023';
  END IF;
  v_actor := memory.consume_human_sign_in(p_user_id, p_session_id, 'approve');

  -- Someone else's challenge, a wrong secret, another sign-in and no
  -- challenge all give the same answer.
  SELECT * INTO c FROM memory.approval_challenges x WHERE x.id = p_challenge_id FOR UPDATE;
  IF NOT FOUND OR c.actor_id <> v_actor
     OR c.sign_in_hash <> sha256(uuid_send(p_session_id))
     OR c.secret_sha256 <> sha256(decode(p_secret, 'hex')) THEN
    RAISE EXCEPTION 'no such challenge for this sign-in' USING ERRCODE = '42501';
  END IF;
  IF EXISTS (SELECT 1 FROM memory.approvals a WHERE a.challenge_id = c.id) THEN
    RAISE EXCEPTION 'this challenge was already used' USING ERRCODE = '55000';
  END IF;
  -- Deadlines are read from the wall clock: now() stays at the moment the
  -- transaction began, which can be long before this call.
  IF c.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'this challenge has expired; review the memory again' USING ERRCODE = '55000';
  END IF;

  -- Hold the authority chain and its holders still until the decision is
  -- recorded, so a revocation or a disabled holder racing this call either
  -- lands first and is seen, or waits until after.
  v_link := c.authority_id;
  WHILE v_link IS NOT NULL LOOP
    SELECT a.id, a.parent_id, a.actor_id, a.expires_at INTO l
    FROM memory.approval_authorities a WHERE a.id = v_link FOR SHARE;
    PERFORM 1 FROM memory.actors x WHERE x.id = l.actor_id FOR SHARE;
    v_chain_expires := least(v_chain_expires, l.expires_at);
    v_link := l.parent_id;
  END LOOP;
  IF NOT memory.approval_authority_valid(c.authority_id) THEN
    RAISE EXCEPTION 'the authority this challenge was issued under is no longer valid' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO m FROM memory.memories mm WHERE mm.id = c.memory_id FOR UPDATE;
  IF m.status NOT IN ('active', 'proposed') OR (m.status = 'proposed') <> (c.base_memory_id IS NOT NULL) THEN
    RAISE EXCEPTION 'this version is no longer active; review the current one' USING ERRCODE = '55000';
  END IF;
  IF m.approval_state IN ('approved', 'rejected') THEN
    RAISE EXCEPTION 'this memory was already %', m.approval_state USING ERRCODE = '55000';
  END IF;
  IF m.content_sha256 <> c.content_sha256 OR m.namespace_id <> c.namespace_id
     OR memory.memory_version(m.id) <> c.memory_version THEN
    RAISE EXCEPTION 'this memory is not the text you were shown' USING ERRCODE = '55000';
  END IF;

  -- A proposed revision replaces exactly the approved version it was reviewed
  -- against. If that version was replaced meanwhile, by a competing revision,
  -- this one is stale and needs a fresh review. Locked after the proposal, so
  -- two competing revisions decided at once are decided one after the other.
  IF m.status = 'proposed' THEN
    SELECT * INTO b FROM memory.memories bb WHERE bb.id = c.base_memory_id FOR UPDATE;
    IF m.supersedes_id IS DISTINCT FROM c.base_memory_id OR b.status <> 'active'
       OR b.approval_state <> 'approved' OR b.namespace_id <> m.namespace_id THEN
      RAISE EXCEPTION 'the approved version this revision would replace has changed; review the current one'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  -- Waiting for the locks above can take time, so both deadlines are checked
  -- once more against the wall clock, just before the decision is recorded.
  IF c.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'this challenge has expired; review the memory again' USING ERRCODE = '55000';
  END IF;
  IF v_chain_expires <= clock_timestamp() THEN
    RAISE EXCEPTION 'the authority this challenge was issued under is no longer valid' USING ERRCODE = '55000';
  END IF;

  INSERT INTO memory.approvals (memory_id, namespace_id, action, scope, claim_type, content_sha256,
      decided_by_actor_id, authority_id, request_id, sign_in_hash, challenge_id)
  VALUES (m.id, m.namespace_id, c.action, memory.approval_scope_for(m.namespace_id), m.claim_type,
      m.content_sha256, v_actor, c.authority_id,
      (SELECT r.id FROM memory.approval_requests r WHERE r.memory_id = m.id),
      c.sign_in_hash, c.id)
  RETURNING id INTO v_id;
  UPDATE memory.memories
  SET approval_state = CASE c.action WHEN 'approve' THEN 'approved'::memory.approval_state
                                     ELSE 'rejected'::memory.approval_state END
  WHERE id = m.id;
  -- Approving a revision makes it current and the version it replaces
  -- superseded, in this same transaction. A rejected revision changes nothing
  -- else and stays on record as proposed and rejected.
  IF m.status = 'proposed' AND c.action = 'approve' THEN
    UPDATE memory.memories SET status = 'superseded' WHERE id = b.id;
    UPDATE memory.memories SET status = 'active' WHERE id = m.id;
  END IF;
  RETURN v_id;
END
$$;

REVOKE ALL ON FUNCTION memory.approval_review(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.approval_review(uuid, uuid, uuid) TO engramport_app;

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
