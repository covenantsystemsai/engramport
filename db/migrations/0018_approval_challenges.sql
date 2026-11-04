-- 0018: every approval decision consumes one exact, single-use challenge.
--
-- Founder decision D-03B. A decision on a memory is no longer one call with a
-- sign-in and a digest. It takes three steps, all with the same fresh Google
-- sign-in of the approver:
--
--   1. Review. memory.approval_review shows the approver the memory they may
--      decide on: its text, digest, version and where it lives. Nothing is
--      spent or recorded.
--   2. Challenge. When the approver picks approve or reject,
--      memory.issue_approval_challenge records a challenge bound to the
--      approver, namespace, action, memory id, version, content digest, the
--      authority it is issued under, the sign-in, and an expiry. It returns a
--      random secret that only the page holds. One sign-in issues at most one
--      challenge, so a sign-in is for one named act.
--   3. Decide. memory.decide_approval_challenge spends the sign-in and the
--      challenge together, once. It is refused unless the challenge, its
--      secret and the sign-in match, the challenge is unexpired and unused,
--      the memory is still that active, undecided version with that digest,
--      and the authority is still valid at every link.
--
-- So a challenge can't be replayed (it is consumed atomically with the
-- decision, and the sign-in with it), can't be used by anyone else (it is
-- bound to one person's sign-in and a secret), and dies when what it is bound
-- to changes: a new version, a retraction, another decision, a revocation, an
-- expiry or a disabled approver. No agent can approve: every step needs a
-- person's own fresh Google sign-in, and none is an MCP tool.
--
-- memory.record_approval from 0016 is removed: there is no other way to decide.
-- Challenges are records, never changed or deleted. The admin sees who was
-- issued a challenge for which memory and action, under which authority, when
-- it expires and whether it was used, never the text, digest, secret or
-- sign-in.

DROP FUNCTION memory.record_approval(uuid, uuid, uuid, memory.approval_action, text);

-- The version of a memory: 1 for the first, one more for each memory it
-- supersedes in turn.
CREATE FUNCTION memory.memory_version(p_memory_id uuid) RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  WITH RECURSIVE chain AS (
    SELECT m.id, m.supersedes_id, 1 AS depth FROM memory.memories m WHERE m.id = p_memory_id
    UNION ALL
    SELECT p.id, p.supersedes_id, c.depth + 1
    FROM memory.memories p JOIN chain c ON p.id = c.supersedes_id
    WHERE c.depth < 100000
  )
  SELECT max(depth) FROM chain
$$;

CREATE TABLE memory.approval_challenges (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  actor_id uuid NOT NULL REFERENCES memory.actors(id),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  memory_id uuid NOT NULL REFERENCES memory.memories(id),
  memory_version integer NOT NULL CHECK (memory_version >= 1),
  content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  action memory.approval_action NOT NULL,
  authority_id uuid NOT NULL REFERENCES memory.approval_authorities(id),
  secret_sha256 bytea NOT NULL UNIQUE CHECK (length(secret_sha256) = 32),
  sign_in_hash bytea NOT NULL UNIQUE CHECK (length(sign_in_hash) = 32),
  issued_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  CHECK (expires_at > issued_at)
);
CREATE INDEX approval_challenges_actor ON memory.approval_challenges (actor_id);
CREATE INDEX approval_challenges_namespace ON memory.approval_challenges (namespace_id, issued_at);
CREATE INDEX approval_challenges_memory ON memory.approval_challenges (memory_id);
CREATE INDEX approval_challenges_authority ON memory.approval_challenges (authority_id);
CREATE TRIGGER approval_challenges_kept BEFORE UPDATE OR DELETE ON memory.approval_challenges
  FOR EACH ROW EXECUTE FUNCTION memory.approval_record_kept();
CREATE TRIGGER approval_challenges_kept_all BEFORE TRUNCATE ON memory.approval_challenges
  FOR EACH STATEMENT EXECUTE FUNCTION memory.approval_record_kept();

-- Each decision consumed exactly one challenge. 0016's approvals were never
-- applied to a real database, so the column can start NOT NULL.
ALTER TABLE memory.approvals ADD COLUMN challenge_id uuid NOT NULL UNIQUE REFERENCES memory.approval_challenges(id);

-- The person behind a fresh, unspent sign-in, with the same answers as
-- memory.consume_human_sign_in, without spending it.
CREATE FUNCTION memory.unspent_human_sign_in(p_user_id uuid, p_session_id uuid) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_email text := memory.oauth_signed_in_email(p_user_id, p_session_id);
  v_actors uuid[];
BEGIN
  IF v_email IS NULL THEN
    RAISE EXCEPTION 'this needs a fresh Google sign-in' USING ERRCODE = '42501';
  END IF;
  SELECT array_agg(DISTINCT m.actor_id) INTO v_actors
  FROM memory.oauth_members m JOIN memory.actors a ON a.id = m.actor_id
  WHERE m.email = v_email AND m.revoked_at IS NULL AND a.kind = 'human' AND a.disabled_at IS NULL;
  IF coalesce(cardinality(v_actors), 0) <> 1 THEN
    RAISE EXCEPTION 'this sign-in is not one enabled person' USING ERRCODE = '42501';
  END IF;
  IF (SELECT count(DISTINCT m.email) FROM memory.oauth_members m
      WHERE m.actor_id = v_actors[1] AND m.revoked_at IS NULL) <> 1 THEN
    RAISE EXCEPTION 'more than one email can sign in as this person; give each person their own actor'
      USING ERRCODE = '42501';
  END IF;
  IF EXISTS (SELECT 1 FROM memory.human_sign_ins_used u WHERE u.session_hash = sha256(uuid_send(p_session_id))) THEN
    RAISE EXCEPTION 'this sign-in was already used; sign in again' USING ERRCODE = '42501';
  END IF;
  RETURN v_actors[1];
END
$$;

-- The authority this person holds that covers this memory, or NULL. The same
-- choice 0016 made: the person's own grant before a delegation, oldest first.
CREATE FUNCTION memory.approval_authority_for(p_actor uuid, p_namespace_id uuid, p_claim_type memory.claim_type)
RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT a.id
  FROM memory.approval_authorities a
  WHERE a.actor_id = p_actor
    AND a.scope = memory.approval_scope_for(p_namespace_id)
    AND a.namespace_id IN (SELECT memory.namespace_and_ancestors(p_namespace_id))
    AND (a.claim_types IS NULL OR p_claim_type = ANY (a.claim_types))
    AND memory.approval_authority_valid(a.id)
  ORDER BY (a.parent_id IS NOT NULL), a.created_at
  LIMIT 1
$$;

-- Step 1: what the approval page shows. Someone with no authority over the
-- memory gets the same answer whether or not it exists.
CREATE FUNCTION memory.approval_review(p_user_id uuid, p_session_id uuid, p_memory_id uuid)
RETURNS TABLE (memory_id uuid, namespace_path text, kind memory.memory_kind, claim_type memory.claim_type,
               content text, content_sha256 text, memory_version integer, status memory.memory_status,
               approval_state memory.approval_state, requested_at timestamptz, scope memory.approval_scope,
               created_at timestamptz)
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
         memory.approval_scope_for(m.namespace_id), m.created_at
  FROM memory.namespaces n WHERE n.id = m.namespace_id;
END
$$;

-- Step 2: the approver has reviewed this version and picked an action. The
-- secret comes back once and is never stored, only its hash.
CREATE FUNCTION memory.issue_approval_challenge(
  p_user_id uuid, p_session_id uuid, p_memory_id uuid, p_action memory.approval_action,
  p_content_sha256 text, p_memory_version integer
) RETURNS TABLE (challenge_id uuid, secret text, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  m memory.memories;
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
  IF m.status <> 'active' THEN
    RAISE EXCEPTION 'this version is no longer active; review the current one' USING ERRCODE = '55000';
  END IF;
  IF m.approval_state IN ('approved', 'rejected') THEN
    RAISE EXCEPTION 'this memory was already %', m.approval_state USING ERRCODE = '55000';
  END IF;
  IF m.content_sha256 <> p_content_sha256 OR memory.memory_version(m.id) <> p_memory_version THEN
    RAISE EXCEPTION 'this memory is not the text you were shown' USING ERRCODE = '55000';
  END IF;

  -- 256 random bits from the server's strong random source.
  v_secret := uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid());
  v_expires := now() + interval '10 minutes';
  BEGIN
    INSERT INTO memory.approval_challenges (actor_id, namespace_id, memory_id, memory_version, content_sha256,
        action, authority_id, secret_sha256, sign_in_hash, expires_at)
    VALUES (v_actor, m.namespace_id, m.id, p_memory_version, m.content_sha256, p_action, v_authority,
        sha256(v_secret), sha256(uuid_send(p_session_id)), v_expires)
    RETURNING id INTO v_id;
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'this sign-in was already used; sign in again' USING ERRCODE = '42501';
  END;
  RETURN QUERY SELECT v_id, encode(v_secret, 'hex'), v_expires;
END
$$;

-- Step 3: the approver confirms. The sign-in and the challenge are spent
-- together, or nothing is.
CREATE FUNCTION memory.decide_approval_challenge(
  p_user_id uuid, p_session_id uuid, p_challenge_id uuid, p_secret text
) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  c memory.approval_challenges;
  m memory.memories;
  v_link uuid;
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
  IF c.expires_at <= now() THEN
    RAISE EXCEPTION 'this challenge has expired; review the memory again' USING ERRCODE = '55000';
  END IF;

  -- Hold the authority chain and its holders still until the decision is
  -- recorded, so a revocation or a disabled holder racing this call either
  -- lands first and is seen, or waits until after.
  v_link := c.authority_id;
  WHILE v_link IS NOT NULL LOOP
    SELECT a.id, a.parent_id, a.actor_id INTO l FROM memory.approval_authorities a WHERE a.id = v_link FOR SHARE;
    PERFORM 1 FROM memory.actors x WHERE x.id = l.actor_id FOR SHARE;
    v_link := l.parent_id;
  END LOOP;
  IF NOT memory.approval_authority_valid(c.authority_id) THEN
    RAISE EXCEPTION 'the authority this challenge was issued under is no longer valid' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO m FROM memory.memories mm WHERE mm.id = c.memory_id FOR UPDATE;
  IF m.status <> 'active' THEN
    RAISE EXCEPTION 'this version is no longer active; review the current one' USING ERRCODE = '55000';
  END IF;
  IF m.approval_state IN ('approved', 'rejected') THEN
    RAISE EXCEPTION 'this memory was already %', m.approval_state USING ERRCODE = '55000';
  END IF;
  IF m.content_sha256 <> c.content_sha256 OR m.namespace_id <> c.namespace_id
     OR memory.memory_version(m.id) <> c.memory_version THEN
    RAISE EXCEPTION 'this memory is not the text you were shown' USING ERRCODE = '55000';
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
  RETURN v_id;
END
$$;

-- 0016's trust guard, unchanged apart from its hint, which named the function
-- removed above.
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
            HINT = 'a memory is approved or rejected only by a person, on the approval page';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION memory.memories_trust_guard() FROM PUBLIC;

-- Row security: the server never reads challenges directly. The admin reads
-- who, which memory, which action, under which authority and when; never the
-- digest, the secret or the sign-in.
ALTER TABLE memory.approval_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.approval_challenges FORCE ROW LEVEL SECURITY;
GRANT SELECT (id, actor_id, namespace_id, memory_id, memory_version, action, authority_id, issued_at, expires_at)
  ON memory.approval_challenges TO engramport_admin;
CREATE POLICY approval_challenges_admin_read ON memory.approval_challenges
  FOR SELECT TO engramport_admin USING (true);
GRANT SELECT (challenge_id) ON memory.approvals TO engramport_admin;

REVOKE ALL ON FUNCTION memory.memory_version(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.unspent_human_sign_in(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.approval_authority_for(uuid, uuid, memory.claim_type) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.approval_review(uuid, uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.issue_approval_challenge(uuid, uuid, uuid, memory.approval_action, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.decide_approval_challenge(uuid, uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.approval_review(uuid, uuid, uuid) TO engramport_app;
GRANT EXECUTE ON FUNCTION memory.issue_approval_challenge(uuid, uuid, uuid, memory.approval_action, text, integer)
  TO engramport_app;
GRANT EXECUTE ON FUNCTION memory.decide_approval_challenge(uuid, uuid, uuid, text) TO engramport_app;

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
