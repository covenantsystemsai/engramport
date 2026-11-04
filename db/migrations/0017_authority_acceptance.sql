-- 0017: a granted approver accepts the exact grant before it counts.
--
-- Founder decision D-03A. Granting approval authority (by the admin role, or a
-- delegation by an owner) only offers it. The person it names must accept it
-- with their own fresh Google sign-in before it confers anything:
--
--   * The person sees the grant and its fingerprint: namespace, scope, claim
--     types, whether it may be delegated, expiry, and the authority it was
--     delegated from. Accepting takes that fingerprint back, so an acceptance
--     binds to exactly the grant that was shown. Grants never change in place
--     (0015), so the fingerprint can only fail to match a different grant.
--   * Accept or reject, once. A pending, rejected, expired or revoked grant
--     confers no approval authority, and neither does anything delegated from
--     it. A rejected grant stays rejected; a new offer is a new grant.
--   * Only the holder can decide, through their own sign-in, which is spent as
--     with every other authority act. No agent, key, server or admin can
--     accept for them.
--   * The decision is a record: never changed or deleted, by any role. The
--     admin sees whether each grant is pending, accepted or rejected, and when,
--     and still reads no memory content.

ALTER TABLE memory.human_sign_ins_used DROP CONSTRAINT human_sign_ins_used_purpose_check;
ALTER TABLE memory.human_sign_ins_used ADD CONSTRAINT human_sign_ins_used_purpose_check
  CHECK (purpose IN ('approve', 'delegate', 'revoke', 'connect', 'accept'));

CREATE TABLE memory.approval_authority_decisions (
  authority_id uuid PRIMARY KEY REFERENCES memory.approval_authorities(id),
  actor_id uuid NOT NULL REFERENCES memory.actors(id),
  decision text NOT NULL CHECK (decision IN ('accept', 'reject')),
  grant_sha256 text NOT NULL CHECK (grant_sha256 ~ '^[0-9a-f]{64}$'),
  sign_in_hash bytea NOT NULL UNIQUE REFERENCES memory.human_sign_ins_used(session_hash),
  decided_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX approval_authority_decisions_actor ON memory.approval_authority_decisions (actor_id);
CREATE TRIGGER approval_authority_decisions_kept BEFORE UPDATE OR DELETE ON memory.approval_authority_decisions
  FOR EACH ROW EXECUTE FUNCTION memory.approval_record_kept();
CREATE TRIGGER approval_authority_decisions_kept_all BEFORE TRUNCATE ON memory.approval_authority_decisions
  FOR EACH STATEMENT EXECUTE FUNCTION memory.approval_record_kept();

-- The fingerprint of a grant: every term the holder accepts, in a fixed form.
-- Times are written in UTC whatever the session's time zone.
CREATE FUNCTION memory.approval_authority_grant_sha256(p_id uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog SET timezone = 'UTC' AS $$
  SELECT encode(sha256(convert_to(jsonb_build_object(
           'authority', a.id,
           'holder', a.actor_id,
           'namespace', n.path,
           'scope', a.scope,
           'claim_types', a.claim_types,
           'can_delegate', a.can_delegate,
           'expires_at', to_char(a.expires_at, 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
           'delegated_from', a.parent_id,
           'granted_by', a.granted_by_actor_id)::text, 'UTF8')), 'hex')
  FROM memory.approval_authorities a JOIN memory.namespaces n ON n.id = a.namespace_id
  WHERE a.id = p_id
$$;

-- Now also: every authority in the chain was accepted by its holder.
CREATE OR REPLACE FUNCTION memory.approval_authority_valid(p_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  WITH RECURSIVE chain AS (
    SELECT a.id, a.parent_id, a.actor_id, a.revoked_at, a.expires_at
    FROM memory.approval_authorities a WHERE a.id = p_id
    UNION ALL
    SELECT p.id, p.parent_id, p.actor_id, p.revoked_at, p.expires_at
    FROM memory.approval_authorities p JOIN chain c ON p.id = c.parent_id
  )
  SELECT EXISTS (SELECT 1 FROM chain)
     AND NOT EXISTS (
       SELECT 1 FROM chain c JOIN memory.actors a ON a.id = c.actor_id
       LEFT JOIN memory.approval_authority_decisions d ON d.authority_id = c.id
       WHERE c.revoked_at IS NOT NULL
          OR (c.expires_at IS NOT NULL AND c.expires_at <= now())
          OR a.kind <> 'human' OR a.disabled_at IS NOT NULL
          OR d.decision IS DISTINCT FROM 'accept'
          OR d.actor_id <> c.actor_id)
$$;

-- The person a sign-in belongs to, without spending it: the same checks as
-- memory.consume_human_sign_in. NULL when it is not one enabled person.
CREATE FUNCTION memory.signed_in_human(p_user_id uuid, p_session_id uuid) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_email text := memory.oauth_signed_in_email(p_user_id, p_session_id);
  v_actors uuid[];
BEGIN
  IF v_email IS NULL THEN
    RETURN NULL;
  END IF;
  SELECT array_agg(DISTINCT m.actor_id) INTO v_actors
  FROM memory.oauth_members m JOIN memory.actors a ON a.id = m.actor_id
  WHERE m.email = v_email AND m.revoked_at IS NULL AND a.kind = 'human' AND a.disabled_at IS NULL;
  IF coalesce(cardinality(v_actors), 0) <> 1
     OR (SELECT count(DISTINCT m.email) FROM memory.oauth_members m
         WHERE m.actor_id = v_actors[1] AND m.revoked_at IS NULL) <> 1 THEN
    RETURN NULL;
  END IF;
  RETURN v_actors[1];
END
$$;

-- What the signed-in person has been offered and not yet decided: what the
-- acceptance page shows them. Only offers that could still become valid.
CREATE FUNCTION memory.pending_authority_grants(p_user_id uuid, p_session_id uuid)
RETURNS TABLE (authority_id uuid, namespace_path text, scope memory.approval_scope,
               claim_types memory.claim_type[], can_delegate boolean, expires_at timestamptz,
               delegated_from uuid, granted_at timestamptz, grant_sha256 text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT a.id, n.path, a.scope, a.claim_types, a.can_delegate, a.expires_at, a.parent_id, a.created_at,
         memory.approval_authority_grant_sha256(a.id)
  FROM memory.approval_authorities a JOIN memory.namespaces n ON n.id = a.namespace_id
  WHERE a.actor_id = memory.signed_in_human(p_user_id, p_session_id)
    AND a.revoked_at IS NULL
    AND (a.expires_at IS NULL OR a.expires_at > now())
    AND (a.parent_id IS NULL OR memory.approval_authority_valid(a.parent_id))
    AND NOT EXISTS (SELECT 1 FROM memory.approval_authority_decisions d WHERE d.authority_id = a.id)
  ORDER BY a.created_at
$$;

-- The holder accepts or rejects one grant, with a fresh sign-in and the
-- fingerprint of the grant they were shown.
CREATE FUNCTION memory.decide_approval_authority(
  p_user_id uuid, p_session_id uuid, p_authority_id uuid, p_decision text, p_grant_sha256 text
) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  a record;
BEGIN
  IF p_decision IS NULL OR p_decision NOT IN ('accept', 'reject') THEN
    RAISE EXCEPTION 'decide accept or reject' USING ERRCODE = '22023';
  END IF;
  IF p_grant_sha256 IS NULL OR p_grant_sha256 !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'pass the fingerprint of the grant you were shown, as 64 lowercase hex digits' USING ERRCODE = '22023';
  END IF;
  v_actor := memory.consume_human_sign_in(p_user_id, p_session_id, 'accept');

  -- Locked, so a revocation and a decision on the same grant happen one after
  -- the other. Someone else's grant and no grant give the same answer.
  SELECT * INTO a FROM memory.approval_authorities x WHERE x.id = p_authority_id FOR UPDATE;
  IF NOT FOUND OR a.actor_id <> v_actor THEN
    RAISE EXCEPTION 'no such grant was offered to you' USING ERRCODE = '42501';
  END IF;
  IF EXISTS (SELECT 1 FROM memory.approval_authority_decisions d WHERE d.authority_id = a.id) THEN
    RAISE EXCEPTION 'this grant was already decided' USING ERRCODE = '55000';
  END IF;
  IF a.revoked_at IS NOT NULL OR (a.expires_at IS NOT NULL AND a.expires_at <= now()) THEN
    RAISE EXCEPTION 'this grant was revoked or has expired' USING ERRCODE = '55000';
  END IF;
  IF p_decision = 'accept' AND a.parent_id IS NOT NULL AND NOT memory.approval_authority_valid(a.parent_id) THEN
    RAISE EXCEPTION 'the authority this was delegated from is no longer valid' USING ERRCODE = '55000';
  END IF;
  IF memory.approval_authority_grant_sha256(a.id) <> p_grant_sha256 THEN
    RAISE EXCEPTION 'this is not the grant you were shown; review it again' USING ERRCODE = '55000';
  END IF;
  INSERT INTO memory.approval_authority_decisions (authority_id, actor_id, decision, grant_sha256, sign_in_hash)
  VALUES (a.id, v_actor, p_decision, p_grant_sha256, sha256(uuid_send(p_session_id)));
END
$$;

-- Row security: the server never reads decisions directly; the admin reads
-- whether and when each grant was decided.
ALTER TABLE memory.approval_authority_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.approval_authority_decisions FORCE ROW LEVEL SECURITY;
GRANT SELECT (authority_id, actor_id, decision, decided_at) ON memory.approval_authority_decisions TO engramport_admin;
CREATE POLICY approval_authority_decisions_admin_read ON memory.approval_authority_decisions
  FOR SELECT TO engramport_admin USING (true);

REVOKE ALL ON FUNCTION memory.approval_authority_grant_sha256(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.signed_in_human(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.pending_authority_grants(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.decide_approval_authority(uuid, uuid, uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.approval_authority_valid(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.approval_authority_valid(uuid) TO engramport_admin;
GRANT EXECUTE ON FUNCTION memory.pending_authority_grants(uuid, uuid) TO engramport_app;
GRANT EXECUTE ON FUNCTION memory.decide_approval_authority(uuid, uuid, uuid, text, text) TO engramport_app;

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
