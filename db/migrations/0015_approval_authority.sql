-- Approval authority: who may approve memories, where, and how that is granted,
-- delegated and revoked. Forward-only; applied by db/migrate.sh in one transaction.
--
-- This migration records authority only. Approving a memory is the next
-- migration's job; it checks an authority here at the moment of approval.
--
-- The rules this implements (founder decision D-03):
--   * Approval is a human act. An authority belongs to a human actor, and is
--     only used through that person's own fresh Google sign-in, which the
--     database checks against Supabase Auth itself (memory.oauth_signed_in_email
--     from 0009). An agent's key, or a person's key held by an agent, never
--     counts: no function here takes a key as proof of a person.
--   * Each sign-in is used once. A second approval or delegation needs a new
--     sign-in, so nothing that was signed in for earlier can be replayed later.
--     A sign-in used to connect a client such as claude.ai is spent for
--     authority too, and the other way round: connecting hands a token to an
--     agent, so that same sign-in never also counts as a person approving.
--   * A person is the one Google email bound to a human actor. If more than one
--     email can sign in as that actor (say an assistant added to connect as the
--     owner), nobody can use the actor's authority until that is undone.
--   * Scopes are kept apart:
--       cell_knowledge      a client cell's owner approves business knowledge
--                           and requirements in that one cell.
--       company_governance  the founder approves within an assigned company
--                           namespace and the namespaces below it.
--       promotion           approving knowledge moving up to a tower or city.
--                           Granted separately, on a tower or city, and never
--                           usable to approve an ordinary memory.
--     None of these is an engineering, security, financial or deployment
--     approval. EngramPort records memory approvals and nothing else.
--   * The admin role grants and revokes top-level authority, and nothing else:
--     it cannot touch a delegation, and a revocation is stamped with the time
--     it happens. It is managing who may approve, and still reads no memory
--     content.
--   * An owner may delegate part of their authority, once, through an explicit
--     grant: the same namespace and scope, the same or fewer claim types, no
--     later expiry, and no further delegation.
--   * An authority is valid only while it and every authority above it is
--     unrevoked and unexpired and its holders are enabled human actors. So
--     revoking an owner's authority ends every delegation made from it, and
--     nothing approved with it from then on can go through.
--   * Rows are never deleted or edited, only revoked, so the trail stays whole.
--     That holds for every role, the table owner included.

CREATE TYPE memory.approval_scope AS ENUM ('cell_knowledge', 'company_governance', 'promotion');

CREATE TABLE memory.approval_authorities (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  actor_id uuid NOT NULL REFERENCES memory.actors(id),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  scope memory.approval_scope NOT NULL,
  -- NULL covers every claim type.
  claim_types memory.claim_type[] CHECK (claim_types IS NULL
                                         OR (cardinality(claim_types) > 0 AND array_position(claim_types, NULL) IS NULL)),
  can_delegate boolean NOT NULL DEFAULT false,
  -- Set on a delegated authority only; a top-level one is granted by the admin role.
  parent_id uuid REFERENCES memory.approval_authorities(id),
  granted_by_actor_id uuid REFERENCES memory.actors(id),
  expires_at timestamptz,
  revoked_at timestamptz,
  revoke_reason text CHECK (revoke_reason ~ '^[a-z_]{1,32}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)),
  CHECK ((parent_id IS NULL) = (granted_by_actor_id IS NULL)),
  CHECK (parent_id IS NULL OR NOT can_delegate),
  CHECK (expires_at IS NULL OR expires_at > created_at)
);
CREATE INDEX approval_authorities_actor ON memory.approval_authorities (actor_id);
CREATE INDEX approval_authorities_namespace ON memory.approval_authorities (namespace_id);
CREATE INDEX approval_authorities_parent ON memory.approval_authorities (parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX approval_authorities_granted_by ON memory.approval_authorities (granted_by_actor_id)
  WHERE granted_by_actor_id IS NOT NULL;

-- Where each scope may be granted, and what a delegation may hand on. Runs for
-- every role, the owner included.
CREATE FUNCTION memory.approval_authorities_shape() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  who record;
  ns record;
  parent record;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF (NEW.id, NEW.actor_id, NEW.namespace_id, NEW.scope, NEW.claim_types, NEW.can_delegate, NEW.parent_id,
        NEW.granted_by_actor_id, NEW.expires_at, NEW.created_at)
       IS DISTINCT FROM
       (OLD.id, OLD.actor_id, OLD.namespace_id, OLD.scope, OLD.claim_types, OLD.can_delegate, OLD.parent_id,
        OLD.granted_by_actor_id, OLD.expires_at, OLD.created_at) THEN
      RAISE EXCEPTION 'an approval authority does not change; revoke it and grant a new one' USING ERRCODE = '42501';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at, NEW.revoke_reason) IS DISTINCT FROM (OLD.revoked_at, OLD.revoke_reason) THEN
      RAISE EXCEPTION 'a revoked approval authority stays revoked' USING ERRCODE = '42501';
    END IF;
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
      -- Only the grantor's own revocation, through revoke_delegated_authority,
      -- may say so, and only on a delegation.
      IF (NEW.revoke_reason = 'revoked_by_grantor') <> (OLD.parent_id IS NOT NULL) THEN
        RAISE EXCEPTION 'a delegation is revoked by its grantor, and only a delegation says so' USING ERRCODE = '42501';
      END IF;
      -- A revocation happens now: it is never backdated or set ahead.
      NEW.revoked_at := now();
    END IF;
    RETURN NEW;
  END IF;

  SELECT a.kind, a.disabled_at INTO who FROM memory.actors a WHERE a.id = NEW.actor_id;
  IF NOT FOUND OR who.kind <> 'human' OR who.disabled_at IS NOT NULL THEN
    RAISE EXCEPTION 'only an enabled human actor can hold approval authority' USING ERRCODE = '42501';
  END IF;
  SELECT n.level, n.purpose INTO ns FROM memory.namespaces n WHERE n.id = NEW.namespace_id;
  IF NEW.scope = 'cell_knowledge' AND NOT (ns.level = 'cell' AND ns.purpose = 'client') THEN
    RAISE EXCEPTION 'cell_knowledge authority is granted on a client cell' USING ERRCODE = '23514';
  ELSIF NEW.scope = 'company_governance' AND ns.purpose <> 'company' THEN
    RAISE EXCEPTION 'company_governance authority is granted on a company namespace' USING ERRCODE = '23514';
  ELSIF NEW.scope = 'promotion' AND ns.level NOT IN ('tower', 'city') THEN
    RAISE EXCEPTION 'promotion authority is granted on a tower or a city' USING ERRCODE = '23514';
  END IF;
  IF NEW.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'a new approval authority starts unrevoked' USING ERRCODE = '23514';
  END IF;

  IF NEW.parent_id IS NOT NULL THEN
    SELECT * INTO parent FROM memory.approval_authorities p WHERE p.id = NEW.parent_id;
    IF NOT parent.can_delegate OR NOT memory.approval_authority_valid(parent.id) THEN
      RAISE EXCEPTION 'that authority cannot be delegated' USING ERRCODE = '42501';
    END IF;
    IF NEW.granted_by_actor_id <> parent.actor_id THEN
      RAISE EXCEPTION 'only the holder of an authority can delegate it' USING ERRCODE = '42501';
    END IF;
    IF NEW.namespace_id <> parent.namespace_id OR NEW.scope <> parent.scope THEN
      RAISE EXCEPTION 'a delegation keeps its authority''s namespace and scope' USING ERRCODE = '42501';
    END IF;
    IF parent.claim_types IS NOT NULL AND (NEW.claim_types IS NULL OR NOT NEW.claim_types <@ parent.claim_types) THEN
      RAISE EXCEPTION 'a delegation cannot cover claim types its authority does not' USING ERRCODE = '42501';
    END IF;
    IF parent.expires_at IS NOT NULL AND (NEW.expires_at IS NULL OR NEW.expires_at > parent.expires_at) THEN
      RAISE EXCEPTION 'a delegation cannot outlast its authority' USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

-- An authority counts only while it and every authority it was delegated
-- from is unrevoked, unexpired and held by an enabled human actor.
CREATE FUNCTION memory.approval_authority_valid(p_id uuid) RETURNS boolean
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
       WHERE c.revoked_at IS NOT NULL
          OR (c.expires_at IS NOT NULL AND c.expires_at <= now())
          OR a.kind <> 'human' OR a.disabled_at IS NOT NULL)
$$;

CREATE TRIGGER approval_authorities_shape BEFORE INSERT OR UPDATE ON memory.approval_authorities
  FOR EACH ROW EXECUTE FUNCTION memory.approval_authorities_shape();

-- The record is kept whole: no role deletes or truncates it, the owner included.
CREATE FUNCTION memory.approval_record_kept() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION '% is a record and is never deleted', TG_TABLE_NAME USING ERRCODE = '42501';
END
$$;
CREATE TRIGGER approval_authorities_kept BEFORE DELETE ON memory.approval_authorities
  FOR EACH ROW EXECUTE FUNCTION memory.approval_record_kept();
CREATE TRIGGER approval_authorities_kept_all BEFORE TRUNCATE ON memory.approval_authorities
  FOR EACH STATEMENT EXECUTE FUNCTION memory.approval_record_kept();

-- ── One sign-in, one act ────────────────────────────────────────────────────

-- Supabase sessions already used: to approve, delegate or revoke, or to
-- connect a client. Only a hash of the session id is kept.
CREATE TABLE memory.human_sign_ins_used (
  session_hash bytea PRIMARY KEY CHECK (octet_length(session_hash) = 32),
  actor_id uuid NOT NULL REFERENCES memory.actors(id),
  purpose text NOT NULL CHECK (purpose IN ('approve', 'delegate', 'revoke', 'connect')),
  used_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX human_sign_ins_used_actor ON memory.human_sign_ins_used (actor_id);
CREATE TRIGGER human_sign_ins_used_kept BEFORE UPDATE OR DELETE ON memory.human_sign_ins_used
  FOR EACH ROW EXECUTE FUNCTION memory.approval_record_kept();
CREATE TRIGGER human_sign_ins_used_kept_all BEFORE TRUNCATE ON memory.human_sign_ins_used
  FOR EACH STATEMENT EXECUTE FUNCTION memory.approval_record_kept();

-- The human actor behind a fresh Google sign-in, used up by this call. The
-- email must belong to exactly one enabled human actor through an unrevoked
-- sign-in membership (0009). Not granted to anyone: only the definer
-- functions below call it.
CREATE FUNCTION memory.consume_human_sign_in(p_user_id uuid, p_session_id uuid, p_purpose text) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_email text;
  v_actors uuid[];
BEGIN
  v_email := memory.oauth_signed_in_email(p_user_id, p_session_id);
  IF v_email IS NULL THEN
    RAISE EXCEPTION 'this needs a fresh Google sign-in' USING ERRCODE = '42501';
  END IF;
  SELECT array_agg(DISTINCT m.actor_id) INTO v_actors
  FROM memory.oauth_members m JOIN memory.actors a ON a.id = m.actor_id
  WHERE m.email = v_email AND m.revoked_at IS NULL AND a.kind = 'human' AND a.disabled_at IS NULL;
  IF coalesce(cardinality(v_actors), 0) <> 1 THEN
    RAISE EXCEPTION 'this sign-in is not one enabled person' USING ERRCODE = '42501';
  END IF;
  -- A person is one email. An actor that another email can also sign in as
  -- (an assistant added to connect as the owner, say) acts for no one.
  IF (SELECT count(DISTINCT m.email) FROM memory.oauth_members m
      WHERE m.actor_id = v_actors[1] AND m.revoked_at IS NULL) <> 1 THEN
    RAISE EXCEPTION 'more than one email can sign in as this person; give each person their own actor'
      USING ERRCODE = '42501';
  END IF;
  BEGIN
    INSERT INTO memory.human_sign_ins_used (session_hash, actor_id, purpose)
    VALUES (sha256(uuid_send(p_session_id)), v_actors[1], p_purpose);
  EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'this sign-in was already used; sign in again' USING ERRCODE = '42501';
  END;
  RETURN v_actors[1];
END
$$;

-- Connecting a client spends the sign-in for authority acts, and a sign-in
-- already spent on one cannot connect. 0009's body is unchanged apart from the
-- two marked lines. One sign-in may still connect several clients.
CREATE OR REPLACE FUNCTION memory.oauth_issue_code(
  p_user_id uuid, p_session_id uuid, p_client_id text, p_member_id uuid, p_redirect_uri text,
  p_code_challenge text, p_resource text, p_scopes text[], p_code_hash bytea
) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_client uuid;
  v_member memory.oauth_members;
  v_email text := memory.oauth_signed_in_email(p_user_id, p_session_id);
BEGIN
  IF v_email IS NULL THEN
    RETURN false;
  END IF;
  SELECT c.id INTO v_client FROM memory.oauth_clients c
  WHERE c.client_id = p_client_id AND p_redirect_uri = ANY (c.redirect_uris);
  IF v_client IS NULL THEN
    RETURN false;
  END IF;
  SELECT m.* INTO v_member FROM memory.oauth_members m JOIN memory.actors a ON a.id = m.actor_id
  WHERE m.id = p_member_id AND m.revoked_at IS NULL AND a.disabled_at IS NULL AND m.email = v_email;
  IF v_member.id IS NULL OR p_scopes IS NULL OR NOT (p_scopes <@ v_member.scopes) THEN
    RETURN false;
  END IF;
  -- (0015) not a sign-in already spent on an authority act; mark it as a connect.
  IF EXISTS (SELECT 1 FROM memory.human_sign_ins_used u
             WHERE u.session_hash = sha256(uuid_send(p_session_id)) AND u.purpose <> 'connect') THEN
    RETURN false;
  END IF;
  INSERT INTO memory.human_sign_ins_used (session_hash, actor_id, purpose)
  VALUES (sha256(uuid_send(p_session_id)), v_member.actor_id, 'connect')
  ON CONFLICT (session_hash) DO NOTHING;
  INSERT INTO memory.oauth_codes (code_hash, client_id, member_id, redirect_uri, code_challenge, resource, scopes, expires_at)
  VALUES (p_code_hash, v_client, v_member.id, p_redirect_uri, p_code_challenge, p_resource, p_scopes,
          now() + interval '5 minutes');
  RETURN true;
END
$$;
REVOKE ALL ON FUNCTION memory.oauth_issue_code(uuid, uuid, text, uuid, text, text, text, text[], bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.oauth_issue_code(uuid, uuid, text, uuid, text, text, text, text[], bytea)
  TO engramport_app;

-- ── Delegation and revocation by a holder ───────────────────────────────────

-- The signed-in holder of a delegable authority hands part of it to another
-- person. Claim types and expiry default to the authority's own.
CREATE FUNCTION memory.delegate_approval_authority(
  p_user_id uuid,
  p_session_id uuid,
  p_authority_id uuid,
  p_grantee_actor_id uuid,
  p_claim_types memory.claim_type[] DEFAULT NULL,
  p_expires_at timestamptz DEFAULT NULL
) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  parent record;
  v_id uuid;
BEGIN
  v_actor := memory.consume_human_sign_in(p_user_id, p_session_id, 'delegate');
  SELECT * INTO parent FROM memory.approval_authorities a WHERE a.id = p_authority_id;
  IF NOT FOUND OR parent.actor_id <> v_actor THEN
    RAISE EXCEPTION 'you do not hold that authority' USING ERRCODE = '42501';
  END IF;
  INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, claim_types, can_delegate, parent_id,
      granted_by_actor_id, expires_at)
  VALUES (p_grantee_actor_id, parent.namespace_id, parent.scope, coalesce(p_claim_types, parent.claim_types), false,
      parent.id, v_actor, coalesce(p_expires_at, parent.expires_at))
  RETURNING id INTO v_id;
  RETURN v_id;
END
$$;

-- The signed-in holder of an authority revokes a delegation they made.
CREATE FUNCTION memory.revoke_delegated_authority(p_user_id uuid, p_session_id uuid, p_authority_id uuid)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
BEGIN
  v_actor := memory.consume_human_sign_in(p_user_id, p_session_id, 'revoke');
  UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'revoked_by_grantor'
  WHERE id = p_authority_id AND granted_by_actor_id = v_actor AND revoked_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no active delegation of yours with that id' USING ERRCODE = '42501';
  END IF;
END
$$;

-- ── Access ──────────────────────────────────────────────────────────────────

ALTER TABLE memory.approval_authorities ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.approval_authorities FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.human_sign_ins_used ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.human_sign_ins_used FORCE ROW LEVEL SECURITY;

-- The admin role grants and revokes top-level authority and reads the list.
-- It cannot write a delegation (parent_id and granted_by_actor_id aren't
-- granted), and cannot revoke one either: only its grantor does that.
GRANT SELECT ON memory.approval_authorities TO engramport_admin;
GRANT INSERT (actor_id, namespace_id, scope, claim_types, can_delegate, expires_at)
  ON memory.approval_authorities TO engramport_admin;
GRANT UPDATE (revoked_at, revoke_reason) ON memory.approval_authorities TO engramport_admin;
CREATE POLICY approval_authorities_admin_read ON memory.approval_authorities FOR SELECT TO engramport_admin
  USING (true);
CREATE POLICY approval_authorities_admin_grant ON memory.approval_authorities FOR INSERT TO engramport_admin
  WITH CHECK (parent_id IS NULL);
CREATE POLICY approval_authorities_admin_revoke ON memory.approval_authorities FOR UPDATE TO engramport_admin
  USING (parent_id IS NULL AND revoked_at IS NULL) WITH CHECK (parent_id IS NULL AND revoked_at IS NOT NULL);

-- The server reaches authority only through these functions, with a person's
-- fresh sign-in. It never reads or writes the tables directly.
REVOKE ALL ON FUNCTION memory.approval_authorities_shape() FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.approval_record_kept() FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.approval_authority_valid(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.consume_human_sign_in(uuid, uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.delegate_approval_authority(uuid, uuid, uuid, uuid, memory.claim_type[], timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.revoke_delegated_authority(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.approval_authority_valid(uuid) TO engramport_admin;
GRANT EXECUTE ON FUNCTION memory.delegate_approval_authority(uuid, uuid, uuid, uuid, memory.claim_type[], timestamptz)
  TO engramport_app;
GRANT EXECUTE ON FUNCTION memory.revoke_delegated_authority(uuid, uuid, uuid) TO engramport_app;

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
