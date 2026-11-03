-- 0009_oauth: the database half of OAuth 2.1 sign-in for claude.ai and other
-- MCP clients. Forward-only; applied by db/migrate.sh in one transaction.
--
-- How a connection is made:
--   * The admin role adds a member: a verified Google email that may connect
--     to one namespace, as one actor, with read or read+write scopes.
--   * A client (claude.ai) registers itself and sends the person to the
--     server's authorize page. They sign in with Google through Supabase Auth
--     and pick one of their memberships. oauth_issue_code checks the fresh
--     Supabase session and its Google identity in the database itself, so the
--     server's own credentials are not enough to issue a code for anyone.
--   * The client redeems the code with its PKCE verifier, checked here too,
--     and gets an access token and a refresh token.
--
-- The access token is an ordinary namespace-bound API key that expires in an
-- hour, tagged with its grant. So row security, provenance and the audit trail
-- work exactly as for any key, and nothing else in the schema changes. Codes
-- and refresh tokens are stored only as the HMAC the server computes with its
-- pepper. A code works once; using it again revokes what it was traded for.
-- A refresh token works once too and is replaced each time; using an old one
-- revokes the whole grant, since only a stolen copy would be reused.
--
-- engramport_app reaches these tables only through the functions below, and
-- the admin role manages members and can revoke grants but never sees a code,
-- a token hash or memory content.

-- ── Members: who may connect to which namespace ──────────────────────────────

CREATE TABLE memory.oauth_members (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  email text NOT NULL CHECK (email = lower(email) AND length(email) <= 254
    AND email ~ '^[^@[:space:][:cntrl:]]+@[^@[:space:][:cntrl:]]+\.[^@[:space:][:cntrl:]]+$'),
  namespace_id uuid NOT NULL REFERENCES memory.namespaces(id),
  actor_id uuid NOT NULL REFERENCES memory.actors(id),
  scopes text[] NOT NULL DEFAULT '{read,write}'
    CHECK (scopes <@ ARRAY['read', 'write']::text[] AND 'read' = ANY (scopes)),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE UNIQUE INDEX oauth_members_active ON memory.oauth_members (email, namespace_id, actor_id)
  WHERE revoked_at IS NULL;
CREATE INDEX oauth_members_namespace ON memory.oauth_members (namespace_id);
CREATE INDEX oauth_members_actor ON memory.oauth_members (actor_id);

-- ── Clients, registered dynamically (RFC 7591) ───────────────────────────────

-- A redirect is https, or http only to this machine (desktop clients).
CREATE FUNCTION memory.oauth_redirect_uris_ok(p_uris text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
  SELECT cardinality(p_uris) BETWEEN 1 AND 5
     AND NOT EXISTS (
       SELECT 1 FROM unnest(p_uris) u
       WHERE u IS NULL OR length(u) > 2000 OR u ~ '[[:space:][:cntrl:]#]'
          OR NOT (u ~ '^https://[^/?@]+(/|$)'
                  OR u ~ '^http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?(/|$)'))
$$;

CREATE TABLE memory.oauth_clients (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  client_id text NOT NULL UNIQUE CHECK (client_id ~ '^epc_[A-Za-z0-9]{24}$'),
  client_name text NOT NULL CHECK (length(client_name) BETWEEN 1 AND 100 AND client_name !~ '[[:cntrl:]]'),
  redirect_uris text[] NOT NULL CHECK (memory.oauth_redirect_uris_ok(redirect_uris)),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ── Grants, codes and refresh tokens ─────────────────────────────────────────

CREATE TABLE memory.oauth_grants (
  id uuid PRIMARY KEY DEFAULT memory.uuid_v7(),
  client_id uuid NOT NULL REFERENCES memory.oauth_clients(id),
  member_id uuid NOT NULL REFERENCES memory.oauth_members(id),
  scopes text[] NOT NULL CHECK (scopes <@ ARRAY['read', 'write']::text[] AND 'read' = ANY (scopes)),
  resource text NOT NULL CHECK (length(resource) BETWEEN 1 AND 2000),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  revoke_reason text CHECK (revoke_reason ~ '^[a-z_]{1,32}$'),
  CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE INDEX oauth_grants_client ON memory.oauth_grants (client_id);
CREATE INDEX oauth_grants_member ON memory.oauth_grants (member_id);

CREATE TABLE memory.oauth_codes (
  code_hash bytea PRIMARY KEY CHECK (octet_length(code_hash) = 32),
  client_id uuid NOT NULL REFERENCES memory.oauth_clients(id),
  member_id uuid NOT NULL REFERENCES memory.oauth_members(id),
  redirect_uri text NOT NULL,
  code_challenge text NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
  resource text NOT NULL CHECK (length(resource) BETWEEN 1 AND 2000),
  scopes text[] NOT NULL CHECK (scopes <@ ARRAY['read', 'write']::text[] AND 'read' = ANY (scopes)),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  grant_id uuid REFERENCES memory.oauth_grants(id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX oauth_codes_client ON memory.oauth_codes (client_id);
CREATE INDEX oauth_codes_member ON memory.oauth_codes (member_id);
CREATE INDEX oauth_codes_grant ON memory.oauth_codes (grant_id) WHERE grant_id IS NOT NULL;

CREATE TABLE memory.oauth_refresh_tokens (
  token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  grant_id uuid NOT NULL REFERENCES memory.oauth_grants(id),
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX oauth_refresh_tokens_grant ON memory.oauth_refresh_tokens (grant_id);

-- An access token is a key minted for a grant.
ALTER TABLE memory.api_keys ADD COLUMN oauth_grant_id uuid REFERENCES memory.oauth_grants(id);
CREATE INDEX api_keys_oauth_grant ON memory.api_keys (oauth_grant_id) WHERE oauth_grant_id IS NOT NULL;

-- The key guard from 0002, now also keeping a key's grant fixed.
CREATE OR REPLACE FUNCTION memory.api_keys_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF (NEW.id, NEW.namespace_id, NEW.actor_id, NEW.prefix, NEW.key_hash, NEW.scopes, NEW.created_at, NEW.oauth_grant_id)
     IS DISTINCT FROM
     (OLD.id, OLD.namespace_id, OLD.actor_id, OLD.prefix, OLD.key_hash, OLD.scopes, OLD.created_at, OLD.oauth_grant_id) THEN
    RAISE EXCEPTION 'a key''s namespace, actor, prefix, hash, scopes and grant cannot change; mint a new key';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'a revoked key cannot be restored or re-dated';
  END IF;
  RETURN NEW;
END
$$;

-- A member, grant or client never changes what it is; revoking is final.
CREATE FUNCTION memory.oauth_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  o jsonb := to_jsonb(OLD) - 'revoked_at' - 'revoke_reason';
  n jsonb := to_jsonb(NEW) - 'revoked_at' - 'revoke_reason';
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION '% rows are never deleted', TG_TABLE_NAME;
  END IF;
  IF o IS DISTINCT FROM n THEN
    RAISE EXCEPTION 'only revoked_at can change on %', TG_TABLE_NAME;
  END IF;
  IF (to_jsonb(OLD) ? 'revoked_at') AND OLD IS DISTINCT FROM NEW
     AND (to_jsonb(OLD) ->> 'revoked_at') IS NOT NULL THEN
    RAISE EXCEPTION 'a revoked % row cannot be restored or re-dated', TG_TABLE_NAME;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER oauth_members_guard BEFORE UPDATE OR DELETE ON memory.oauth_members
  FOR EACH ROW EXECUTE FUNCTION memory.oauth_guard();
CREATE TRIGGER oauth_grants_guard BEFORE UPDATE OR DELETE ON memory.oauth_grants
  FOR EACH ROW EXECUTE FUNCTION memory.oauth_guard();
CREATE TRIGGER oauth_clients_guard BEFORE UPDATE OR DELETE ON memory.oauth_clients
  FOR EACH ROW EXECUTE FUNCTION memory.oauth_guard();

-- Revoking a grant revokes every access token minted for it. Revoking a member
-- revokes every grant made through it. Definer, so it works whoever revokes.
CREATE FUNCTION memory.oauth_grant_revoked() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  UPDATE memory.api_keys SET revoked_at = now()
  WHERE oauth_grant_id = NEW.id AND revoked_at IS NULL;
  RETURN NULL;
END
$$;
CREATE TRIGGER oauth_grants_revoked AFTER UPDATE OF revoked_at ON memory.oauth_grants
  FOR EACH ROW WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
  EXECUTE FUNCTION memory.oauth_grant_revoked();

CREATE FUNCTION memory.oauth_member_revoked() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
  UPDATE memory.oauth_grants SET revoked_at = now(), revoke_reason = 'member_revoked'
  WHERE member_id = NEW.id AND revoked_at IS NULL;
  RETURN NULL;
END
$$;
CREATE TRIGGER oauth_members_revoked AFTER UPDATE OF revoked_at ON memory.oauth_members
  FOR EACH ROW WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
  EXECUTE FUNCTION memory.oauth_member_revoked();

-- ── Row security ─────────────────────────────────────────────────────────────

ALTER TABLE memory.oauth_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.oauth_members FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.oauth_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.oauth_clients FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.oauth_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.oauth_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.oauth_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.oauth_codes FORCE ROW LEVEL SECURITY;
ALTER TABLE memory.oauth_refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.oauth_refresh_tokens FORCE ROW LEVEL SECURITY;

-- The admin role manages members, sees clients and grants, and can revoke a
-- grant. It never sees codes or refresh tokens. engramport_app gets no table
-- grants at all here.
GRANT SELECT ON memory.oauth_members TO engramport_admin;
GRANT INSERT (email, namespace_id, actor_id, scopes) ON memory.oauth_members TO engramport_admin;
GRANT UPDATE (revoked_at) ON memory.oauth_members TO engramport_admin;
GRANT SELECT ON memory.oauth_clients TO engramport_admin;
GRANT SELECT ON memory.oauth_grants TO engramport_admin;
GRANT UPDATE (revoked_at, revoke_reason) ON memory.oauth_grants TO engramport_admin;
GRANT SELECT (oauth_grant_id) ON memory.api_keys TO engramport_admin;

CREATE POLICY oauth_members_admin_read ON memory.oauth_members FOR SELECT TO engramport_admin USING (true);
CREATE POLICY oauth_members_admin_create ON memory.oauth_members FOR INSERT TO engramport_admin
  WITH CHECK (revoked_at IS NULL);
CREATE POLICY oauth_members_admin_revoke ON memory.oauth_members FOR UPDATE TO engramport_admin
  USING (revoked_at IS NULL) WITH CHECK (true);
CREATE POLICY oauth_clients_admin_read ON memory.oauth_clients FOR SELECT TO engramport_admin USING (true);
CREATE POLICY oauth_grants_admin_read ON memory.oauth_grants FOR SELECT TO engramport_admin USING (true);
CREATE POLICY oauth_grants_admin_revoke ON memory.oauth_grants FOR UPDATE TO engramport_admin
  USING (revoked_at IS NULL) WITH CHECK (revoked_at IS NOT NULL);

-- ── What the server calls ────────────────────────────────────────────────────

-- The verified Google email behind a Supabase Auth session that started in the
-- last 15 minutes and has not ended, or NULL. The session itself must come
-- from a Google sign-in: Supabase records it as an OAuth sign-in, and the
-- account's Google identity signed in within a minute of the session starting.
-- Having a Google identity is not enough, since a password or magic-link
-- session on the same account would pass that. The session id comes from the
-- signed-in person's token; it is never shown to them or anyone else.
-- Internal: only the functions below call it.
CREATE FUNCTION memory.oauth_signed_in_email(p_user_id uuid, p_session_id uuid) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_email text;
BEGIN
  IF p_user_id IS NULL OR p_session_id IS NULL THEN
    RETURN NULL;
  END IF;
  SELECT lower(i.identity_data ->> 'email') INTO v_email
  FROM auth.sessions s
  JOIN auth.users u ON u.id = s.user_id
  JOIN auth.identities i ON i.user_id = u.id AND i.provider = 'google'
  WHERE s.id = p_session_id
    AND s.user_id = p_user_id
    AND s.created_at > now() - interval '15 minutes'
    AND (s.not_after IS NULL OR s.not_after > now())
    AND u.deleted_at IS NULL
    AND (u.banned_until IS NULL OR u.banned_until <= now())
    AND NOT coalesce(u.is_anonymous, false)
    AND i.identity_data ->> 'email_verified' = 'true'
    AND coalesce(i.identity_data ->> 'email', '') <> ''
    AND i.last_sign_in_at BETWEEN s.created_at - interval '1 minute' AND s.created_at + interval '1 minute'
    AND EXISTS (SELECT 1 FROM auth.mfa_amr_claims c
                WHERE c.session_id = s.id AND c.authentication_method = 'oauth')
  ORDER BY i.id
  LIMIT 1;
  RETURN v_email;
END
$$;

-- Register a client. Its id is generated by the server; bad input is refused
-- by the table's checks.
CREATE FUNCTION memory.oauth_register_client(p_client_id text, p_client_name text, p_redirect_uris text[])
RETURNS timestamptz
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
  INSERT INTO memory.oauth_clients (client_id, client_name, redirect_uris)
  VALUES (p_client_id, p_client_name, p_redirect_uris)
  RETURNING created_at
$$;

-- What the authorize page shows about a client.
CREATE FUNCTION memory.oauth_client(p_client_id text)
RETURNS TABLE (client_name text, redirect_uris text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT c.client_name, c.redirect_uris FROM memory.oauth_clients c WHERE c.client_id = p_client_id
$$;

-- The memberships a freshly signed-in person may connect with. Empty for an
-- unknown, stale or ended session.
CREATE FUNCTION memory.oauth_member_choices(p_user_id uuid, p_session_id uuid)
RETURNS TABLE (member_id uuid, namespace_path text, actor_slug text, scopes text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT m.id, n.path, a.slug, m.scopes
  FROM memory.oauth_members m
  JOIN memory.namespaces n ON n.id = m.namespace_id
  JOIN memory.actors a ON a.id = m.actor_id
  WHERE m.revoked_at IS NULL AND a.disabled_at IS NULL
    AND m.email = memory.oauth_signed_in_email(p_user_id, p_session_id)
  ORDER BY n.path, a.slug
$$;

-- Issue a code for the membership the person picked. True if issued. The
-- session must be fresh and its Google email must be the member's, the
-- redirect must be one the client registered, and the scopes no more than the
-- member's.
CREATE FUNCTION memory.oauth_issue_code(
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
  INSERT INTO memory.oauth_codes (code_hash, client_id, member_id, redirect_uri, code_challenge, resource, scopes, expires_at)
  VALUES (p_code_hash, v_client, v_member.id, p_redirect_uri, p_code_challenge, p_resource, p_scopes,
          now() + interval '5 minutes');
  RETURN true;
END
$$;

-- PKCE S256: base64url(sha256(verifier)) with no padding (RFC 7636).
CREATE FUNCTION memory.oauth_pkce_s256(p_verifier text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $$
  SELECT translate(rtrim(encode(sha256(convert_to(p_verifier, 'UTF8')), 'base64'), '='), '+/', '-_')
$$;

-- Mint the access token's key row for a grant. Internal.
CREATE FUNCTION memory.oauth_mint_access(p_grant memory.oauth_grants, p_prefix text, p_key_hash bytea)
RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_member memory.oauth_members;
  v_expires timestamptz := now() + interval '1 hour';
BEGIN
  SELECT * INTO v_member FROM memory.oauth_members WHERE id = p_grant.member_id;
  INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes, expires_at, oauth_grant_id)
  VALUES (v_member.namespace_id, v_member.actor_id, p_prefix, p_key_hash, p_grant.scopes, v_expires, p_grant.id);
  RETURN v_expires;
END
$$;

-- True if the grant's member and actor are still active. Internal.
CREATE FUNCTION memory.oauth_grant_usable(p_grant memory.oauth_grants) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
  SELECT p_grant.revoked_at IS NULL AND EXISTS (
    SELECT 1 FROM memory.oauth_members m JOIN memory.actors a ON a.id = m.actor_id
    WHERE m.id = p_grant.member_id AND m.revoked_at IS NULL AND a.disabled_at IS NULL)
$$;

-- Trade a code for tokens. status is 'ok' or an OAuth error code; on 'ok' the
-- server hands the client the access key and refresh token whose hashes it
-- passed in. Errors are returned, not raised, so a revocation for a reused
-- code is kept.
CREATE FUNCTION memory.oauth_exchange_code(
  p_client_id text, p_code_hash bytea, p_code_verifier text, p_redirect_uri text, p_resource text,
  p_access_prefix text, p_access_hash bytea, p_refresh_hash bytea
) RETURNS TABLE (status text, scopes text[], namespace_path text, access_expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_code memory.oauth_codes;
  v_grant memory.oauth_grants;
  v_expires timestamptz;
BEGIN
  SELECT k.* INTO v_code FROM memory.oauth_codes k
  JOIN memory.oauth_clients c ON c.id = k.client_id
  WHERE k.code_hash = p_code_hash AND c.client_id = p_client_id
  FOR UPDATE OF k;
  IF v_code.code_hash IS NULL THEN
    RETURN QUERY SELECT 'invalid_grant'::text, NULL::text[], NULL::text, NULL::timestamptz;
    RETURN;
  END IF;
  IF v_code.used_at IS NOT NULL THEN
    -- A second use means the code leaked: take back what the first use got.
    IF v_code.grant_id IS NOT NULL THEN
      UPDATE memory.oauth_grants SET revoked_at = now(), revoke_reason = 'code_reuse'
      WHERE id = v_code.grant_id AND revoked_at IS NULL;
    END IF;
    RETURN QUERY SELECT 'invalid_grant'::text, NULL::text[], NULL::text, NULL::timestamptz;
    RETURN;
  END IF;
  -- Any failure from here on spends the code, so it cannot be guessed at.
  UPDATE memory.oauth_codes SET used_at = now() WHERE code_hash = v_code.code_hash;
  IF v_code.expires_at <= now()
     OR v_code.redirect_uri IS DISTINCT FROM p_redirect_uri
     OR v_code.resource IS DISTINCT FROM p_resource
     OR p_code_verifier IS NULL OR p_code_verifier !~ '^[A-Za-z0-9._~-]{43,128}$'
     OR memory.oauth_pkce_s256(p_code_verifier) <> v_code.code_challenge THEN
    RETURN QUERY SELECT 'invalid_grant'::text, NULL::text[], NULL::text, NULL::timestamptz;
    RETURN;
  END IF;
  -- Hold the member against a revocation running at the same time: either the
  -- revocation commits first and this sees it, or it waits and then revokes
  -- the grant made here.
  PERFORM 1 FROM memory.oauth_members WHERE id = v_code.member_id FOR SHARE;
  INSERT INTO memory.oauth_grants (client_id, member_id, scopes, resource)
  VALUES (v_code.client_id, v_code.member_id, v_code.scopes, v_code.resource)
  RETURNING * INTO v_grant;
  IF NOT memory.oauth_grant_usable(v_grant) THEN
    UPDATE memory.oauth_grants SET revoked_at = now(), revoke_reason = 'member_inactive' WHERE id = v_grant.id;
    RETURN QUERY SELECT 'invalid_grant'::text, NULL::text[], NULL::text, NULL::timestamptz;
    RETURN;
  END IF;
  UPDATE memory.oauth_codes SET grant_id = v_grant.id WHERE code_hash = v_code.code_hash;
  INSERT INTO memory.oauth_refresh_tokens (token_hash, grant_id, expires_at)
  VALUES (p_refresh_hash, v_grant.id, now() + interval '30 days');
  v_expires := memory.oauth_mint_access(v_grant, p_access_prefix, p_access_hash);
  RETURN QUERY
    SELECT 'ok'::text, v_grant.scopes, n.path, v_expires
    FROM memory.oauth_members m JOIN memory.namespaces n ON n.id = m.namespace_id
    WHERE m.id = v_grant.member_id;
END
$$;

-- Trade a refresh token for a new access token and a new refresh token. The
-- old refresh token is spent; presenting it again revokes the grant.
CREATE FUNCTION memory.oauth_refresh(
  p_client_id text, p_refresh_hash bytea, p_resource text,
  p_access_prefix text, p_access_hash bytea, p_new_refresh_hash bytea
) RETURNS TABLE (status text, scopes text[], namespace_path text, access_expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_token memory.oauth_refresh_tokens;
  v_grant memory.oauth_grants;
  v_expires timestamptz;
BEGIN
  SELECT r.* INTO v_token FROM memory.oauth_refresh_tokens r
  JOIN memory.oauth_grants g ON g.id = r.grant_id
  JOIN memory.oauth_clients c ON c.id = g.client_id
  WHERE r.token_hash = p_refresh_hash AND c.client_id = p_client_id
  FOR UPDATE OF r, g;
  IF v_token.token_hash IS NULL THEN
    RETURN QUERY SELECT 'invalid_grant'::text, NULL::text[], NULL::text, NULL::timestamptz;
    RETURN;
  END IF;
  SELECT * INTO v_grant FROM memory.oauth_grants WHERE id = v_token.grant_id;
  PERFORM 1 FROM memory.oauth_members WHERE id = v_grant.member_id FOR SHARE;
  IF v_token.used_at IS NOT NULL THEN
    UPDATE memory.oauth_grants SET revoked_at = now(), revoke_reason = 'refresh_reuse'
    WHERE id = v_grant.id AND revoked_at IS NULL;
    RETURN QUERY SELECT 'invalid_grant'::text, NULL::text[], NULL::text, NULL::timestamptz;
    RETURN;
  END IF;
  IF v_token.expires_at <= now() OR NOT memory.oauth_grant_usable(v_grant)
     OR (p_resource IS NOT NULL AND p_resource IS DISTINCT FROM v_grant.resource) THEN
    RETURN QUERY SELECT 'invalid_grant'::text, NULL::text[], NULL::text, NULL::timestamptz;
    RETURN;
  END IF;
  UPDATE memory.oauth_refresh_tokens SET used_at = now() WHERE token_hash = v_token.token_hash;
  INSERT INTO memory.oauth_refresh_tokens (token_hash, grant_id, expires_at)
  VALUES (p_new_refresh_hash, v_grant.id, now() + interval '30 days');
  v_expires := memory.oauth_mint_access(v_grant, p_access_prefix, p_access_hash);
  RETURN QUERY
    SELECT 'ok'::text, v_grant.scopes, n.path, v_expires
    FROM memory.oauth_members m JOIN memory.namespaces n ON n.id = m.namespace_id
    WHERE m.id = v_grant.member_id;
END
$$;

-- RFC 7009 revocation: a refresh token (prefix NULL) or an access token
-- (its key prefix and hash) of this client revokes its whole grant. Says
-- nothing about whether it found one.
CREATE FUNCTION memory.oauth_revoke(p_client_id text, p_token_hash bytea, p_access_prefix text DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_grant uuid;
BEGIN
  IF p_access_prefix IS NULL THEN
    SELECT r.grant_id INTO v_grant FROM memory.oauth_refresh_tokens r WHERE r.token_hash = p_token_hash;
  ELSE
    SELECT k.oauth_grant_id INTO v_grant FROM memory.api_keys k
    WHERE k.prefix = p_access_prefix AND k.key_hash = p_token_hash;
  END IF;
  UPDATE memory.oauth_grants g SET revoked_at = now(), revoke_reason = 'client_revoked'
  FROM memory.oauth_clients c
  WHERE g.id = v_grant AND c.id = g.client_id AND c.client_id = p_client_id AND g.revoked_at IS NULL;
END
$$;

-- ── Execute rights ───────────────────────────────────────────────────────────

REVOKE ALL ON FUNCTION memory.oauth_redirect_uris_ok(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_grant_revoked() FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_member_revoked() FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_signed_in_email(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_register_client(text, text, text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_client(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_member_choices(uuid, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_issue_code(uuid, uuid, text, uuid, text, text, text, text[], bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_pkce_s256(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_mint_access(memory.oauth_grants, text, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_grant_usable(memory.oauth_grants) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_exchange_code(text, bytea, text, text, text, text, bytea, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_refresh(text, bytea, text, text, bytea, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION memory.oauth_revoke(text, bytea, text) FROM PUBLIC;

-- The server's role runs these seven entry points and nothing else here. The
-- table checks call oauth_redirect_uris_ok as the owner, so it needs no grant.
GRANT EXECUTE ON FUNCTION memory.oauth_register_client(text, text, text[]) TO engramport_app;
GRANT EXECUTE ON FUNCTION memory.oauth_client(text) TO engramport_app;
GRANT EXECUTE ON FUNCTION memory.oauth_member_choices(uuid, uuid) TO engramport_app;
GRANT EXECUTE ON FUNCTION memory.oauth_issue_code(uuid, uuid, text, uuid, text, text, text, text[], bytea) TO engramport_app;
GRANT EXECUTE ON FUNCTION memory.oauth_exchange_code(text, bytea, text, text, text, text, bytea, bytea) TO engramport_app;
GRANT EXECUTE ON FUNCTION memory.oauth_refresh(text, bytea, text, text, bytea, bytea) TO engramport_app;
GRANT EXECUTE ON FUNCTION memory.oauth_revoke(text, bytea, text) TO engramport_app;

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
