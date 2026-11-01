-- 0002_admin_role: a separate role for managing namespaces, actors and keys.
-- Forward-only; applied by db/migrate.sh in one transaction.
--
-- engramport_admin is what `engramport admin` runs as. It can create
-- namespaces and actors, mint keys (it inserts the HMAC, never sees a stored
-- one), revoke keys and shorten or set their expiry. It cannot read or write
-- memories, provenance or embeddings, cannot read key hashes, and cannot
-- delete anything. It gets no login here: an operator's login role is granted
-- SET on it at setup time, and the tool switches to it for every statement.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'engramport_admin') THEN
    CREATE ROLE engramport_admin NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END
$$;

-- A key's identity never changes after it is minted, and a revoked key stays
-- revoked. Applies to every role, the owner included; rotate to change scopes.
CREATE FUNCTION memory.api_keys_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF (NEW.id, NEW.namespace_id, NEW.actor_id, NEW.prefix, NEW.key_hash, NEW.scopes, NEW.created_at)
     IS DISTINCT FROM
     (OLD.id, OLD.namespace_id, OLD.actor_id, OLD.prefix, OLD.key_hash, OLD.scopes, OLD.created_at) THEN
    RAISE EXCEPTION 'a key''s namespace, actor, prefix, hash and scopes cannot change; mint a new key';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'a revoked key cannot be restored or re-dated';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER api_keys_guard BEFORE UPDATE ON memory.api_keys
  FOR EACH ROW EXECUTE FUNCTION memory.api_keys_guard();

GRANT USAGE ON SCHEMA memory TO engramport_admin;
GRANT SELECT, INSERT ON memory.namespaces TO engramport_admin;
GRANT SELECT, INSERT ON memory.actors TO engramport_admin;
GRANT UPDATE (display_name, disabled_at) ON memory.actors TO engramport_admin;
-- Every key column but the hash is readable; the hash goes in, never out.
GRANT SELECT (id, namespace_id, actor_id, prefix, scopes, expires_at, revoked_at, last_used_at, created_at)
  ON memory.api_keys TO engramport_admin;
GRANT INSERT (namespace_id, actor_id, prefix, key_hash, scopes, expires_at)
  ON memory.api_keys TO engramport_admin;
GRANT UPDATE (expires_at, revoked_at) ON memory.api_keys TO engramport_admin;
GRANT EXECUTE ON FUNCTION memory.uuid_v7() TO engramport_admin;

CREATE POLICY namespaces_admin_read ON memory.namespaces FOR SELECT TO engramport_admin USING (true);
CREATE POLICY namespaces_admin_create ON memory.namespaces FOR INSERT TO engramport_admin WITH CHECK (true);
CREATE POLICY actors_admin_read ON memory.actors FOR SELECT TO engramport_admin USING (true);
CREATE POLICY actors_admin_create ON memory.actors FOR INSERT TO engramport_admin WITH CHECK (true);
CREATE POLICY actors_admin_update ON memory.actors FOR UPDATE TO engramport_admin USING (true) WITH CHECK (true);
CREATE POLICY api_keys_admin_read ON memory.api_keys FOR SELECT TO engramport_admin USING (true);
-- A new key starts active; revoked_at is not in the insert grant either.
CREATE POLICY api_keys_admin_create ON memory.api_keys FOR INSERT TO engramport_admin
  WITH CHECK (revoked_at IS NULL AND last_used_at IS NULL);
-- Only active keys can be changed, so revoking is final for this role too.
CREATE POLICY api_keys_admin_update ON memory.api_keys FOR UPDATE TO engramport_admin
  USING (revoked_at IS NULL) WITH CHECK (true);

-- New functions default to EXECUTE for PUBLIC; take it back, as in 0001.
REVOKE ALL ON FUNCTION memory.api_keys_guard() FROM PUBLIC;

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
