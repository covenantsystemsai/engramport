-- Trust layer milestone 1: what a memory claims, kept apart from whether
-- anyone approved or verified it.
-- Forward-only; applied by db/migrate.sh in one transaction.
--
-- A memory's kind (fact, decision, note...) says what the text is. These
-- columns say how much it can be trusted, as independent dimensions:
--
--   claim_type          what the writer claims: an observation, an inference,
--                       a hypothesis, a proposal, a decision or a fact.
--                       The writer chooses it; it is a claim, not a check.
--   approval_state      none, pending, approved or rejected.
--   verification_state  unverified, verified or disputed.
--   status (0001)       the lifecycle: active, superseded or retracted.
--
-- A model writing "approved" is not an authorization event. So no write can
-- set approval_state or verification_state: every new memory starts at
-- none / unverified, whoever writes it and whatever its text or metadata says,
-- and neither column, nor claim_type, changes in place. A later migration adds
-- the human-only approval and verification events that are the one way to
-- change them. Until then the guard below refuses every change, for every role.
--
-- Existing memories become observation / none / unverified.

CREATE TYPE memory.claim_type AS ENUM
  ('observation', 'inference', 'hypothesis', 'proposal', 'decision', 'fact');
CREATE TYPE memory.approval_state AS ENUM ('none', 'pending', 'approved', 'rejected');
CREATE TYPE memory.verification_state AS ENUM ('unverified', 'verified', 'disputed');

ALTER TABLE memory.memories
  ADD COLUMN claim_type memory.claim_type NOT NULL DEFAULT 'observation',
  ADD COLUMN approval_state memory.approval_state NOT NULL DEFAULT 'none',
  ADD COLUMN verification_state memory.verification_state NOT NULL DEFAULT 'unverified';

CREATE FUNCTION memory.memories_trust_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.approval_state <> 'none' OR NEW.verification_state <> 'unverified' THEN
      RAISE EXCEPTION 'a write cannot approve or verify a memory'
        USING ERRCODE = '42501',
              HINT = 'approval and verification are recorded as their own events, not set by the writer';
    END IF;
  ELSIF NEW.approval_state IS DISTINCT FROM OLD.approval_state
     OR NEW.verification_state IS DISTINCT FROM OLD.verification_state
     OR NEW.claim_type IS DISTINCT FROM OLD.claim_type THEN
    RAISE EXCEPTION 'claim type, approval and verification do not change in place'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER memories_trust_guard BEFORE INSERT OR UPDATE ON memory.memories
  FOR EACH ROW EXECUTE FUNCTION memory.memories_trust_guard();
REVOKE ALL ON FUNCTION memory.memories_trust_guard() FROM PUBLIC;

-- memory.remember takes the claim type. Same body as 0001 otherwise.
DROP FUNCTION memory.remember(memory.memory_kind, text, text, memory.transport, real, jsonb, text, text,
                              text, text, text, text, text, uuid, jsonb);
CREATE FUNCTION memory.remember(
  p_kind memory.memory_kind,
  p_content text,
  p_tool text,
  p_transport memory.transport,
  p_importance real DEFAULT 0.5,
  p_metadata jsonb DEFAULT '{}',
  p_dedup_key text DEFAULT NULL,
  p_client_name text DEFAULT NULL,
  p_client_version text DEFAULT NULL,
  p_session_id text DEFAULT NULL,
  p_request_id text DEFAULT NULL,
  p_source_kind text DEFAULT NULL,
  p_source_ref text DEFAULT NULL,
  p_log_event_id uuid DEFAULT NULL,
  p_claimed jsonb DEFAULT '{}',
  p_claim_type memory.claim_type DEFAULT 'observation'
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
  INSERT INTO memory.provenance (namespace_id, api_key_id, actor_id, tool, client_name,
      client_version, transport, session_id, request_id, source_kind, source_ref,
      log_event_id, content_sha256, claimed)
  VALUES (k.namespace_id, k.api_key_id, k.actor_id, p_tool, p_client_name,
      p_client_version, p_transport, p_session_id, p_request_id, p_source_kind, p_source_ref,
      p_log_event_id, encode(sha256(convert_to(p_content, 'UTF8')), 'hex'), p_claimed)
  RETURNING id INTO prov_id;
  INSERT INTO memory.memories (namespace_id, kind, content, dedup_key, importance, metadata, provenance_id,
      claim_type)
  VALUES (k.namespace_id, p_kind, p_content, p_dedup_key, p_importance, p_metadata, prov_id,
      coalesce(p_claim_type, 'observation'))
  RETURNING id INTO mem_id;
  RETURN mem_id;
END
$$;
REVOKE ALL ON FUNCTION memory.remember(memory.memory_kind, text, text, memory.transport, real, jsonb, text, text,
                                       text, text, text, text, text, uuid, jsonb, memory.claim_type) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.remember(memory.memory_kind, text, text, memory.transport, real, jsonb, text, text,
                                          text, text, text, text, text, uuid, jsonb, memory.claim_type)
  TO engramport_app;
