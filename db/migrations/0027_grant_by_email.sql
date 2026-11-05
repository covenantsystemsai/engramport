-- D-02 Grant Recipient Selection (founder decision, Nov 5): an owner gives an
-- erase or export grant by typing the recipient's email. Forward-only; applied
-- by db/migrate.sh in one transaction.
--
-- The decision, in its own words: "The owner enters the intended recipient's
-- email. The server accepts the request only if the recipient is already an
-- active member of the authorized cell. Do not expose a cell-member directory
-- or disclose membership through lookup errors. Grant authority remains
-- inactive until the intended recipient independently signs in and accepts
-- the precise terms."
--
-- So memory.offer_data_grant returns nothing and raises nothing about the
-- recipient: whether or not the address belongs to another enabled person who
-- is an active member of the namespace, the caller sees the same outcome, and
-- a grant is written only when it does. Every refusal it can raise is about
-- the caller or the request itself (the power, the end date, the address's
-- shape, the caller's own sign-in and authority), checked before the address
-- is looked up. The grant it writes is the same row memory.grant_data_power
-- writes, undecided, and counts only once the recipient accepts its exact
-- terms with their own sign-in (memory.decide_data_grant).

CREATE FUNCTION memory.offer_data_grant(p_user_id uuid, p_session_id uuid, p_namespace_id uuid,
                                        p_email text, p_power memory.data_power, p_expires_at timestamptz)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid;
  v_parent uuid;
  v_email text := lower(btrim(coalesce(p_email, '')));
  v_to uuid[];
BEGIN
  IF p_power IS NULL THEN
    RAISE EXCEPTION 'say which power: erase or export' USING ERRCODE = '22023';
  END IF;
  IF p_expires_at IS NULL OR p_expires_at <= now() OR p_expires_at > now() + interval '90 days' THEN
    RAISE EXCEPTION 'a grant ends within 90 days; give a date' USING ERRCODE = '22023';
  END IF;
  IF length(v_email) > 254 OR v_email !~ '^[^@[:space:]]+@[^@[:space:]]+$' THEN
    RAISE EXCEPTION 'enter the email address of the person the grant is for' USING ERRCODE = '22023';
  END IF;
  v_actor := memory.consume_human_sign_in(p_user_id, p_session_id, 'grant');
  v_parent := memory.delegable_owner_authority(v_actor, p_namespace_id);
  IF v_parent IS NULL THEN
    RAISE EXCEPTION 'you hold no owner''s authority over this namespace that you may delegate' USING ERRCODE = '42501';
  END IF;
  -- From here on nothing is said about the address. One enabled person, other
  -- than the caller, with an active membership of this namespace under it.
  SELECT array_agg(DISTINCT a.id) INTO v_to
  FROM memory.oauth_members m
  JOIN memory.actors a ON a.id = m.actor_id
  WHERE m.namespace_id = p_namespace_id AND m.email = v_email AND m.revoked_at IS NULL
    AND a.kind = 'human' AND a.disabled_at IS NULL;
  IF cardinality(v_to) = 1 AND v_to[1] <> v_actor THEN
    INSERT INTO memory.data_grants (namespace_id, power, actor_id, granted_by_actor_id, parent_authority_id, expires_at)
    VALUES (p_namespace_id, p_power, v_to[1], v_actor, v_parent, p_expires_at);
  END IF;
END
$$;
REVOKE ALL ON FUNCTION memory.offer_data_grant(uuid, uuid, uuid, text, memory.data_power, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.offer_data_grant(uuid, uuid, uuid, text, memory.data_power, timestamptz) TO engramport_app;

-- What the owner's grant page shows before they type anything: the namespace,
-- and whether they may give grants over it. Nothing about its members.
CREATE FUNCTION memory.data_grant_giver_view(p_user_id uuid, p_session_id uuid, p_namespace_id uuid)
RETURNS TABLE (namespace_path text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_actor uuid := memory.unspent_human_sign_in(p_user_id, p_session_id);
BEGIN
  IF memory.delegable_owner_authority(v_actor, p_namespace_id) IS NULL THEN
    RAISE EXCEPTION 'you hold no owner''s authority over this namespace that you may delegate' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY SELECT n.path FROM memory.namespaces n WHERE n.id = p_namespace_id;
END
$$;
REVOKE ALL ON FUNCTION memory.data_grant_giver_view(uuid, uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.data_grant_giver_view(uuid, uuid, uuid) TO engramport_app;
