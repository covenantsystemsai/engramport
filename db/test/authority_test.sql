-- Tests for 0015_approval_authority. Run by db/test/run.sh after trust_test.sql,
-- on the rls_test namespaces, the company city from company_test and the
-- stand-in Supabase Auth tables from oauth_test.
\set ON_ERROR_STOP on
\set QUIET on
\set ta   '00000000-0000-7000-8000-000000000011'
\set c1   '00000000-0000-7000-8000-000000000111'
\set c2   '00000000-0000-7000-8000-000000000112'
\set agent '00000000-0000-7000-8000-00000000a001'

-- A fresh Google sign-in for an email, as Supabase Auth would record it.
CREATE FUNCTION t.sign_in(p_email text, OUT user_id uuid, OUT session_id uuid) LANGUAGE plpgsql AS $$
#variable_conflict use_variable
BEGIN
  SELECT u.id INTO user_id FROM auth.users u WHERE u.email = p_email;
  IF NOT FOUND THEN
    user_id := gen_random_uuid();
    INSERT INTO auth.users (id, email) VALUES (user_id, p_email);
    INSERT INTO auth.identities (user_id, provider, identity_data, last_sign_in_at)
    VALUES (user_id, 'google', jsonb_build_object('email', p_email, 'email_verified', true), now());
  END IF;
  UPDATE auth.identities SET last_sign_in_at = now() WHERE identities.user_id = user_id AND provider = 'google';
  session_id := gen_random_uuid();
  INSERT INTO auth.sessions (id, user_id, created_at) VALUES (session_id, user_id, now());
  INSERT INTO auth.mfa_amr_claims (session_id, authentication_method) VALUES (session_id, 'oauth');
END
$$;

SELECT id AS co_city FROM memory.namespaces WHERE purpose = 'company' AND parent_id IS NULL \gset
SELECT id AS co_hq FROM memory.namespaces WHERE purpose = 'company' AND level = 'cell' AND slug = 'hq' \gset

INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'auth-founder', 'Founder') RETURNING id AS founder \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'auth-owner', 'Cell owner') RETURNING id AS owner \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'auth-helper', 'Helper') RETURNING id AS helper \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'auth-other', 'Other owner') RETURNING id AS other \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES
  ('founder@an2b.test', :'co_hq', :'founder'),
  ('owner@client.test', :'c1', :'owner'),
  ('helper@client.test', :'c1', :'helper'),
  ('other@client.test', :'c2', :'other'),
  ('agent@client.test', :'c1', :'agent');

\echo '-- the admin role grants top-level authority where each scope belongs'
SET ROLE engramport_admin;
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
  VALUES (:'founder', :'co_city', 'company_governance') RETURNING id AS a_founder \gset
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, can_delegate)
  VALUES (:'owner', :'c1', 'cell_knowledge', true) RETURNING id AS a_owner \gset
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, claim_types)
  VALUES (:'other', :'c2', 'cell_knowledge', '{decision,fact}') RETURNING id AS a_other \gset
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope)
  VALUES (:'founder', :'ta', 'promotion') RETURNING id AS a_promo \gset
SELECT t.expect_count('four authorities granted', 'SELECT 1 FROM memory.approval_authorities', 4);
SELECT t.expect_denied('an agent cannot hold authority',
  format($$INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope) VALUES (%L, %L, 'cell_knowledge')$$, :'agent', :'c1'));
SELECT t.expect_denied('cell_knowledge is not granted on a tower',
  format($$INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope) VALUES (%L, %L, 'cell_knowledge')$$, :'owner', :'ta'));
SELECT t.expect_denied('cell_knowledge is not granted on a company cell',
  format($$INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope) VALUES (%L, %L, 'cell_knowledge')$$, :'owner', :'co_hq'));
SELECT t.expect_denied('company_governance is not granted on a client namespace',
  format($$INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope) VALUES (%L, %L, 'company_governance')$$, :'founder', :'c1'));
SELECT t.expect_denied('promotion is not granted on a cell',
  format($$INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope) VALUES (%L, %L, 'promotion')$$, :'founder', :'c1'));
SELECT t.expect_denied('the admin role cannot write a delegation',
  format($$INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, parent_id, granted_by_actor_id)
           VALUES (%L, %L, 'cell_knowledge', %L, %L)$$, :'helper', :'c1', :'a_owner', :'owner'));
SELECT t.expect_denied('an authority cannot be widened in place',
  format($$UPDATE memory.approval_authorities SET claim_types = NULL WHERE id = %L$$, :'a_other'));
SELECT t.expect_denied('or moved to another namespace',
  format($$UPDATE memory.approval_authorities SET namespace_id = %L WHERE id = %L$$, :'c1', :'a_other'));
SELECT t.expect_denied('a claim type list cannot hold a blank',
  format($$INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, claim_types)
           VALUES (%L, %L, 'cell_knowledge', ARRAY['decision', NULL]::memory.claim_type[])$$, :'owner', :'c1'));
SELECT t.expect_denied('or be empty',
  format($$INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, claim_types)
           VALUES (%L, %L, 'cell_knowledge', '{}')$$, :'owner', :'c1'));
SELECT t.expect_denied('the admin role cannot delete an authority',
  format($$DELETE FROM memory.approval_authorities WHERE id = %L$$, :'a_other'));
RESET ROLE;
SELECT t.expect_denied('not even by the table owner',
  format($$UPDATE memory.approval_authorities SET claim_types = NULL WHERE id = %L$$, :'a_other'));
SELECT t.expect_denied('the table owner cannot delete an authority either',
  format($$DELETE FROM memory.approval_authorities WHERE id = %L$$, :'a_other'));
SELECT t.expect_denied('or empty the table', 'TRUNCATE memory.approval_authorities CASCADE');
SET ROLE engramport_admin;
SELECT t.expect_count('the admin role can check an authority',
  format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'a_owner'), 1);
RESET ROLE;

\echo '-- the server never touches authority directly'
SET ROLE engramport_app;
SELECT t.expect_denied('the app cannot read authorities', 'SELECT 1 FROM memory.approval_authorities');
SELECT t.expect_denied('the app cannot grant authority',
  format($$INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope) VALUES (%L, %L, 'cell_knowledge')$$, :'owner', :'c1'));
SELECT t.expect_denied('the app cannot read used sign-ins', 'SELECT 1 FROM memory.human_sign_ins_used');
SELECT t.expect_denied('the app cannot use a sign-in directly',
  $$SELECT memory.consume_human_sign_in(gen_random_uuid(), gen_random_uuid(), 'approve')$$);
RESET ROLE;

\echo '-- delegation needs the holder''s own fresh sign-in, once'
SELECT * FROM t.sign_in('owner@client.test') \gset own1_
SELECT * FROM t.sign_in('owner@client.test') \gset own2_
SELECT * FROM t.sign_in('owner@client.test') \gset own3_
SELECT * FROM t.sign_in('owner@client.test') \gset own4_
SELECT * FROM t.sign_in('helper@client.test') \gset help_
SELECT * FROM t.sign_in('agent@client.test') \gset bot_
SELECT * FROM t.sign_in('other@client.test') \gset oth0_
SET ROLE engramport_app;
SELECT memory.delegate_approval_authority(:'own1_user_id', :'own1_session_id', :'a_owner', :'helper',
  '{observation,fact}', now() + interval '30 days') AS a_helper \gset
SELECT t.expect_denied('the same sign-in cannot be used twice',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'own1_user_id', :'own1_session_id', :'a_owner', :'helper'));
SELECT t.expect_denied('someone else''s sign-in cannot delegate it',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'help_user_id', :'help_session_id', :'a_owner', :'helper'));
SELECT t.expect_denied('no sign-in at all',
  format($$SELECT memory.delegate_approval_authority(gen_random_uuid(), gen_random_uuid(), %L, %L)$$, :'a_owner', :'helper'));
SELECT t.expect_denied('a delegation cannot go to an agent',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'own2_user_id', :'own2_session_id', :'a_owner', :'agent'));
SELECT t.expect_denied('a sign-in that maps to an agent is no person',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'bot_user_id', :'bot_session_id', :'a_owner', :'helper'));
SELECT t.expect_denied('a delegation cannot be delegated again',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'help_user_id', :'help_session_id', :'a_helper', :'other'));
SELECT t.expect_denied('an authority marked not delegable cannot be delegated, even by its holder',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'oth0_user_id', :'oth0_session_id', :'a_other', :'helper'));
SELECT t.expect_denied('a user id with someone else''s session is no sign-in',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'own3_user_id', :'help_session_id', :'a_owner', :'helper'));
RESET ROLE;
SELECT t.expect_count('the delegation keeps namespace and scope, narrows claim types, cannot delegate',
  format($$SELECT 1 FROM memory.approval_authorities WHERE id = %L AND parent_id = %L AND granted_by_actor_id = %L
           AND namespace_id = %L AND scope = 'cell_knowledge' AND claim_types = '{observation,fact}' AND NOT can_delegate$$,
         :'a_helper', :'a_owner', :'owner', :'c1'), 1);
SELECT t.expect_count('every used sign-in is recorded once, by hash',
  format($$SELECT 1 FROM memory.human_sign_ins_used WHERE session_hash = sha256(uuid_send(%L::uuid)) AND purpose = 'delegate'$$,
         :'own1_session_id'), 1);

\echo '-- a sign-in used to connect a client cannot also delegate, and the reverse'
SELECT id AS owner_member FROM memory.oauth_members WHERE email = 'owner@client.test' \gset
SET ROLE engramport_app;
SELECT t.expect_count('the owner connects a client with a sign-in',
  format($$SELECT 1 WHERE memory.oauth_issue_code(%L, %L, 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', %L, 'https://claude.ai/api/mcp/auth_callback',
           'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'https://mcp.example/mcp', '{read}', sha256('authority-connect-1'))$$,
         :'own3_user_id', :'own3_session_id', :'owner_member'), 1);
SELECT t.expect_count('and that sign-in may connect another client',
  format($$SELECT 1 WHERE memory.oauth_issue_code(%L, %L, 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', %L, 'https://claude.ai/api/mcp/auth_callback',
           'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'https://mcp.example/mcp', '{read}', sha256('authority-connect-2'))$$,
         :'own3_user_id', :'own3_session_id', :'owner_member'), 1);
SELECT t.expect_denied('but it cannot delegate',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'own3_user_id', :'own3_session_id', :'a_owner', :'helper'));
SELECT t.expect_count('and a sign-in spent on a delegation cannot connect a client',
  format($$SELECT 1 WHERE memory.oauth_issue_code(%L, %L, 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', %L, 'https://claude.ai/api/mcp/auth_callback',
           'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'https://mcp.example/mcp', '{read}', sha256('authority-connect-3'))$$,
         :'own1_user_id', :'own1_session_id', :'owner_member'), 0);
RESET ROLE;
SELECT t.expect_count('the connect sign-in is recorded once',
  format($$SELECT 1 FROM memory.human_sign_ins_used WHERE session_hash = sha256(uuid_send(%L::uuid)) AND purpose = 'connect'$$,
         :'own3_session_id'), 1);
SELECT t.expect_denied('a used sign-in record cannot be changed',
  format($$UPDATE memory.human_sign_ins_used SET purpose = 'connect' WHERE session_hash = sha256(uuid_send(%L::uuid))$$, :'own1_session_id'));
SELECT t.expect_denied('or deleted', 'DELETE FROM memory.human_sign_ins_used');
SELECT t.expect_denied('or emptied', 'TRUNCATE memory.human_sign_ins_used');

\echo '-- a person is one email'
INSERT INTO memory.oauth_members (email, namespace_id, actor_id)
  VALUES ('owner-assistant@client.test', :'c1', :'owner') RETURNING id AS assistant_member \gset
SELECT * FROM t.sign_in('owner@client.test') \gset own5_
SELECT * FROM t.sign_in('owner-assistant@client.test') \gset asst_
SET ROLE engramport_app;
SELECT t.expect_denied('while a second email can sign in as the owner, the owner''s sign-in cannot delegate',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'own5_user_id', :'own5_session_id', :'a_owner', :'helper'));
SELECT t.expect_denied('nor can the second email''s',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'asst_user_id', :'asst_session_id', :'a_owner', :'helper'));
RESET ROLE;
UPDATE memory.oauth_members SET revoked_at = now() WHERE id = :'assistant_member';

\echo '-- a delegation cannot be wider or longer than its authority'
-- A temporary narrow authority to delegate from.
SET ROLE engramport_admin;
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, claim_types, can_delegate, expires_at)
  VALUES (:'other', :'c2', 'cell_knowledge', '{decision}', true, now() + interval '7 days') RETURNING id AS a_narrow \gset
RESET ROLE;
SELECT * FROM t.sign_in('other@client.test') \gset oth1_
SELECT * FROM t.sign_in('other@client.test') \gset oth2_
SELECT * FROM t.sign_in('other@client.test') \gset oth3_
SET ROLE engramport_app;
SELECT t.expect_denied('not with claim types it lacks',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L, '{decision,fact}')$$, :'oth1_user_id', :'oth1_session_id', :'a_narrow', :'helper'));
SELECT t.expect_denied('not past its expiry',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L, NULL, now() + interval '30 days')$$, :'oth2_user_id', :'oth2_session_id', :'a_narrow', :'helper'));
SELECT memory.delegate_approval_authority(:'oth3_user_id', :'oth3_session_id', :'a_narrow', :'helper') AS a_narrow_child \gset
RESET ROLE;
SELECT t.expect_count('left out, claim types and expiry are the authority''s own',
  format($$SELECT 1 FROM memory.approval_authorities c JOIN memory.approval_authorities p ON p.id = c.parent_id
           WHERE c.id = %L AND c.claim_types = p.claim_types AND c.expires_at = p.expires_at$$, :'a_narrow_child'), 1);

\echo '-- revoking an authority ends what was delegated from it'
SELECT t.expect_count('the delegation is valid', format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'a_helper'), 1);
SET ROLE engramport_admin;
SELECT t.expect_denied('the admin role cannot revoke a delegation',
  format($$UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'owner_left' WHERE id = %L$$, :'a_helper'), true);
SELECT t.expect_denied('or pass its revocation off as the grantor''s',
  format($$UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'revoked_by_grantor' WHERE id = %L$$, :'a_helper'), true);
SELECT t.expect_denied('or say a top-level authority was revoked by a grantor',
  format($$UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'revoked_by_grantor' WHERE id = %L$$, :'a_promo'));
RESET ROLE;
SELECT t.expect_count('the delegation is still valid and unrevoked',
  format($$SELECT 1 FROM memory.approval_authorities WHERE id = %L AND revoked_at IS NULL AND memory.approval_authority_valid(id)$$, :'a_helper'), 1);
SELECT t.expect_denied('the table owner cannot mark a top-level authority revoked by a grantor either',
  format($$UPDATE memory.approval_authorities SET revoked_at = now(), revoke_reason = 'revoked_by_grantor' WHERE id = %L$$, :'a_promo'));
SET ROLE engramport_admin;
UPDATE memory.approval_authorities SET revoked_at = now() - interval '1 year', revoke_reason = 'owner_left' WHERE id = :'a_owner';
SELECT t.expect_denied('a revoked authority stays revoked',
  format($$UPDATE memory.approval_authorities SET revoked_at = NULL, revoke_reason = NULL WHERE id = %L$$, :'a_owner'), true);
RESET ROLE;
SELECT t.expect_count('a revocation is stamped with the time it happened, not the time given',
  format($$SELECT 1 FROM memory.approval_authorities WHERE id = %L AND revoked_at > now() - interval '1 minute'$$, :'a_owner'), 1);
SELECT t.expect_denied('a revoked authority stays revoked, even for the table owner',
  format($$UPDATE memory.approval_authorities SET revoked_at = NULL, revoke_reason = NULL WHERE id = %L$$, :'a_owner'));
SELECT t.expect_denied('and its revocation time cannot be moved',
  format($$UPDATE memory.approval_authorities SET revoked_at = now() - interval '1 year' WHERE id = %L$$, :'a_owner'));
SELECT t.expect_count('the owner''s authority is no longer valid', format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'a_owner'), 0);
SELECT t.expect_count('nor the delegation made from it', format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'a_helper'), 0);
SET ROLE engramport_app;
SELECT t.expect_denied('and it can no longer be delegated',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'own4_user_id', :'own4_session_id', :'a_owner', :'helper'));
RESET ROLE;

\echo '-- a holder revokes their own delegation; an expired or disabled one is not valid'
SELECT * FROM t.sign_in('other@client.test') \gset oth4_
SELECT * FROM t.sign_in('helper@client.test') \gset help2_
SET ROLE engramport_app;
SELECT t.expect_denied('the delegate cannot revoke it',
  format($$SELECT memory.revoke_delegated_authority(%L, %L, %L)$$, :'help2_user_id', :'help2_session_id', :'a_narrow_child'));
SELECT memory.revoke_delegated_authority(:'oth4_user_id', :'oth4_session_id', :'a_narrow_child');
RESET ROLE;
SELECT t.expect_count('the grantor''s revocation holds',
  format($$SELECT 1 FROM memory.approval_authorities WHERE id = %L AND revoke_reason = 'revoked_by_grantor'$$, :'a_narrow_child'), 1);
SELECT * FROM t.sign_in('other@client.test') \gset oth5_
SET ROLE engramport_app;
SELECT memory.delegate_approval_authority(:'oth5_user_id', :'oth5_session_id', :'a_narrow', :'helper') AS a_narrow_child2 \gset
SELECT t.expect_denied('a sign-in spent on a revocation cannot revoke again',
  format($$SELECT memory.revoke_delegated_authority(%L, %L, %L)$$, :'oth4_user_id', :'oth4_session_id', :'a_narrow_child2'));
RESET ROLE;
SELECT t.expect_count('so the second delegation stands', format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'a_narrow_child2'), 1);
INSERT INTO memory.approval_authorities (actor_id, namespace_id, scope, created_at, expires_at)
  VALUES (:'other', :'c2', 'cell_knowledge', now() - interval '2 days', now() - interval '1 day') RETURNING id AS a_expired \gset
SELECT t.expect_count('an expired authority is not valid', format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'a_expired'), 0);
SELECT t.expect_count('the founder''s authority is valid', format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'a_founder'), 1);
UPDATE memory.actors SET disabled_at = now() WHERE id = :'founder';
SELECT t.expect_count('until the founder''s actor is disabled', format($$SELECT 1 WHERE memory.approval_authority_valid(%L)$$, :'a_founder'), 0);
UPDATE memory.actors SET disabled_at = NULL WHERE id = :'founder';
SELECT t.expect_count('an unknown authority is not valid', $$SELECT 1 WHERE memory.approval_authority_valid(gen_random_uuid())$$, 0);

\echo '-- a sign-in that is stale or not Google does not count'
INSERT INTO auth.sessions (id, user_id, created_at)
  SELECT gen_random_uuid(), u.id, now() - interval '20 minutes' FROM auth.users u WHERE u.email = 'other@client.test'
  RETURNING id AS stale_session, user_id AS stale_user \gset
INSERT INTO auth.mfa_amr_claims (session_id, authentication_method) VALUES (:'stale_session', 'oauth');
SET ROLE engramport_app;
SELECT t.expect_denied('a sign-in older than fifteen minutes',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'stale_user', :'stale_session', :'a_narrow', :'helper'));
RESET ROLE;
INSERT INTO auth.sessions (id, user_id, created_at)
  SELECT gen_random_uuid(), u.id, now() FROM auth.users u WHERE u.email = 'other@client.test'
  RETURNING id AS pw_session, user_id AS pw_user \gset
INSERT INTO auth.mfa_amr_claims (session_id, authentication_method) VALUES (:'pw_session', 'password');
SET ROLE engramport_app;
SELECT t.expect_denied('a fresh password sign-in',
  format($$SELECT memory.delegate_approval_authority(%L, %L, %L, %L)$$, :'pw_user', :'pw_session', :'a_narrow', :'helper'));
RESET ROLE;

\echo '-- Supabase''s API roles get nothing'
SELECT t.expect_count('no API role can use approval authority',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) r
    WHERE has_table_privilege(r, 'memory.approval_authorities', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE')
       OR has_table_privilege(r, 'memory.human_sign_ins_used', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE')
       OR has_function_privilege(r, 'memory.delegate_approval_authority(uuid, uuid, uuid, uuid, memory.claim_type[], timestamptz)', 'EXECUTE')
       OR has_function_privilege(r, 'memory.revoke_delegated_authority(uuid, uuid, uuid)', 'EXECUTE')
       OR has_function_privilege(r, 'memory.approval_authority_valid(uuid)', 'EXECUTE')
       OR has_function_privilege(r, 'memory.consume_human_sign_in(uuid, uuid, text)', 'EXECUTE')
       OR has_function_privilege(r, 'memory.oauth_issue_code(uuid, uuid, text, uuid, text, text, text, text[], bytea)', 'EXECUTE')$$, 0);
SELECT t.expect_count('and the server cannot write authority or sign-in records directly',
  $$SELECT 1 WHERE has_table_privilege('engramport_app', 'memory.approval_authorities', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE')
                OR has_table_privilege('engramport_app', 'memory.human_sign_ins_used', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE')
                OR has_function_privilege('engramport_app', 'memory.consume_human_sign_in(uuid, uuid, text)', 'EXECUTE')$$, 0);
