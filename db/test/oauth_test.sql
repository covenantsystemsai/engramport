-- Tests for 0009_oauth. Run by db/test/run.sh after search_test.sql, with the
-- helpers in schema t and the rls_test namespaces in place. Supabase Auth's
-- tables are stood in for with the few columns the migration reads.
\set ON_ERROR_STOP on
\set QUIET on
\set c3 '00000000-0000-7000-8000-000000000121'
\set c2 '00000000-0000-7000-8000-000000000112'

CREATE SCHEMA IF NOT EXISTS auth;
CREATE TABLE IF NOT EXISTS auth.users (
  id uuid PRIMARY KEY, email text, email_confirmed_at timestamptz, banned_until timestamptz,
  deleted_at timestamptz, is_anonymous boolean NOT NULL DEFAULT false);
CREATE TABLE IF NOT EXISTS auth.identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL, provider text NOT NULL,
  provider_id text, identity_data jsonb NOT NULL, last_sign_in_at timestamptz);
CREATE TABLE IF NOT EXISTS auth.sessions (
  id uuid PRIMARY KEY, user_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  not_after timestamptz);
CREATE TABLE IF NOT EXISTS auth.mfa_amr_claims (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), session_id uuid NOT NULL, authentication_method text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now());

\set u_ok   '00000000-0000-4000-8000-00000000a001'
\set u_new  '00000000-0000-4000-8000-00000000a002'
\set u_pw   '00000000-0000-4000-8000-00000000a003'
\set s_ok   '00000000-0000-4000-8000-00000000b001'
\set s_old  '00000000-0000-4000-8000-00000000b002'
\set s_end  '00000000-0000-4000-8000-00000000b003'
\set s_new  '00000000-0000-4000-8000-00000000b004'
\set s_pw   '00000000-0000-4000-8000-00000000b005'
\set u_both '00000000-0000-4000-8000-00000000a004'
\set s_both_pw '00000000-0000-4000-8000-00000000b006'
\set s_both_other '00000000-0000-4000-8000-00000000b007'
\set s_ok_pw '00000000-0000-4000-8000-00000000b008'
INSERT INTO auth.users (id, email) VALUES
  (:'u_ok', 'Owner@Example.com'), (:'u_new', 'unverified@example.com'), (:'u_pw', 'owner2@example.com'),
  (:'u_both', 'owner@example.com');
-- u_both has a verified Google identity that last signed in an hour ago, and
-- a password; its fresh sessions come from the password and from another
-- OAuth provider, never from Google.
INSERT INTO auth.identities (user_id, provider, identity_data, last_sign_in_at) VALUES
  (:'u_ok', 'google', '{"email": "Owner@Example.com", "email_verified": true}', now()),
  (:'u_new', 'google', '{"email": "unverified@example.com", "email_verified": false}', now()),
  (:'u_pw', 'email', '{"email": "owner2@example.com", "email_verified": true}', now()),
  (:'u_both', 'google', '{"email": "owner@example.com", "email_verified": true}', now() - interval '1 hour'),
  (:'u_both', 'email', '{"email": "owner@example.com", "email_verified": true}', now()),
  (:'u_both', 'github', '{"email": "owner@example.com", "email_verified": true}', now());
INSERT INTO auth.sessions (id, user_id, created_at, not_after) VALUES
  (:'s_ok', :'u_ok', now(), NULL),
  (:'s_old', :'u_ok', now() - interval '20 minutes', NULL),
  (:'s_end', :'u_ok', now(), now() - interval '1 second'),
  (:'s_new', :'u_new', now(), NULL),
  (:'s_pw', :'u_pw', now(), NULL),
  (:'s_both_pw', :'u_both', now(), NULL),
  (:'s_both_other', :'u_both', now(), NULL),
  (:'s_ok_pw', :'u_ok', now(), NULL);
INSERT INTO auth.mfa_amr_claims (session_id, authentication_method) VALUES
  (:'s_ok', 'oauth'), (:'s_old', 'oauth'), (:'s_end', 'oauth'), (:'s_new', 'oauth'), (:'s_pw', 'password'),
  (:'s_both_pw', 'password'), (:'s_both_other', 'oauth'), (:'s_ok_pw', 'magiclink');

-- Members, made by the admin role: write in cell 3, read-only in cell 2, and
-- one for an email that only signs in with a password.
SET ROLE engramport_admin;
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('agent', 'oauth-claude', 'Claude')
  RETURNING id AS actor \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id, scopes)
  VALUES ('owner@example.com', :'c3', :'actor', '{read,write}') RETURNING id AS m_rw \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id, scopes)
  VALUES ('owner@example.com', :'c2', :'actor', '{read}') RETURNING id AS m_ro \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id, scopes)
  VALUES ('owner2@example.com', :'c3', :'actor', '{read}') RETURNING id AS m_pw \gset
SELECT t.expect_denied('an email is stored lower case',
  format($$INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ('Owner@Example.com', %L, %L)$$,
         :'c3', :'actor'));
SELECT t.expect_denied('one active membership per email, namespace and actor',
  format($$INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES ('owner@example.com', %L, %L)$$,
         :'c3', :'actor'));
SELECT t.expect_denied('a membership cannot be write-only',
  format($$INSERT INTO memory.oauth_members (email, namespace_id, actor_id, scopes) VALUES ('w@example.com', %L, %L, '{write}')$$,
         :'c3', :'actor'));
SELECT t.expect_denied('a membership cannot move to another namespace',
  format($$UPDATE memory.oauth_members SET namespace_id = %L WHERE id = %L$$, :'c2', :'m_rw'));
SELECT t.expect_denied('or another email',
  format($$UPDATE memory.oauth_members SET email = 'x@example.com' WHERE id = %L$$, :'m_rw'));
SELECT t.expect_denied('the admin role cannot delete a membership',
  format($$DELETE FROM memory.oauth_members WHERE id = %L$$, :'m_rw'));
RESET ROLE;

\echo '-- shape'
SELECT t.expect_count('the oauth tables have row security on and forced',
  $$SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'memory' AND c.relname LIKE 'oauth\_%' AND c.relkind = 'r'
      AND c.relrowsecurity AND c.relforcerowsecurity$$, 5);
SELECT t.expect_count('the server role has no table rights on them',
  $$SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'memory' AND c.relname LIKE 'oauth\_%' AND c.relkind = 'r'
      AND has_table_privilege('engramport_app', c.oid, 'SELECT, INSERT, UPDATE, DELETE')$$, 0);
SELECT t.expect_count('nor on any of their columns',
  $$SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'memory' AND c.relname LIKE 'oauth\_%' AND c.relkind = 'r' AND a.attnum > 0
      AND has_column_privilege('engramport_app', c.oid, a.attnum, 'SELECT, INSERT, UPDATE')$$, 0);
SELECT t.expect_count('the server role runs exactly the seven entry points',
  $$SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'memory' AND p.proname LIKE 'oauth\_%'
      AND has_function_privilege('engramport_app', p.oid, 'EXECUTE')$$, 7);
SELECT t.expect_count('nothing in schema memory is executable by PUBLIC',
  $$SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'memory' AND has_function_privilege('public', p.oid, 'EXECUTE')$$, 0);
SELECT t.expect_count('no API role can touch the oauth tables',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) r,
         pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'memory' AND c.relname LIKE 'oauth\_%' AND c.relkind = 'r'
      AND has_table_privilege(r, c.oid, 'SELECT, INSERT, UPDATE, DELETE')$$, 0);
SELECT t.expect_count('or run the oauth functions',
  $$SELECT 1 FROM unnest(ARRAY['anon', 'authenticated', 'service_role']) r,
         pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'memory' AND p.proname LIKE 'oauth\_%' AND has_function_privilege(r, p.oid, 'EXECUTE')$$, 0);
SELECT t.expect_count('PKCE S256 matches the RFC 7636 example',
  $$SELECT 1 WHERE memory.oauth_pkce_s256('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
                   = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'$$, 1);

\echo '-- registering a client'
SET ROLE engramport_app;
SELECT memory.oauth_register_client('epc_aaaaaaaaaaaaaaaaaaaaaaaa', 'Claude',
  ARRAY['https://claude.ai/api/mcp/auth_callback']) IS NOT NULL;
SELECT memory.oauth_register_client('epc_bbbbbbbbbbbbbbbbbbbbbbbb', 'Desktop',
  ARRAY['http://127.0.0.1:33418/callback']) IS NOT NULL;
SELECT t.expect_count('a registered client can be looked up',
  $$SELECT 1 FROM memory.oauth_client('epc_aaaaaaaaaaaaaaaaaaaaaaaa') WHERE client_name = 'Claude'$$, 1);
SELECT t.expect_denied('a redirect must be https',
  $$SELECT memory.oauth_register_client('epc_cccccccccccccccccccccccc', 'x', ARRAY['http://evil.example/cb'])$$);
SELECT t.expect_denied('a redirect has no fragment',
  $$SELECT memory.oauth_register_client('epc_cccccccccccccccccccccccc', 'x', ARRAY['https://a.example/cb#x'])$$);
SELECT t.expect_denied('a redirect host has no user part',
  $$SELECT memory.oauth_register_client('epc_cccccccccccccccccccccccc', 'x', ARRAY['https://claude.ai@evil.example/cb'])$$);
SELECT t.expect_denied('a localhost look-alike is not localhost',
  $$SELECT memory.oauth_register_client('epc_cccccccccccccccccccccccc', 'x', ARRAY['http://localhost.evil.example/cb'])$$);
SELECT t.expect_denied('at most five redirects',
  $$SELECT memory.oauth_register_client('epc_cccccccccccccccccccccccc', 'x',
      ARRAY['https://a.example/1', 'https://a.example/2', 'https://a.example/3', 'https://a.example/4',
            'https://a.example/5', 'https://a.example/6'])$$);
SELECT t.expect_denied('a client name has no control characters',
  $$SELECT memory.oauth_register_client('epc_cccccccccccccccccccccccc', E'Claude\nApprove', ARRAY['https://a.example/cb'])$$);
SELECT t.expect_denied('a client id has the server''s format',
  $$SELECT memory.oauth_register_client('claude', 'x', ARRAY['https://a.example/cb'])$$);
SELECT t.expect_denied('the server role cannot read clients directly', 'SELECT * FROM memory.oauth_clients');

\echo '-- who may sign in'
SELECT t.expect_count('a fresh Google session sees its memberships',
  format($$SELECT 1 FROM memory.oauth_member_choices(%L, %L)$$, :'u_ok', :'s_ok'), 2);
SELECT t.expect_count('with their namespaces and scopes',
  format($$SELECT 1 FROM memory.oauth_member_choices(%L, %L)
           WHERE (namespace_path = 'testcity/tower-b/cell-3' AND scopes = '{read,write}')
              OR (namespace_path = 'testcity/tower-a/cell-2' AND scopes = '{read}')$$, :'u_ok', :'s_ok'), 2);
SELECT t.expect_count('a session older than 15 minutes sees none',
  format($$SELECT 1 FROM memory.oauth_member_choices(%L, %L)$$, :'u_ok', :'s_old'), 0);
SELECT t.expect_count('an ended session sees none',
  format($$SELECT 1 FROM memory.oauth_member_choices(%L, %L)$$, :'u_ok', :'s_end'), 0);
SELECT t.expect_count('a session of another user sees none',
  format($$SELECT 1 FROM memory.oauth_member_choices(%L, %L)$$, :'u_new', :'s_ok'), 0);
SELECT t.expect_count('an unverified Google email sees none',
  format($$SELECT 1 FROM memory.oauth_member_choices(%L, %L)$$, :'u_new', :'s_new'), 0);
SELECT t.expect_count('a password sign-in sees none, even for a member''s email',
  format($$SELECT 1 FROM memory.oauth_member_choices(%L, %L)$$, :'u_pw', :'s_pw'), 0);
SELECT t.expect_count('a password session sees none, though the account also has a Google identity',
  format($$SELECT 1 FROM memory.oauth_member_choices(%L, %L)$$, :'u_both', :'s_both_pw'), 0);
SELECT t.expect_count('nor a magic-link session started just after a Google sign-in',
  format($$SELECT 1 FROM memory.oauth_member_choices(%L, %L)$$, :'u_ok', :'s_ok_pw'), 0);
SELECT t.expect_count('nor a session from another OAuth provider',
  format($$SELECT 1 FROM memory.oauth_member_choices(%L, %L)$$, :'u_both', :'s_both_other'), 0);
SELECT t.expect_count('no session sees none',
  format($$SELECT 1 FROM memory.oauth_member_choices(%L, NULL)$$, :'u_ok'), 0);

\echo '-- issuing a code'
-- Challenge for the RFC 7636 example verifier.
\set verifier 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
\set challenge 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
\set cb 'https://claude.ai/api/mcp/auth_callback'
\set res 'https://mcp.example/mcp'
SELECT t.expect_count('a member gets a code for a registered redirect',
  format($$SELECT 1 WHERE memory.oauth_issue_code(%L, %L, 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', %L, %L, %L, %L, '{read,write}', sha256('code-1'))$$,
         :'u_ok', :'s_ok', :'m_rw', :'cb', :'challenge', :'res'), 1);
SELECT t.expect_count('not for a redirect the client did not register',
  format($$SELECT 1 WHERE memory.oauth_issue_code(%L, %L, 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', %L, 'https://claude.ai/other', %L, %L, '{read}', sha256('code-x'))$$,
         :'u_ok', :'s_ok', :'m_rw', :'challenge', :'res'), 0);
SELECT t.expect_count('not for more scopes than the membership has',
  format($$SELECT 1 WHERE memory.oauth_issue_code(%L, %L, 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', %L, %L, %L, %L, '{read,write}', sha256('code-x'))$$,
         :'u_ok', :'s_ok', :'m_ro', :'cb', :'challenge', :'res'), 0);
SELECT t.expect_count('not for someone else''s membership',
  format($$SELECT 1 WHERE memory.oauth_issue_code(%L, %L, 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', %L, %L, %L, %L, '{read}', sha256('code-x'))$$,
         :'u_ok', :'s_ok', :'m_pw', :'cb', :'challenge', :'res'), 0);
SELECT t.expect_count('not from a stale session',
  format($$SELECT 1 WHERE memory.oauth_issue_code(%L, %L, 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', %L, %L, %L, %L, '{read}', sha256('code-x'))$$,
         :'u_ok', :'s_old', :'m_rw', :'cb', :'challenge', :'res'), 0);
SELECT t.expect_count('not for an unknown client',
  format($$SELECT 1 WHERE memory.oauth_issue_code(%L, %L, 'epc_zzzzzzzzzzzzzzzzzzzzzzzz', %L, %L, %L, %L, '{read}', sha256('code-x'))$$,
         :'u_ok', :'s_ok', :'m_rw', :'cb', :'challenge', :'res'), 0);
SELECT t.expect_denied('a challenge must be an S256 value',
  format($$SELECT memory.oauth_issue_code(%L, %L, 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', %L, %L, 'plain', %L, '{read}', sha256('code-x'))$$,
         :'u_ok', :'s_ok', :'m_rw', :'cb', :'res'));
SELECT memory.oauth_issue_code(:'u_ok', :'s_ok', 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', :'m_rw', :'cb', :'challenge', :'res',
  '{read,write}', sha256('code-2'));
SELECT memory.oauth_issue_code(:'u_ok', :'s_ok', 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', :'m_ro', :'cb', :'challenge', :'res',
  '{read}', sha256('code-3'));
SELECT memory.oauth_issue_code(:'u_ok', :'s_ok', 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', :'m_rw', :'cb', :'challenge', :'res',
  '{read}', sha256('code-4'));
RESET ROLE;
UPDATE memory.oauth_codes SET expires_at = now() - interval '1 second' WHERE code_hash = sha256('code-4');
SET ROLE engramport_app;

\echo '-- trading a code'
SELECT t.expect_count('another client cannot redeem the code',
  format($$SELECT 1 FROM memory.oauth_exchange_code('epc_bbbbbbbbbbbbbbbbbbbbbbbb', sha256('code-1'), %L, %L, %L,
           'ep_live_oauthtest0x', sha256('x'), sha256('rx')) WHERE status = 'invalid_grant'$$, :'verifier', :'cb', :'res'), 1);
SELECT t.expect_count('the right verifier gets tokens bound to the member''s namespace',
  format($$SELECT 1 FROM memory.oauth_exchange_code('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('code-1'), %L, %L, %L,
           'ep_live_oauthtest01', sha256('access-1'), sha256('refresh-1'))
           WHERE status = 'ok' AND scopes = '{read,write}' AND namespace_path = 'testcity/tower-b/cell-3'
             AND access_expires_at BETWEEN now() + interval '59 minutes' AND now() + interval '61 minutes'$$,
         :'verifier', :'cb', :'res'), 1);
SELECT t.expect_count('the access token is a working key for that namespace and actor',
  format($$SELECT 1 FROM memory.authenticate('ep_live_oauthtest01', sha256('access-1'))
           WHERE namespace_id = %L AND actor_id = %L AND scopes = '{read,write}'$$, :'c3', :'actor'), 1);
SELECT t.expect_count('a code works only once',
  format($$SELECT 1 FROM memory.oauth_exchange_code('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('code-1'), %L, %L, %L,
           'ep_live_oauthtest02', sha256('access-2'), sha256('refresh-2')) WHERE status = 'invalid_grant'$$,
         :'verifier', :'cb', :'res'), 1);
SELECT t.expect_count('and using it again revokes the tokens it got',
  $$SELECT 1 FROM memory.authenticate('ep_live_oauthtest01', sha256('access-1'))$$, 0);
SELECT t.expect_count('a wrong verifier gets nothing',
  format($$SELECT 1 FROM memory.oauth_exchange_code('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('code-2'),
           'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', %L, %L,
           'ep_live_oauthtest03', sha256('access-3'), sha256('refresh-3')) WHERE status = 'invalid_grant'$$, :'cb', :'res'), 1);
SELECT t.expect_count('and spends the code, so the right verifier is too late',
  format($$SELECT 1 FROM memory.oauth_exchange_code('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('code-2'), %L, %L, %L,
           'ep_live_oauthtest03', sha256('access-3'), sha256('refresh-3')) WHERE status = 'invalid_grant'$$,
         :'verifier', :'cb', :'res'), 1);
SELECT t.expect_count('the redirect must match the one the code was issued for',
  format($$SELECT 1 FROM memory.oauth_exchange_code('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('code-3'), %L,
           'https://claude.ai/other', %L, 'ep_live_oauthtest04', sha256('access-4'), sha256('refresh-4'))
           WHERE status = 'invalid_grant'$$, :'verifier', :'res'), 1);
SELECT t.expect_count('an expired code gets nothing',
  format($$SELECT 1 FROM memory.oauth_exchange_code('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('code-4'), %L, %L, %L,
           'ep_live_oauthtest05', sha256('access-5'), sha256('refresh-5')) WHERE status = 'invalid_grant'$$,
         :'verifier', :'cb', :'res'), 1);
SELECT t.expect_count('no failed trade minted a key',
  $$SELECT 1 FROM memory.authenticate('ep_live_oauthtest03', sha256('access-3'))
    UNION ALL SELECT 1 FROM memory.authenticate('ep_live_oauthtest04', sha256('access-4'))
    UNION ALL SELECT 1 FROM memory.authenticate('ep_live_oauthtest05', sha256('access-5'))$$, 0);

\echo '-- refreshing'
SELECT memory.oauth_issue_code(:'u_ok', :'s_ok', 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', :'m_rw', :'cb', :'challenge', :'res',
  '{read,write}', sha256('code-5'));
SELECT status FROM memory.oauth_exchange_code('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('code-5'), :'verifier', :'cb', :'res',
  'ep_live_oauthtest06', sha256('access-6'), sha256('refresh-6'));
SELECT t.expect_count('another client cannot use the refresh token',
  format($$SELECT 1 FROM memory.oauth_refresh('epc_bbbbbbbbbbbbbbbbbbbbbbbb', sha256('refresh-6'), %L,
           'ep_live_oauthtest0y', sha256('y'), sha256('ry')) WHERE status = 'invalid_grant'$$, :'res'), 1);
SELECT t.expect_count('nor for another resource',
  $$SELECT 1 FROM memory.oauth_refresh('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('refresh-6'), 'https://other.example/mcp',
      'ep_live_oauthtest0y', sha256('y'), sha256('ry')) WHERE status = 'invalid_grant'$$, 1);
SELECT t.expect_count('the client gets a new access token and refresh token',
  format($$SELECT 1 FROM memory.oauth_refresh('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('refresh-6'), %L,
           'ep_live_oauthtest07', sha256('access-7'), sha256('refresh-7')) WHERE status = 'ok'$$, :'res'), 1);
SELECT t.expect_count('which works',
  $$SELECT 1 FROM memory.authenticate('ep_live_oauthtest07', sha256('access-7'))$$, 1);
SELECT t.expect_count('the new refresh token works once in turn',
  $$SELECT 1 FROM memory.oauth_refresh('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('refresh-7'), NULL,
      'ep_live_oauthtest08', sha256('access-8'), sha256('refresh-8')) WHERE status = 'ok'$$, 1);
SELECT t.expect_count('presenting a spent refresh token is refused',
  format($$SELECT 1 FROM memory.oauth_refresh('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('refresh-6'), %L,
           'ep_live_oauthtest09', sha256('access-9'), sha256('refresh-9')) WHERE status = 'invalid_grant'$$, :'res'), 1);
SELECT t.expect_count('and revokes the whole grant: every access token',
  $$SELECT 1 FROM memory.authenticate('ep_live_oauthtest07', sha256('access-7'))
    UNION ALL SELECT 1 FROM memory.authenticate('ep_live_oauthtest08', sha256('access-8'))$$, 0);
SELECT t.expect_count('and the newest refresh token',
  $$SELECT 1 FROM memory.oauth_refresh('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('refresh-8'), NULL,
      'ep_live_oauthtest10', sha256('access-10'), sha256('refresh-10')) WHERE status = 'ok'$$, 0);

\echo '-- revoking'
SELECT memory.oauth_issue_code(:'u_ok', :'s_ok', 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', :'m_rw', :'cb', :'challenge', :'res',
  '{read,write}', sha256('code-6'));
SELECT status FROM memory.oauth_exchange_code('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('code-6'), :'verifier', :'cb', :'res',
  'ep_live_oauthtest11', sha256('access-11'), sha256('refresh-11'));
SELECT memory.oauth_revoke('epc_bbbbbbbbbbbbbbbbbbbbbbbb', sha256('refresh-11'));
SELECT t.expect_count('another client cannot revoke a grant',
  $$SELECT 1 FROM memory.authenticate('ep_live_oauthtest11', sha256('access-11'))$$, 1);
SELECT memory.oauth_revoke('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('refresh-11'));
SELECT t.expect_count('the client revokes its grant with the refresh token',
  $$SELECT 1 FROM memory.authenticate('ep_live_oauthtest11', sha256('access-11'))$$, 0);
SELECT memory.oauth_issue_code(:'u_ok', :'s_ok', 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', :'m_rw', :'cb', :'challenge', :'res',
  '{read,write}', sha256('code-7'));
SELECT status FROM memory.oauth_exchange_code('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('code-7'), :'verifier', :'cb', :'res',
  'ep_live_oauthtest12', sha256('access-12'), sha256('refresh-12'));
SELECT memory.oauth_revoke('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('access-12'), 'ep_live_oauthtest12');
SELECT t.expect_count('or with an access token',
  $$SELECT 1 FROM memory.oauth_refresh('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('refresh-12'), NULL,
      'ep_live_oauthtest13', sha256('access-13'), sha256('refresh-13')) WHERE status = 'ok'$$, 0);
RESET ROLE;

\echo '-- what the admin role sees and does'
SET ROLE engramport_app;
SELECT memory.oauth_issue_code(:'u_ok', :'s_ok', 'epc_aaaaaaaaaaaaaaaaaaaaaaaa', :'m_rw', :'cb', :'challenge', :'res',
  '{read,write}', sha256('code-8'));
SELECT status FROM memory.oauth_exchange_code('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('code-8'), :'verifier', :'cb', :'res',
  'ep_live_oauthtest14', sha256('access-14'), sha256('refresh-14'));
RESET ROLE;
SET ROLE engramport_admin;
SELECT t.expect_count('the admin role sees grants and why they ended',
  $$SELECT 1 FROM memory.oauth_grants WHERE revoke_reason IN ('code_reuse', 'refresh_reuse', 'client_revoked')$$, 4);
SELECT t.expect_count('and which key belongs to which grant',
  $$SELECT 1 FROM memory.api_keys WHERE oauth_grant_id IS NOT NULL$$, 7);
SELECT t.expect_denied('but never a code', 'SELECT * FROM memory.oauth_codes');
SELECT t.expect_denied('or a refresh token', 'SELECT * FROM memory.oauth_refresh_tokens');
SELECT t.expect_denied('and cannot mint a key for a grant',
  format($$INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, oauth_grant_id)
           SELECT %L, %L, 'ep_live_oauthforge1', sha256('forge'), id FROM memory.oauth_grants LIMIT 1$$, :'c3', :'actor'));
SELECT t.expect_denied('or restore a revoked grant',
  $$UPDATE memory.oauth_grants SET revoked_at = NULL, revoke_reason = NULL WHERE revoked_at IS NOT NULL$$, true);
SELECT t.expect_rows('revoking a membership',
  format($$UPDATE memory.oauth_members SET revoked_at = now() WHERE id = %L$$, :'m_rw'), 1);
RESET ROLE;
SELECT t.expect_count('ends its grants',
  format($$SELECT 1 FROM memory.oauth_grants WHERE member_id = %L AND revoked_at IS NULL$$, :'m_rw'), 0);
SELECT t.expect_count('and their access tokens',
  $$SELECT 1 FROM memory.authenticate('ep_live_oauthtest14', sha256('access-14'))$$, 0);
SET ROLE engramport_app;
SELECT t.expect_count('and refresh fails',
  $$SELECT 1 FROM memory.oauth_refresh('epc_aaaaaaaaaaaaaaaaaaaaaaaa', sha256('refresh-14'), NULL,
      'ep_live_oauthtest15', sha256('access-15'), sha256('refresh-15')) WHERE status = 'ok'$$, 0);
SELECT t.expect_count('and the membership is no longer offered',
  format($$SELECT 1 FROM memory.oauth_member_choices(%L, %L) WHERE member_id = %L$$, :'u_ok', :'s_ok', :'m_rw'), 0);
RESET ROLE;
SELECT t.expect_denied('not even the owner can restore a membership',
  format($$UPDATE memory.oauth_members SET revoked_at = NULL WHERE id = %L$$, :'m_rw'));
SELECT t.expect_denied('or change a key''s grant',
  $$UPDATE memory.api_keys SET oauth_grant_id = NULL WHERE oauth_grant_id IS NOT NULL$$);

\echo 'all oauth tests passed'
