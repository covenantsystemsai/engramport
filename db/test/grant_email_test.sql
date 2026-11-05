-- Tests for 0027_grant_by_email (founder decision D-02 Grant Recipient
-- Selection): an owner gives a grant by typing the recipient's email, the
-- server writes it only for another enabled, active member of the namespace,
-- and nothing about the address comes back either way. Run by db/test/run.sh
-- after cell_erasure_race_test.sh, on the fixtures and helpers of rls_test,
-- erasure_test and grants_test.
\set ON_ERROR_STOP on
\set QUIET on
\set c1    '00000000-0000-7000-8000-000000000111'
\set c2    '00000000-0000-7000-8000-000000000112'

SELECT id AS owner FROM memory.actors WHERE slug = 'er-owner' \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'ge-friend', 'Friend') RETURNING id AS friend \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'ge-gone', 'Gone') RETURNING id AS gone \gset
INSERT INTO memory.actors (kind, slug, display_name) VALUES ('human', 'ge-left', 'Left') RETURNING id AS left_ \gset
INSERT INTO memory.oauth_members (email, namespace_id, actor_id) VALUES
  ('ge-friend@client.test', :'c1', :'friend'),
  ('ge-gone@client.test', :'c1', :'gone'),
  ('ge-left@client.test', :'c1', :'left_');
UPDATE memory.actors SET disabled_at = now() WHERE id = :'gone';
UPDATE memory.oauth_members SET revoked_at = now() WHERE actor_id = :'left_';
CREATE FUNCTION t.grants_to(p_actor uuid) RETURNS bigint LANGUAGE sql AS $$
  SELECT count(*) FROM memory.data_grants WHERE actor_id = p_actor $$;
SELECT count(*) AS all_before FROM memory.data_grants \gset

\echo '-- refusals are about the request and the caller, before any address is looked up'
SELECT * FROM t.sign_in('er-owner@client.test') \gset s1_
SET ROLE engramport_app;
SELECT t.expect_error('a grant ends within 90 days',
  format($$SELECT memory.offer_data_grant(%L, %L, %L, 'ge-friend@client.test', 'export', now() + interval '91 days')$$,
         :'s1_user_id', :'s1_session_id', :'c1'), '%within 90 days%');
SELECT t.expect_error('an address is needed',
  format($$SELECT memory.offer_data_grant(%L, %L, %L, 'not an address', 'export', now() + interval '30 days')$$,
         :'s1_user_id', :'s1_session_id', :'c1'), '%email address%');
SELECT t.expect_error('and a power',
  format($$SELECT memory.offer_data_grant(%L, %L, %L, 'ge-friend@client.test', NULL, now() + interval '30 days')$$,
         :'s1_user_id', :'s1_session_id', :'c1'), '%erase or export%');
-- Those spent nothing: the same sign-in still opens the page and gives a grant.
SELECT t.expect_count('the owner sees only the namespace before typing',
  format($$SELECT 1 FROM memory.data_grant_giver_view(%L, %L, %L) WHERE namespace_path IS NOT NULL$$,
         :'s1_user_id', :'s1_session_id', :'c1'), 1);
SELECT memory.offer_data_grant(:'s1_user_id', :'s1_session_id', :'c1', '  GE-Friend@Client.test ', 'export',
                               now() + interval '30 days');
RESET ROLE;
SELECT t.expect_count('a member''s address gets the grant, undecided, from the owner',
  format($$SELECT 1 FROM memory.data_grants WHERE actor_id = %L AND granted_by_actor_id = %L AND namespace_id = %L
           AND power = 'export' AND accepted_at IS NULL AND rejected_at IS NULL AND NOT memory.data_grant_valid(id)$$,
         :'friend', :'owner', :'c1'), 1);
SET ROLE engramport_app;
SELECT t.expect_error('each try spends its sign-in',
  format($$SELECT memory.offer_data_grant(%L, %L, %L, 'ge-friend@client.test', 'erase', now() + interval '30 days')$$,
         :'s1_user_id', :'s1_session_id', :'c1'), '%already used%');
RESET ROLE;

\echo '-- any other address: the same outcome, and no grant'
SELECT * FROM t.sign_in('er-owner@client.test') \gset a_
SELECT * FROM t.sign_in('er-owner@client.test') \gset b_
SELECT * FROM t.sign_in('er-owner@client.test') \gset c_
SELECT * FROM t.sign_in('er-owner@client.test') \gset d_
SELECT * FROM t.sign_in('er-owner@client.test') \gset e_
SET ROLE engramport_app;
-- Each returns normally, as the member's did.
SELECT memory.offer_data_grant(:'a_user_id', :'a_session_id', :'c1', 'er-c2@client.test', 'erase', now() + interval '30 days');
SELECT memory.offer_data_grant(:'b_user_id', :'b_session_id', :'c1', 'nobody@nowhere.test', 'erase', now() + interval '30 days');
SELECT memory.offer_data_grant(:'c_user_id', :'c_session_id', :'c1', 'er-owner@client.test', 'erase', now() + interval '30 days');
SELECT memory.offer_data_grant(:'d_user_id', :'d_session_id', :'c1', 'ge-gone@client.test', 'erase', now() + interval '30 days');
SELECT memory.offer_data_grant(:'e_user_id', :'e_session_id', :'c1', 'ge-left@client.test', 'erase', now() + interval '30 days');
RESET ROLE;
SELECT count(*) AS all_after FROM memory.data_grants \gset
SELECT t.expect_count('of all six, only the member''s address wrote a grant',
  format($$SELECT 1 WHERE %s - %s = 1$$, :'all_after', :'all_before'), 1);
SELECT t.expect_count('none to the disabled person, the one who left, or the owner',
  format($$SELECT 1 WHERE t.grants_to(%L) + t.grants_to(%L) + t.grants_to(%L) = 0$$, :'gone', :'left_', :'owner'), 1);

\echo '-- only an owner who may delegate gives one'
SELECT * FROM t.sign_in('er-obs@client.test') \gset ob_
SELECT * FROM t.sign_in('er-c2@client.test') \gset c2_
SET ROLE engramport_app;
SELECT t.expect_error('a limited owner is refused, whatever address they type',
  format($$SELECT memory.offer_data_grant(%L, %L, %L, 'ge-friend@client.test', 'erase', now() + interval '30 days')$$,
         :'ob_user_id', :'ob_session_id', :'c1'), '%may delegate%');
SELECT t.expect_error('and sees nothing of the page',
  format($$SELECT * FROM memory.data_grant_giver_view(%L, %L, %L)$$, :'c2_user_id', :'c2_session_id', :'c1'),
  '%may delegate%');
RESET ROLE;
SET ROLE engramport_admin;
SELECT t.expect_error('the admin can''t give one',
  format($$SELECT memory.offer_data_grant(%L, %L, %L, 'ge-friend@client.test', 'erase', now() + interval '30 days')$$,
         :'c2_user_id', :'c2_session_id', :'c1'), '%permission denied%');
RESET ROLE;

\echo '-- the grant counts only once the recipient accepts its exact terms'
SELECT * FROM t.sign_in('ge-friend@client.test') \gset f_
SELECT g.grant_id, g.grant_sha256 FROM memory.pending_data_grants(:'f_user_id', :'f_session_id') g
  WHERE g.power = 'export' \gset
SELECT memory.decide_data_grant(:'f_user_id', :'f_session_id', :'grant_id', 'accept', :'grant_sha256');
SELECT t.expect_count('accepted, it counts',
  format($$SELECT 1 FROM memory.data_grants WHERE id = %L AND memory.data_grant_valid(id)$$, :'grant_id'), 1);
