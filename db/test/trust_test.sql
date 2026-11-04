-- Tests for 0014_trust_dimensions. Run by db/test/run.sh after the other
-- tests, on the rls_test fixtures (cell 1 and its key).
\set ON_ERROR_STOP on
\set QUIET on
\set c1   '00000000-0000-7000-8000-000000000111'
\set k_c1 '00000000-0000-7000-8000-0000000000f1'

\echo '-- memories written before 0014 start unapproved and unverified'
SELECT t.expect_count('no memory is approved or verified after the migration',
  $$SELECT 1 FROM memory.memories WHERE approval_state <> 'none' OR verification_state <> 'unverified'$$, 0);
SELECT t.expect_count('and every older memory is an observation',
  $$SELECT 1 FROM memory.memories WHERE claim_type <> 'observation'$$, 0);

SET ROLE engramport_app;
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
  SELECT memory.remember('decision', 'trust check: approved by the founder', 'remember', 'rest',
                         p_metadata => '{"approval_state": "approved"}', p_claim_type => 'decision') AS dec_mem \gset
  SELECT memory.remember('fact', 'trust check: plain write', 'remember', 'rest') AS plain_mem \gset
COMMIT;

\echo '-- a write records its claim and nothing more'
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT t.expect_count('the claim type is the writer''s',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND claim_type = 'decision'$$, :'dec_mem'), 1);
SELECT t.expect_count('the claim type defaults to observation',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND claim_type = 'observation'$$, :'plain_mem'), 1);
SELECT t.expect_count('approval in the text or metadata approves nothing',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND approval_state = 'none' AND verification_state = 'unverified'$$, :'dec_mem'), 1);
COMMIT;

\echo '-- the app role cannot approve or verify'
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
SELECT t.expect_denied('an insert that says approved',
  format($$INSERT INTO memory.memories (namespace_id, kind, content, provenance_id, approval_state)
           SELECT namespace_id, kind, content, provenance_id, 'approved' FROM memory.memories WHERE id = %L$$, :'plain_mem'));
SELECT t.expect_denied('an insert that says verified',
  format($$INSERT INTO memory.memories (namespace_id, kind, content, provenance_id, verification_state)
           SELECT namespace_id, kind, content, provenance_id, 'verified' FROM memory.memories WHERE id = %L$$, :'plain_mem'));
SELECT t.expect_denied('an update to approved',
  format($$UPDATE memory.memories SET approval_state = 'approved' WHERE id = %L$$, :'dec_mem'));
SELECT t.expect_denied('an update to verified',
  format($$UPDATE memory.memories SET verification_state = 'verified' WHERE id = %L$$, :'dec_mem'));
SELECT t.expect_denied('an update to the claim type',
  format($$UPDATE memory.memories SET claim_type = 'fact' WHERE id = %L$$, :'plain_mem'));
ROLLBACK;

\echo '-- superseding and retracting still work'
BEGIN; SELECT t.as_key(:'k_c1', :'c1');
UPDATE memory.memories SET status = 'retracted' WHERE id = :'plain_mem';
SELECT t.expect_count('a retraction changes the status only',
  format($$SELECT 1 FROM memory.memories WHERE id = %L AND status = 'retracted' AND claim_type = 'observation'$$, :'plain_mem'), 1);
ROLLBACK;
RESET ROLE;

\echo '-- nobody can change them in place yet, not even the owner'
SELECT t.expect_denied('the table owner cannot approve',
  format($$UPDATE memory.memories SET approval_state = 'approved' WHERE id = %L$$, :'dec_mem'));
SELECT t.expect_denied('the table owner cannot verify',
  format($$UPDATE memory.memories SET verification_state = 'verified' WHERE id = %L$$, :'dec_mem'));
SET ROLE engramport_admin;
SELECT t.expect_denied('the admin role cannot approve',
  format($$UPDATE memory.memories SET approval_state = 'approved' WHERE id = %L$$, :'dec_mem'));
RESET ROLE;

\echo '-- the old remember signature is gone and the new one is the app''s only'
SELECT t.expect_count('one remember function',
  $$SELECT 1 FROM pg_proc WHERE proname = 'remember' AND pronamespace = 'memory'::regnamespace$$, 1);
SELECT t.expect_count('Supabase API roles cannot call it',
  $$SELECT 1 FROM pg_proc p, unnest(ARRAY['anon', 'authenticated', 'service_role']) r
    WHERE p.proname = 'remember' AND p.pronamespace = 'memory'::regnamespace
      AND has_function_privilege(r, p.oid, 'EXECUTE')$$, 0);
SELECT t.expect_count('the guard is not callable by the app',
  $$SELECT 1 WHERE has_function_privilege('engramport_app', 'memory.memories_trust_guard()', 'EXECUTE')$$, 0);
