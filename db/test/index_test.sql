-- Every foreign key in schema memory has an index that starts with its column,
-- so a later migration that adds a foreign key without one fails here.
\set ON_ERROR_STOP on
\set QUIET on

SELECT t.expect_count('every foreign key in schema memory is indexed',
  $$SELECT c.conrelid::regclass, c.conname
    FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
    WHERE n.nspname = 'memory' AND c.contype = 'f'
      AND NOT EXISTS (
        SELECT 1 FROM pg_index i
        WHERE i.indrelid = c.conrelid
          AND (i.indkey::int2[])[0:array_length(c.conkey, 1) - 1] = c.conkey)$$, 0);

\echo 'all index tests passed'
