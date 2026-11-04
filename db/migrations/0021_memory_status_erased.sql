-- D-02: an erased memory keeps only a content-free row.
-- Forward-only; applied by db/migrate.sh in one transaction.
--
-- Postgres can't use a new enum value in the transaction that adds it, so the
-- value gets its own migration and 0022 uses it.

ALTER TYPE memory.memory_status ADD VALUE IF NOT EXISTS 'erased';
