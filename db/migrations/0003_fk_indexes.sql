-- 0003_fk_indexes: indexes for the four foreign keys that had none, as the
-- Supabase performance advisor flagged after 0001. Without them, disabling an
-- actor, revoking a key or following a supersedes chain scans whole tables, and
-- deleting a parent row would too. Forward-only; applied by db/migrate.sh.

CREATE INDEX api_keys_actor ON memory.api_keys (actor_id);
CREATE INDEX provenance_actor ON memory.provenance (actor_id);
CREATE INDEX provenance_api_key ON memory.provenance (api_key_id);
-- Most memories supersede nothing, so index only the ones that do.
CREATE INDEX memories_supersedes ON memory.memories (supersedes_id) WHERE supersedes_id IS NOT NULL;
