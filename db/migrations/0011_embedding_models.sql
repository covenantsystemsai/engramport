-- 0011_embedding_models: each namespace names the one embedding model its text
-- may be sent to, and the database refuses an embedding from any other.
--
-- Until now every namespace was fixed to OpenAI's text-embedding-3-small. Now:
--
--   memory.embedding_models  the models this store knows, with their size and
--                            whether text sent to them stays inside Supabase.
--   namespaces.embedding_model  the model for this namespace's own memories,
--                            or NULL for none (keyword and graph search only).
--                            New cities default to gte-small, Supabase's own
--                            built-in model, so by default no memory text is
--                            sent outside Supabase. The admin tool gives a new
--                            tower or cell its parent's model unless told
--                            otherwise.
--
-- The server reads the namespace's model before it embeds anything and never
-- sends a namespace's text to a different model. The row security policy on
-- memory_embeddings is the second check: an embedding is accepted only when its
-- model and size are the namespace's own.
--
-- memory_embeddings.embedding loses its fixed size so one table holds both
-- sizes. Each size has its own HNSW index over a cast to that size, and
-- memory.search casts the same way so those indexes are used. Memories read
-- from a tower or city embedded with another model are still found by keyword
-- and graph search, just not by meaning.
--
-- A namespace's model can be changed by the admin role (and only that column).
-- Embeddings already stored under the old model stay, and stop being searched;
-- re-embedding is a separate job, not part of this migration.

CREATE TABLE memory.embedding_models (
  model text PRIMARY KEY CHECK (model ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
  dimension integer NOT NULL CHECK (dimension IN (384, 1536)),
  stays_in_supabase boolean NOT NULL,
  description text NOT NULL
);
INSERT INTO memory.embedding_models (model, dimension, stays_in_supabase, description) VALUES
  ('gte-small', 384, true, 'Supabase built-in model, run by an Edge Function in the same project'),
  ('text-embedding-3-small', 1536, false, 'OpenAI embeddings API');

ALTER TABLE memory.embedding_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE memory.embedding_models FORCE ROW LEVEL SECURITY;
REVOKE ALL ON memory.embedding_models FROM PUBLIC;
GRANT SELECT ON memory.embedding_models TO engramport_app, engramport_admin;
CREATE POLICY embedding_models_read ON memory.embedding_models FOR SELECT
  TO engramport_app, engramport_admin USING (true);

-- Namespaces: one model or none. embedding_dim is now the model's own size.
ALTER TABLE memory.namespaces DROP CONSTRAINT namespaces_embedding_dim_check;
ALTER TABLE memory.namespaces DROP COLUMN embedding_dim;
ALTER TABLE memory.namespaces ALTER COLUMN embedding_model DROP NOT NULL;
ALTER TABLE memory.namespaces ALTER COLUMN embedding_model SET DEFAULT 'gte-small';
ALTER TABLE memory.namespaces
  ADD CONSTRAINT namespaces_embedding_model FOREIGN KEY (embedding_model)
  REFERENCES memory.embedding_models (model);
CREATE INDEX namespaces_embedding_model ON memory.namespaces (embedding_model);

-- The admin role may change a namespace's model and nothing else about it.
GRANT UPDATE (embedding_model) ON memory.namespaces TO engramport_admin;
CREATE POLICY namespaces_admin_embedding ON memory.namespaces FOR UPDATE TO engramport_admin
  USING (true) WITH CHECK (true);

-- Embeddings: either size, matching the stored vector.
DROP INDEX memory.memory_embeddings_hnsw;
ALTER TABLE memory.memory_embeddings DROP CONSTRAINT memory_embeddings_dimension_check;
ALTER TABLE memory.memory_embeddings ALTER COLUMN embedding TYPE extensions.halfvec;
ALTER TABLE memory.memory_embeddings
  ADD CONSTRAINT memory_embeddings_dimension CHECK (dimension IN (384, 1536)),
  ADD CONSTRAINT memory_embeddings_size CHECK (extensions.vector_dims(embedding) = dimension),
  ADD CONSTRAINT memory_embeddings_model FOREIGN KEY (model) REFERENCES memory.embedding_models (model);

CREATE INDEX memory_embeddings_hnsw_384 ON memory.memory_embeddings
  USING hnsw ((embedding::extensions.halfvec(384)) extensions.halfvec_cosine_ops)
  WITH (m = 16, ef_construction = 64) WHERE dimension = 384;
CREATE INDEX memory_embeddings_hnsw_1536 ON memory.memory_embeddings
  USING hnsw ((embedding::extensions.halfvec(1536)) extensions.halfvec_cosine_ops)
  WITH (m = 16, ef_construction = 64) WHERE dimension = 1536;
CREATE INDEX memory_embeddings_model ON memory.memory_embeddings (model);

-- The model this transaction's namespace embeds with, or NULL for none.
CREATE FUNCTION memory.current_embedding_model() RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog AS $$
  SELECT n.embedding_model FROM memory.namespaces n WHERE n.id = memory.current_namespace()
$$;
REVOKE ALL ON FUNCTION memory.current_embedding_model() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.current_embedding_model() TO engramport_app;

DROP POLICY embeddings_write ON memory.memory_embeddings;
CREATE POLICY embeddings_write ON memory.memory_embeddings FOR INSERT TO engramport_app
  WITH CHECK (memory.can_write() AND namespace_id = memory.current_namespace()
    AND memory.is_own_memory(memory_id)
    AND model = memory.current_embedding_model()
    AND dimension = (SELECT em.dimension FROM memory.embedding_models em WHERE em.model = memory_embeddings.model));

-- memory.search as in 0010, with the query vector at either size. Each size's
-- branch casts to that size so its HNSW index is used.
DROP FUNCTION memory.search(text, extensions.halfvec, text, memory.memory_kind, timestamptz, timestamptz, integer, text[]);
CREATE FUNCTION memory.search(
  p_query text,
  p_embedding extensions.halfvec DEFAULT NULL,
  p_model text DEFAULT NULL,
  p_kind memory.memory_kind DEFAULT NULL,
  p_from timestamptz DEFAULT NULL,
  p_to timestamptz DEFAULT NULL,
  p_limit integer DEFAULT 10,
  p_retrievers text[] DEFAULT ARRAY['vector', 'keyword', 'graph']
) RETURNS TABLE (
  memory_id uuid,
  score double precision,
  depth integer,
  vector_rank integer,
  keyword_rank integer,
  graph_rank integer,
  graph_entity text,
  graph_hops integer
)
LANGUAGE sql STABLE SET search_path = pg_catalog, extensions AS $$
  WITH RECURSIVE
  up AS (
    SELECT n.id, n.parent_id, 0 AS depth FROM memory.namespaces n WHERE n.id = memory.current_namespace()
    UNION ALL
    SELECT n.id, n.parent_id, up.depth + 1 FROM memory.namespaces n JOIN up ON n.id = up.parent_id
  ),
  params AS (
    SELECT least(greatest(coalesce(p_limit, 10), 1), 50) AS lim,
           greatest(least(greatest(coalesce(p_limit, 10), 1), 50) * 4, 40) AS pool,
           memory.norm_key(coalesce(p_query, '')) AS qn,
           replace(plainto_tsquery('english'::regconfig, coalesce(p_query, ''))::text, ' & ', ' | ') AS anyq
  ),
  vec AS (
    SELECT v.memory_id, row_number() OVER (ORDER BY v.dist, v.memory_id)::int AS rnk,
           greatest(1 - v.dist, 0) AS rel
    FROM (
      (SELECT e.memory_id, e.embedding::halfvec(384) <=> p_embedding::halfvec(384) AS dist
       FROM memory.memory_embeddings e
       JOIN memory.memories m ON m.id = e.memory_id
       WHERE p_embedding IS NOT NULL AND vector_dims(p_embedding) = 384 AND 'vector' = ANY (p_retrievers)
         AND e.dimension = 384 AND e.model = p_model AND m.status = 'active'
         AND (p_kind IS NULL OR m.kind = p_kind)
         AND (p_from IS NULL OR m.created_at >= p_from)
         AND (p_to IS NULL OR m.created_at <= p_to)
       ORDER BY e.embedding::halfvec(384) <=> p_embedding::halfvec(384)
       LIMIT (SELECT pool FROM params))
      UNION ALL
      (SELECT e.memory_id, e.embedding::halfvec(1536) <=> p_embedding::halfvec(1536) AS dist
       FROM memory.memory_embeddings e
       JOIN memory.memories m ON m.id = e.memory_id
       WHERE p_embedding IS NOT NULL AND vector_dims(p_embedding) = 1536 AND 'vector' = ANY (p_retrievers)
         AND e.dimension = 1536 AND e.model = p_model AND m.status = 'active'
         AND (p_kind IS NULL OR m.kind = p_kind)
         AND (p_from IS NULL OR m.created_at >= p_from)
         AND (p_to IS NULL OR m.created_at <= p_to)
       ORDER BY e.embedding::halfvec(1536) <=> p_embedding::halfvec(1536)
       LIMIT (SELECT pool FROM params))
    ) v
  ),
  kw AS (
    SELECT k.memory_id, row_number() OVER (ORDER BY k.rank DESC, k.created_at DESC, k.memory_id)::int AS rnk,
           k.rank / nullif(max(k.rank) OVER (), 0) AS rel
    FROM (
      SELECT m.id AS memory_id, ts_rank_cd(m.fts, q.tsq) AS rank, m.created_at
      FROM memory.memories m,
           (SELECT nullif(anyq, '')::tsquery AS tsq FROM params) q
      WHERE 'keyword' = ANY (p_retrievers) AND q.tsq IS NOT NULL
        AND m.fts @@ q.tsq AND m.status = 'active'
        AND (p_kind IS NULL OR m.kind = p_kind)
        AND (p_from IS NULL OR m.created_at >= p_from)
        AND (p_to IS NULL OR m.created_at <= p_to)
      ORDER BY rank DESC, m.created_at DESC
      LIMIT (SELECT pool FROM params)
    ) k
  ),
  -- Entities named in the query: the whole name or an alias appears in it,
  -- give or take a letter. Names under three characters are too noisy.
  seeds AS (
    SELECT s.entity_id, max(s.sim) AS sim
    FROM (
      SELECT e.id AS entity_id, word_similarity(e.norm_key, p.qn) AS sim
      FROM memory.entities e, params p
      WHERE 'graph' = ANY (p_retrievers) AND e.status = 'active' AND length(e.norm_key) >= 3
        AND word_similarity(e.norm_key, p.qn) >= 0.8
      UNION ALL
      SELECT a.entity_id, word_similarity(a.norm_key, p.qn)
      FROM memory.entity_aliases a, params p
      WHERE 'graph' = ANY (p_retrievers) AND length(a.norm_key) >= 3
        AND word_similarity(a.norm_key, p.qn) >= 0.8
    ) s
    JOIN memory.entities e ON e.id = s.entity_id AND e.status = 'active'
     AND memory.entity_is_live(e.id, e.origin)
    GROUP BY s.entity_id
  ),
  walk (entity_id, hops, seed_id, sim) AS (
    SELECT entity_id, 0, entity_id, sim FROM seeds
    UNION
    SELECT CASE WHEN r.source_entity_id = w.entity_id THEN r.target_entity_id ELSE r.source_entity_id END,
           w.hops + 1, w.seed_id, w.sim
    FROM walk w
    JOIN memory.relations r ON w.entity_id IN (r.source_entity_id, r.target_entity_id)
    -- The walk only steps onto active entities, so a retracted one breaks every
    -- path through it, as it does for get_entity, even though unlink keeps its
    -- relations for the record.
    JOIN memory.entities nx ON nx.status = 'active'
     AND nx.id = CASE WHEN r.source_entity_id = w.entity_id THEN r.target_entity_id ELSE r.source_entity_id END
     AND memory.entity_is_live(nx.id, nx.origin)
    WHERE w.hops < 2 AND r.status = 'active' AND r.confidence >= 0.5
      AND memory.relation_is_live(r.evidence_memory_id)
  ),
  reached AS (
    SELECT DISTINCT ON (w.entity_id) w.entity_id, w.hops, w.sim
    FROM walk w JOIN memory.entities e ON e.id = w.entity_id AND e.status = 'active'
    ORDER BY w.entity_id, w.hops, w.sim DESC
  ),
  gr AS (
    SELECT g.memory_id, g.entity_id, g.hops, g.sim * power(0.7, g.hops) AS rel,
           row_number() OVER (ORDER BY g.hops, g.sim DESC, g.n DESC, g.created_at DESC, g.memory_id)::int AS rnk
    FROM (
      SELECT DISTINCT ON (mm.memory_id) mm.memory_id, x.entity_id, x.hops, x.sim, m.created_at,
             count(*) OVER (PARTITION BY mm.memory_id) AS n
      FROM reached x
      JOIN memory.entity_mentions mm ON mm.entity_id = x.entity_id
      JOIN memory.memories m ON m.id = mm.memory_id
      WHERE m.status = 'active'
        AND (p_kind IS NULL OR m.kind = p_kind)
        AND (p_from IS NULL OR m.created_at >= p_from)
        AND (p_to IS NULL OR m.created_at <= p_to)
      ORDER BY mm.memory_id, x.hops, x.sim DESC
    ) g
    ORDER BY rnk
    LIMIT (SELECT pool FROM params)
  ),
  cand AS (
    SELECT vec.memory_id FROM vec UNION SELECT kw.memory_id FROM kw UNION SELECT gr.memory_id FROM gr
  ),
  scored AS (
    SELECT c.memory_id, up.depth, m.created_at, v.rnk AS vr, k.rnk AS kr, g.rnk AS grk,
           ge.name AS g_entity, g.hops AS g_hops,
           (0.40 * greatest(coalesce(v.rel, 0), coalesce(g.rel, 0))
          + 0.25 * greatest(coalesce(k.rel, 0), coalesce(g.rel, 0))) / 0.65 AS relevance,
           0.65
         + 0.20 * exp(-greatest(extract(epoch FROM now() - m.created_at), 0) / (86400.0 * 90))
         + 0.10 * CASE m.kind
             WHEN 'decision' THEN 1.0 WHEN 'principle' THEN 0.9 WHEN 'insight' THEN 0.8
             WHEN 'fact' THEN 0.7 WHEN 'summary' THEN 0.6 WHEN 'hypothesis' THEN 0.5
             WHEN 'document_chunk' THEN 0.5 ELSE 0.4 END
         + 0.05 * CASE WHEN p.source_kind IS NOT NULL OR p.log_event_id IS NOT NULL THEN 1.0 ELSE 0.5 END
           AS boost
    FROM cand c
    JOIN memory.memories m ON m.id = c.memory_id
    JOIN up ON up.id = m.namespace_id
    LEFT JOIN memory.provenance p ON p.id = m.provenance_id
    LEFT JOIN vec v ON v.memory_id = c.memory_id
    LEFT JOIN kw k ON k.memory_id = c.memory_id
    LEFT JOIN gr g ON g.memory_id = c.memory_id
    LEFT JOIN memory.entities ge ON ge.id = g.entity_id
  )
  SELECT s.memory_id, s.relevance * s.boost, s.depth, s.vr, s.kr, s.grk, s.g_entity, s.g_hops
  FROM scored s
  WHERE s.relevance >= 0.05
  ORDER BY round((s.relevance * s.boost)::numeric, 4) DESC, s.depth, s.created_at DESC, s.memory_id
  LIMIT (SELECT lim FROM params)
$$;

REVOKE ALL ON FUNCTION memory.search(text, extensions.halfvec, text, memory.memory_kind, timestamptz, timestamptz, integer, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.search(text, extensions.halfvec, text, memory.memory_kind, timestamptz, timestamptz, integer, text[])
  TO engramport_app;


-- Vector search alone (recall mode "vector"): nearest memories by meaning for
-- a query vector of either size, with the raw cosine similarity as the score.
-- Invoker rights, so row security limits it to what the key can read.
CREATE FUNCTION memory.vector_search(
  p_embedding extensions.halfvec,
  p_model text,
  p_kind memory.memory_kind DEFAULT NULL,
  p_from timestamptz DEFAULT NULL,
  p_to timestamptz DEFAULT NULL,
  p_limit integer DEFAULT 10
) RETURNS TABLE (memory_id uuid, score double precision)
LANGUAGE sql STABLE SET search_path = pg_catalog, extensions AS $$
  (SELECT e.memory_id, 1 - (e.embedding::halfvec(384) <=> p_embedding::halfvec(384))
   FROM memory.memory_embeddings e
   JOIN memory.memories m ON m.id = e.memory_id
   WHERE vector_dims(p_embedding) = 384 AND e.dimension = 384 AND e.model = p_model AND m.status = 'active'
     AND (p_kind IS NULL OR m.kind = p_kind)
     AND (p_from IS NULL OR m.created_at >= p_from)
     AND (p_to IS NULL OR m.created_at <= p_to)
   ORDER BY e.embedding::halfvec(384) <=> p_embedding::halfvec(384)
   LIMIT least(greatest(coalesce(p_limit, 10), 1), 50))
  UNION ALL
  (SELECT e.memory_id, 1 - (e.embedding::halfvec(1536) <=> p_embedding::halfvec(1536))
   FROM memory.memory_embeddings e
   JOIN memory.memories m ON m.id = e.memory_id
   WHERE vector_dims(p_embedding) = 1536 AND e.dimension = 1536 AND e.model = p_model AND m.status = 'active'
     AND (p_kind IS NULL OR m.kind = p_kind)
     AND (p_from IS NULL OR m.created_at >= p_from)
     AND (p_to IS NULL OR m.created_at <= p_to)
   ORDER BY e.embedding::halfvec(1536) <=> p_embedding::halfvec(1536)
   LIMIT least(greatest(coalesce(p_limit, 10), 1), 50))
$$;
REVOKE ALL ON FUNCTION memory.vector_search(extensions.halfvec, text, memory.memory_kind, timestamptz, timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION memory.vector_search(extensions.halfvec, text, memory.memory_kind, timestamptz, timestamptz, integer)
  TO engramport_app;

DO $$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA memory FROM %I', r);
      EXECUTE format('REVOKE ALL ON memory.embedding_models FROM %I', r);
    END IF;
  END LOOP;
END
$$;
