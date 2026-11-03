-- Hybrid search weighs meaning and keywords more evenly.
--
-- The gte-small benchmark (bench/embeddings.ts) showed hybrid recall ranking
-- the right memory first less often than meaning alone, for two reasons:
--
--   * gte-small's cosine similarities sit close together (most candidates
--     score about 0.8), so the vector part barely separated a close match from
--     a loose one, while keyword relevance runs from 0 to 1.
--   * any query word may match, and the best keyword match is scaled to 1, so
--     a memory sharing one common word with the question scored like one
--     answering all of it.
--
-- memory.search now spreads vector similarity over the candidates the same way
-- keyword relevance already is, and ranks each keyword match first by the share
-- of the question's words it contains, then by how often they appear. Signature, columns and grants are as in
-- 0011; the rest of the function is unchanged.

CREATE OR REPLACE FUNCTION memory.search(
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
           replace(plainto_tsquery('english'::regconfig, coalesce(p_query, ''))::text, ' & ', ' | ') AS anyq,
           -- The query's words, one tsquery each, to measure how much of the
           -- question a keyword match covers.
           ARRAY(SELECT quote_literal(w)::tsquery
                 FROM unnest(tsvector_to_array(to_tsvector('english'::regconfig, coalesce(p_query, '')))) w) AS words
  ),
  vec AS (
    -- gte-small's similarities sit close together, so each one is scaled by
    -- where it falls among the candidates (nearest 1, furthest 0.1). A memory
    -- with no similarity at all still scores 0 and is dropped.
    SELECT v.memory_id, row_number() OVER (ORDER BY v.dist, v.memory_id)::int AS rnk,
           greatest(1 - v.dist, 0)
             * (0.1 + 0.9 * coalesce((max(v.dist) OVER () - v.dist) / nullif(max(v.dist) OVER () - min(v.dist) OVER (), 0), 1)) AS rel
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
    -- A match counts first for the share of the question's words it covers,
    -- then for how often they appear, so one common word ("check", "get"),
    -- however often repeated, no longer scores like the whole question.
    SELECT k.memory_id, row_number() OVER (ORDER BY k.cover DESC, k.rank DESC, k.created_at DESC, k.memory_id)::int AS rnk,
           k.cover * (0.5 + 0.5 * k.rank / nullif(max(k.rank) OVER (), 0)) AS rel
    FROM (
      SELECT a.* FROM (
        SELECT m.id AS memory_id, ts_rank_cd(m.fts, q.tsq) AS rank, m.created_at,
               (SELECT count(*) FROM unnest(q.words) w WHERE m.fts @@ w)::double precision
                 / greatest(cardinality(q.words), 1) AS cover
        FROM memory.memories m,
             (SELECT nullif(anyq, '')::tsquery AS tsq, words FROM params) q
        WHERE 'keyword' = ANY (p_retrievers) AND q.tsq IS NOT NULL
          AND m.fts @@ q.tsq AND m.status = 'active'
          AND (p_kind IS NULL OR m.kind = p_kind)
          AND (p_from IS NULL OR m.created_at >= p_from)
          AND (p_to IS NULL OR m.created_at <= p_to)
      ) a
      -- Candidates are chosen the same way, so a match on every word is not
      -- crowded out by many that repeat one.
      ORDER BY a.cover DESC, a.rank DESC, a.created_at DESC, a.memory_id
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

