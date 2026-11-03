-- Embeddings made under a namespace's old model stop being searched by meaning.
--
-- 0011 lets an admin change a namespace's embedding model and says the vectors
-- it already has are no longer searched by meaning. That held for the
-- namespace's own keys, which always query with its current model, but not for
-- the cells below it: a cell still on gte-small kept matching its tower's old
-- gte-small vectors after the tower moved to another model or to none.
--
-- The read policy now shows a key only the embeddings made under their own
-- namespace's current model, so every search (memory.search, vector_search and
-- anything later) drops the stale ones. They stay stored, unread, until they are
-- made again under the new model or the namespace switches back.

DROP POLICY embeddings_read ON memory.memory_embeddings;
CREATE POLICY embeddings_read ON memory.memory_embeddings FOR SELECT TO engramport_app
  USING (
    namespace_id IN (SELECT memory.readable_namespaces())
    AND model IS NOT DISTINCT FROM (
      SELECT n.embedding_model FROM memory.namespaces n WHERE n.id = memory_embeddings.namespace_id
    )
  );
