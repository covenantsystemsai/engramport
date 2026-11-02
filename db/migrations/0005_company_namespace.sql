-- 0005_company_namespace: one namespace tree for the operator's own company,
-- kept apart from every client. Forward-only; applied by db/migrate.sh in one
-- transaction.
--
-- Reads flow down the tree: a cell reads itself, its tower and its city. So
-- the only way company knowledge could reach a client, or client data reach
-- the company, is for the two to share an ancestor. This migration makes that
-- impossible at the database level rather than by convention:
--   * Every namespace has a purpose, client or company.
--   * A city chooses its purpose when it is created; a tower or cell always
--     has its parent's purpose. So a company city holds only company towers and
--     cells, and a client city never holds a company one.
--   * A purpose never changes, and (from 0001) a namespace never moves.
--   * There is at most one company city.
-- Existing namespaces are all client namespaces.

CREATE TYPE memory.namespace_purpose AS ENUM ('client', 'company');

ALTER TABLE memory.namespaces
  ADD COLUMN purpose memory.namespace_purpose NOT NULL DEFAULT 'client';

CREATE FUNCTION memory.namespaces_purpose() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
  parent_purpose memory.namespace_purpose;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.purpose IS DISTINCT FROM OLD.purpose THEN
      RAISE EXCEPTION 'a namespace''s purpose cannot change';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.parent_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT n.purpose INTO parent_purpose FROM memory.namespaces n WHERE n.id = NEW.parent_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'parent namespace % does not exist', NEW.parent_id;
  END IF;
  IF NEW.purpose IS DISTINCT FROM parent_purpose THEN
    RAISE EXCEPTION 'a % namespace cannot sit under a % namespace', NEW.purpose, parent_purpose;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER namespaces_purpose BEFORE INSERT OR UPDATE ON memory.namespaces
  FOR EACH ROW EXECUTE FUNCTION memory.namespaces_purpose();

CREATE UNIQUE INDEX namespaces_one_company_city ON memory.namespaces ((true))
  WHERE purpose = 'company' AND parent_id IS NULL;

REVOKE ALL ON FUNCTION memory.namespaces_purpose() FROM PUBLIC;

DO $$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['anon', 'authenticated', 'service_role'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA memory FROM %I', r);
      EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA memory FROM %I', r);
    END IF;
  END LOOP;
END
$$;
