/**
 * `engramport admin`: manage namespaces, actors and keys in the memory store.
 *
 * Runs as the engramport_admin database role (migration 0002), which can
 * create namespaces and actors, mint, rotate and revoke keys, and read the
 * audit trail (0006): who wrote, through which agent, client, tool and
 * transport, where and when. It cannot read memories, embeddings, graph rows,
 * stored key hashes, or the parts of provenance that could carry or confirm
 * content, and it cannot delete. The connection URL may belong to any login role that has been
 * granted SET on engramport_admin; every transaction switches to that role
 * first, so a more powerful login is still held to the admin role's limits.
 *
 * A minted key is printed once, alone on stdout, so it can be piped straight
 * into a secrets manager. Only its HMAC is stored.
 *
 * Settings: ENGRAMPORT_ADMIN_DATABASE_URL, ENGRAMPORT_DATABASE_CA_FILE (optional),
 * ENGRAMPORT_KEY_PEPPER (for mint and rotate; the same pepper the server uses).
 */

import pg from "pg";
import { decodePepper, hashKey, KEY_PREFIX, mintKey } from "./keys.js";
import { createPool } from "./store/postgres.js";

export const ADMIN_ROLE = "engramport_admin";
export const ACTOR_KINDS = ["agent", "human", "service"] as const;
export type ActorKind = (typeof ACTOR_KINDS)[number];

const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const LEVELS = ["city", "tower", "cell"] as const;
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
const MAX_DURATION_MS = 3650 * 24 * 3600 * 1000;

export class AdminError extends Error {}

export type NamespacePurpose = "client" | "company";

export interface NamespaceRow {
  path: string;
  level: string;
  purpose: NamespacePurpose;
  created_at: Date;
}
export interface ActorRow {
  slug: string;
  kind: string;
  display_name: string;
  disabled_at: Date | null;
  created_at: Date;
}
export interface KeyRow {
  prefix: string;
  namespace: string;
  actor: string;
  scopes: string[];
  created_at: Date;
  expires_at: Date | null;
  revoked_at: Date | null;
  last_used_at: Date | null;
}
export type AuditEvent = "write" | "key minted" | "key revoked";

/** One line of the audit trail. Metadata only: no content, hash or claimed fields. */
export interface AuditRow {
  at: Date;
  event: AuditEvent;
  namespace: string;
  actor: string;
  key_prefix: string;
  tool: string | null;
  transport: string | null;
  client: string | null;
  session_id: string | null;
  request_id: string | null;
}

export interface AuditFilter {
  /** A namespace path; its towers and cells are included. */
  namespace?: string;
  actor?: string;
  sinceMs?: number;
  /** 1 to 1000, default 100. */
  limit?: number;
  /** Leave out key minted and revoked events. */
  writesOnly?: boolean;
}

export interface MintedKey {
  key: string;
  prefix: string;
  namespace: string;
  actor: string;
  scopes: string[];
  expires_at: Date | null;
}

/** "90d", "24h", "30m" or "0" to milliseconds. */
export function parseDuration(text: string): number {
  const m = /^(\d{1,6})([dhm]?)$/.exec(text.trim());
  if (!m) throw new AdminError(`not a duration: ${text} (use a number with d, h or m, such as 90d)`);
  const n = Number(m[1]);
  const ms = n * ({ d: 86_400_000, h: 3_600_000, m: 60_000, "": 0 }[m[2] as "d" | "h" | "m" | ""]);
  if (m[2] === "" && n !== 0) throw new AdminError(`give ${text} a unit: d, h or m`);
  if (ms > MAX_DURATION_MS) throw new AdminError(`${text} is longer than ten years`);
  return ms;
}

/** Problems with the admin URL, as sentences. Empty when it can be used. */
export function adminUrlProblems(url: string | undefined): string[] {
  if (!url) return ["ENGRAMPORT_ADMIN_DATABASE_URL is not set."];
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return ["ENGRAMPORT_ADMIN_DATABASE_URL is not a valid URL."];
  }
  const problems: string[] = [];
  if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
    problems.push("ENGRAMPORT_ADMIN_DATABASE_URL must be a postgres:// URL.");
  }
  if (!LOCAL_HOSTS.has(parsed.hostname) && /[?&]sslmode=/i.test(url)) {
    problems.push("Remove sslmode from ENGRAMPORT_ADMIN_DATABASE_URL: the tool always verifies TLS to a remote database.");
  }
  return problems;
}

function checkPath(path: string): string[] {
  const parts = path.split("/");
  if (parts.length > 3 || parts.some((p) => !SLUG.test(p))) {
    throw new AdminError(
      `not a namespace path: ${path} (city, city/tower or city/tower/cell; lowercase letters, digits and hyphens)`,
    );
  }
  return parts;
}

function checkSlug(slug: string, what: string): void {
  if (!SLUG.test(slug)) throw new AdminError(`not a valid ${what}: ${slug} (lowercase letters, digits and hyphens)`);
}

function checkPrefix(prefix: string): void {
  if (prefix.includes(".")) {
    throw new AdminError("pass the key's prefix (the part before the dot), never the whole key");
  }
  if (!prefix.startsWith(KEY_PREFIX) || !/^[A-Za-z0-9_]{8,32}$/.test(prefix)) {
    throw new AdminError(`not a key prefix: ${prefix}`);
  }
}

export class AdminClient {
  constructor(private readonly pool: pg.Pool, private readonly pepper?: Buffer) {}

  static fromEnv(env: NodeJS.ProcessEnv = process.env): AdminClient {
    const problems = adminUrlProblems(env.ENGRAMPORT_ADMIN_DATABASE_URL);
    if (problems.length) throw new AdminError(problems.join(" "));
    const pool = createPool(env.ENGRAMPORT_ADMIN_DATABASE_URL!, env.ENGRAMPORT_DATABASE_CA_FILE || undefined);
    return new AdminClient(pool, decodePepper(env.ENGRAMPORT_KEY_PEPPER ?? ""));
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  /** One transaction, as engramport_admin. */
  private async tx<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      try {
        await client.query(`SET LOCAL ROLE ${ADMIN_ROLE}`);
      } catch (err) {
        const code = (err as { code?: string }).code;
        if (code === "42501" || code === "22023" || code === "42704") {
          throw new AdminError(
            `this login cannot switch to ${ADMIN_ROLE}. Grant it with: GRANT ${ADMIN_ROLE} TO <login role> WITH INHERIT FALSE, SET TRUE`,
          );
        }
        throw err;
      }
      await client.query("SELECT set_config('search_path', 'pg_catalog', true)");
      const out = await fn(client);
      await client.query("COMMIT");
      return out;
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  private requirePepper(): Buffer {
    if (!this.pepper) throw new AdminError("ENGRAMPORT_KEY_PEPPER is not set or shorter than 32 bytes.");
    return this.pepper;
  }

  /**
   * Creates a namespace. A city is a client city unless `company` is set;
   * a tower or cell always takes its parent's purpose, so passing `company`
   * for one is refused rather than ignored. The database enforces the same
   * rules (0005), and allows one company city.
   */
  async createNamespace(path: string, opts: { company?: boolean } = {}): Promise<NamespaceRow> {
    const parts = checkPath(path);
    const level = LEVELS[parts.length - 1];
    const parentPath = parts.slice(0, -1).join("/");
    if (opts.company && level !== "city") {
      throw new AdminError("only a city is marked as the company's; its towers and cells are company namespaces already");
    }
    return this.tx(async (c) => {
      let parentId: string | null = null;
      let purpose: NamespacePurpose = opts.company ? "company" : "client";
      if (parentPath) {
        const parent = await c.query<{ id: string; purpose: NamespacePurpose }>(
          "SELECT id, purpose::text AS purpose FROM memory.namespaces WHERE path = $1",
          [parentPath],
        );
        if (!parent.rows[0]) throw new AdminError(`no namespace ${parentPath}; create it first`);
        parentId = parent.rows[0].id;
        purpose = parent.rows[0].purpose;
      }
      const exists = await c.query("SELECT 1 FROM memory.namespaces WHERE path = $1", [path]);
      if (exists.rowCount) throw new AdminError(`namespace ${path} already exists`);
      if (purpose === "company" && level === "city") {
        const other = await c.query<{ path: string }>(
          "SELECT path FROM memory.namespaces WHERE purpose = 'company' AND parent_id IS NULL",
        );
        if (other.rows[0]) throw new AdminError(`the company city is already ${other.rows[0].path}; there is only one`);
      }
      const r = await c.query<NamespaceRow>(
        `INSERT INTO memory.namespaces (parent_id, level, slug, purpose) VALUES ($1, $2, $3, $4)
         RETURNING path, level::text AS level, purpose::text AS purpose, created_at`,
        [parentId, level, parts[parts.length - 1], purpose],
      );
      return r.rows[0];
    });
  }

  async listNamespaces(): Promise<NamespaceRow[]> {
    return this.tx(async (c) =>
      (
        await c.query<NamespaceRow>(
          "SELECT path, level::text AS level, purpose::text AS purpose, created_at FROM memory.namespaces ORDER BY path",
        )
      ).rows,
    );
  }

  async createActor(slug: string, kind: ActorKind, displayName: string): Promise<ActorRow> {
    checkSlug(slug, "actor name");
    if (!ACTOR_KINDS.includes(kind)) throw new AdminError(`actor kind must be one of ${ACTOR_KINDS.join(", ")}`);
    const name = displayName.trim();
    if (!name || name.length > 200) throw new AdminError("give the actor a display name of 1 to 200 characters");
    return this.tx(async (c) => {
      const exists = await c.query("SELECT 1 FROM memory.actors WHERE slug = $1", [slug]);
      if (exists.rowCount) throw new AdminError(`actor ${slug} already exists`);
      const r = await c.query<ActorRow>(
        `INSERT INTO memory.actors (kind, slug, display_name) VALUES ($1, $2, $3)
         RETURNING slug, kind::text AS kind, display_name, disabled_at, created_at`,
        [kind, slug, name],
      );
      return r.rows[0];
    });
  }

  async listActors(): Promise<ActorRow[]> {
    return this.tx(async (c) =>
      (
        await c.query<ActorRow>(
          "SELECT slug, kind::text AS kind, display_name, disabled_at, created_at FROM memory.actors ORDER BY slug",
        )
      ).rows,
    );
  }

  /** Disabling an actor stops every key it holds on their next request. */
  async setActorDisabled(slug: string, disabled: boolean): Promise<ActorRow> {
    checkSlug(slug, "actor name");
    return this.tx(async (c) => {
      const r = await c.query<ActorRow>(
        `UPDATE memory.actors SET disabled_at = CASE WHEN $2 THEN coalesce(disabled_at, now()) END
         WHERE slug = $1 RETURNING slug, kind::text AS kind, display_name, disabled_at, created_at`,
        [slug, disabled],
      );
      if (!r.rows[0]) throw new AdminError(`no actor ${slug}`);
      return r.rows[0];
    });
  }

  private async insertKey(
    c: pg.PoolClient,
    namespaceId: string,
    actorId: string,
    scopes: string[],
    expiresAt: Date | null,
  ): Promise<{ key: string; prefix: string }> {
    const pepper = this.requirePepper();
    // A prefix collision is astronomically unlikely, but retry rather than fail.
    for (let attempt = 0; attempt < 3; attempt++) {
      const minted = mintKey();
      const taken = await c.query("SELECT 1 FROM memory.api_keys WHERE prefix = $1", [minted.prefix]);
      if (taken.rowCount) continue;
      await c.query(
        `INSERT INTO memory.api_keys (namespace_id, actor_id, prefix, key_hash, scopes, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [namespaceId, actorId, minted.prefix, hashKey(minted.key, pepper), scopes, expiresAt],
      );
      return minted;
    }
    throw new AdminError("could not find a free key prefix; try again");
  }

  async mintKey(opts: { namespace: string; actor: string; readOnly?: boolean; expiresInMs?: number }): Promise<MintedKey> {
    checkPath(opts.namespace);
    checkSlug(opts.actor, "actor name");
    this.requirePepper();
    if (opts.expiresInMs !== undefined && opts.expiresInMs <= 0) throw new AdminError("a new key's expiry must be in the future");
    const scopes = opts.readOnly ? ["read"] : ["read", "write"];
    const expiresAt = opts.expiresInMs === undefined ? null : new Date(Date.now() + opts.expiresInMs);
    return this.tx(async (c) => {
      const ns = await c.query<{ id: string }>("SELECT id FROM memory.namespaces WHERE path = $1", [opts.namespace]);
      if (!ns.rows[0]) throw new AdminError(`no namespace ${opts.namespace}`);
      const actor = await c.query<{ id: string; disabled_at: Date | null }>(
        "SELECT id, disabled_at FROM memory.actors WHERE slug = $1",
        [opts.actor],
      );
      if (!actor.rows[0]) throw new AdminError(`no actor ${opts.actor}`);
      if (actor.rows[0].disabled_at) throw new AdminError(`actor ${opts.actor} is disabled`);
      const minted = await this.insertKey(c, ns.rows[0].id, actor.rows[0].id, scopes, expiresAt);
      return { ...minted, namespace: opts.namespace, actor: opts.actor, scopes, expires_at: expiresAt };
    });
  }

  async listKeys(opts: { namespace?: string; includeInactive?: boolean } = {}): Promise<KeyRow[]> {
    if (opts.namespace) checkPath(opts.namespace);
    return this.tx(async (c) =>
      (
        await c.query<KeyRow>(
          `SELECT k.prefix, n.path AS namespace, a.slug AS actor, k.scopes, k.created_at, k.expires_at,
                  k.revoked_at, k.last_used_at
           FROM memory.api_keys k
           JOIN memory.namespaces n ON n.id = k.namespace_id
           JOIN memory.actors a ON a.id = k.actor_id
           WHERE ($1::text IS NULL OR n.path = $1)
             AND ($2 OR (k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now())))
           ORDER BY n.path, k.created_at`,
          [opts.namespace ?? null, opts.includeInactive ?? false],
        )
      ).rows,
    );
  }

  async revokeKey(prefix: string): Promise<KeyRow> {
    checkPrefix(prefix);
    return this.tx(async (c) => {
      // A plain read first: the admin role's update policy hides revoked rows
      // from FOR UPDATE, which would make "already revoked" look like "no key".
      const r = await c.query<{ id: string; revoked_at: Date | null }>(
        "SELECT id, revoked_at FROM memory.api_keys WHERE prefix = $1",
        [prefix],
      );
      if (!r.rows[0]) throw new AdminError(`no key ${prefix}`);
      if (r.rows[0].revoked_at) throw new AdminError(`key ${prefix} was already revoked`);
      const done = await c.query("UPDATE memory.api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", [
        r.rows[0].id,
      ]);
      if (!done.rowCount) throw new AdminError(`key ${prefix} was already revoked`);
      return this.keyByPrefix(c, prefix);
    });
  }

  /**
   * A new key for the same namespace, actor and scopes. The old key keeps
   * working for the grace period (never longer than it already had), so the
   * new one can be rolled out first. A grace of 0 revokes it now.
   */
  async rotateKey(
    prefix: string,
    graceMs: number,
    expiresInMs?: number,
  ): Promise<{ minted: MintedKey; old: KeyRow }> {
    checkPrefix(prefix);
    this.requirePepper();
    if (graceMs < 0) throw new AdminError("the grace period cannot be negative");
    if (expiresInMs !== undefined && expiresInMs <= 0) throw new AdminError("a new key's expiry must be in the future");
    return this.tx(async (c) => {
      const r = await c.query<{
        id: string;
        namespace_id: string;
        actor_id: string;
        scopes: string[];
        expires_at: Date | null;
        revoked_at: Date | null;
        created_at: Date;
        path: string;
        slug: string;
        disabled_at: Date | null;
      }>(
        `SELECT k.id, k.namespace_id, k.actor_id, k.scopes, k.expires_at, k.revoked_at, k.created_at,
                n.path, a.slug, a.disabled_at
         FROM memory.api_keys k
         JOIN memory.namespaces n ON n.id = k.namespace_id
         JOIN memory.actors a ON a.id = k.actor_id
         WHERE k.prefix = $1`,
        [prefix],
      );
      const old = r.rows[0];
      if (!old) throw new AdminError(`no key ${prefix}`);
      if (old.revoked_at) throw new AdminError(`key ${prefix} is revoked; mint a new one instead`);
      // Lock it, so two rotations of one key run one after the other.
      const locked = await c.query("SELECT 1 FROM memory.api_keys WHERE id = $1 AND revoked_at IS NULL FOR UPDATE", [old.id]);
      if (!locked.rowCount) throw new AdminError(`key ${prefix} is revoked; mint a new one instead`);
      if (old.expires_at && old.expires_at.getTime() <= Date.now()) {
        throw new AdminError(`key ${prefix} has expired; mint a new one instead`);
      }
      if (old.disabled_at) throw new AdminError(`actor ${old.slug} is disabled`);
      // Unless told otherwise, the new key gets the old key's lifetime, counted
      // from now, so rotating a key that expires soon renews it.
      const lifetime = expiresInMs ?? (old.expires_at ? old.expires_at.getTime() - old.created_at.getTime() : undefined);
      const expiresAt = lifetime === undefined ? null : new Date(Date.now() + lifetime);
      const minted = await this.insertKey(c, old.namespace_id, old.actor_id, old.scopes, expiresAt);
      if (graceMs === 0) {
        await c.query("UPDATE memory.api_keys SET revoked_at = now() WHERE id = $1", [old.id]);
      } else {
        await c.query(
          `UPDATE memory.api_keys
           SET expires_at = least(coalesce(expires_at, 'infinity'::timestamptz), now() + make_interval(secs => $2::double precision / 1000))
           WHERE id = $1`,
          [old.id, graceMs],
        );
      }
      return {
        minted: { ...minted, namespace: old.path, actor: old.slug, scopes: old.scopes, expires_at: expiresAt },
        old: await this.keyByPrefix(c, prefix),
      };
    });
  }

  /**
   * The audit trail, newest first: every write's provenance metadata and every
   * key minted or revoked. Never memory text, its hash, agent-claimed fields
   * or source references; the admin role cannot read those (0006).
   */
  async audit(filter: AuditFilter = {}): Promise<AuditRow[]> {
    if (filter.namespace) checkPath(filter.namespace);
    if (filter.actor) checkSlug(filter.actor, "actor name");
    const limit = filter.limit ?? 100;
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw new AdminError("the limit must be 1 to 1000");
    if (filter.sinceMs !== undefined && filter.sinceMs <= 0) throw new AdminError("--since must be longer than 0");
    const since = filter.sinceMs === undefined ? null : new Date(Date.now() - filter.sinceMs);
    return this.tx(async (c) => {
      if (filter.namespace) {
        const ns = await c.query("SELECT 1 FROM memory.namespaces WHERE path = $1", [filter.namespace]);
        if (!ns.rowCount) throw new AdminError(`no namespace ${filter.namespace}`);
      }
      if (filter.actor) {
        const a = await c.query("SELECT 1 FROM memory.actors WHERE slug = $1", [filter.actor]);
        if (!a.rowCount) throw new AdminError(`no actor ${filter.actor}`);
      }
      const r = await c.query<AuditRow>(
        `WITH scope AS (
           SELECT id, path FROM memory.namespaces
           WHERE $1::text IS NULL OR path = $1 OR starts_with(path, $1 || '/')
         ),
         events AS (
           SELECT p.created_at AS at, 'write' AS event, s.path AS namespace, a.slug AS actor,
                  k.prefix AS key_prefix, p.tool, p.transport::text AS transport,
                  nullif(concat_ws(' ', p.client_name, p.client_version), '') AS client,
                  p.session_id, p.request_id
           FROM memory.provenance p
           JOIN scope s ON s.id = p.namespace_id
           JOIN memory.actors a ON a.id = p.actor_id
           JOIN memory.api_keys k ON k.id = p.api_key_id
           WHERE ($2::text IS NULL OR a.slug = $2) AND ($3::timestamptz IS NULL OR p.created_at >= $3)
           UNION ALL
           SELECT x.at, x.event, s.path, a.slug, k.prefix, NULL, NULL, NULL, NULL, NULL
           FROM memory.api_keys k
           JOIN scope s ON s.id = k.namespace_id
           JOIN memory.actors a ON a.id = k.actor_id
           CROSS JOIN LATERAL (VALUES (k.created_at, 'key minted'), (k.revoked_at, 'key revoked')) AS x(at, event)
           WHERE NOT $5 AND x.at IS NOT NULL
             AND ($2::text IS NULL OR a.slug = $2) AND ($3::timestamptz IS NULL OR x.at >= $3)
         )
         SELECT * FROM events ORDER BY at DESC, event LIMIT $4`,
        [filter.namespace ?? null, filter.actor ?? null, since, limit, filter.writesOnly ?? false],
      );
      return r.rows;
    });
  }

  private async keyByPrefix(c: pg.PoolClient, prefix: string): Promise<KeyRow> {
    const r = await c.query<KeyRow>(
      `SELECT k.prefix, n.path AS namespace, a.slug AS actor, k.scopes, k.created_at, k.expires_at,
              k.revoked_at, k.last_used_at
       FROM memory.api_keys k
       JOIN memory.namespaces n ON n.id = k.namespace_id
       JOIN memory.actors a ON a.id = k.actor_id
       WHERE k.prefix = $1`,
      [prefix],
    );
    return r.rows[0];
  }
}

// ─── command line ───────────────────────────────────────────────────────────

export const ADMIN_USAGE = `Usage: engramport admin <command>

  namespace create <path> [--company]
                                     path is city, city/tower or city/tower/cell;
                                     --company makes a new city your company's own:
                                     its towers and cells never share a city with
                                     a client, so neither can read the other
  namespace list
  actor create <name> --kind agent|human|service --display "<display name>"
  actor list
  actor disable <name>               stops every key the actor holds
  actor enable <name>
  key mint --namespace <path> --actor <name> [--read-only] [--expires-in 90d]
  key list [--namespace <path>] [--all]
  key rotate <prefix> [--grace 24h] [--expires-in 90d]
                                     --grace 0 revokes the old key at once; the new
                                     key gets the old one's lifetime unless told
  key revoke <prefix>
  audit [--namespace <path>] [--actor <name>] [--since 7d] [--limit 100] [--writes-only]
                                     newest first: who wrote, through which client,
                                     tool and transport, where and when, and every
                                     key minted or revoked. Never memory content.

A minted key is printed once, alone on stdout. Pipe it into your secrets
manager; it cannot be shown again. City and tower names must not name a client.
There is one company city; set it up once with namespace create <city> --company.

Settings: ENGRAMPORT_ADMIN_DATABASE_URL, ENGRAMPORT_KEY_PEPPER (mint and rotate),
ENGRAMPORT_DATABASE_CA_FILE (optional).`;

export interface AdminIO {
  out: (line: string) => void;
  err: (line: string) => void;
}

function parseFlags(args: string[], allowed: Record<string, "value" | "bool">): {
  positional: string[];
  flags: Record<string, string | true>;
} {
  const positional: string[] = [];
  const flags: Record<string, string | true> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith("--")) {
      positional.push(a);
      continue;
    }
    const [name, inline] = a.slice(2).split(/=(.*)/s, 2);
    const kind = allowed[name];
    if (!kind) throw new UsageError(`unknown option --${name}`);
    if (kind === "bool") {
      if (inline !== undefined) throw new UsageError(`--${name} takes no value`);
      flags[name] = true;
    } else {
      const value = inline ?? args[++i];
      if (value === undefined || value.startsWith("--")) throw new UsageError(`--${name} needs a value`);
      flags[name] = value;
    }
  }
  return { positional, flags };
}

class UsageError extends Error {}

const when = (d: Date | null): string => (d ? d.toISOString().replace(/\.\d{3}Z$/, "Z") : "-");

function keyState(k: KeyRow): string {
  if (k.revoked_at) return `revoked ${when(k.revoked_at)}`;
  if (k.expires_at && k.expires_at.getTime() <= Date.now()) return `expired ${when(k.expires_at)}`;
  return k.expires_at ? `active until ${when(k.expires_at)}` : "active";
}

function one(positional: string[], what: string): string {
  if (positional.length !== 1) throw new UsageError(`give exactly one ${what}`);
  return positional[0];
}

/** Runs one admin command. Returns the exit code: 0 done, 1 refused, 2 bad usage. */
export async function runAdmin(argv: string[], open: () => AdminClient, io: AdminIO): Promise<number> {
  const [group, action, ...rest] = argv;
  if (!group || group === "help" || group === "--help" || group === "-h") {
    (group ? io.out : io.err)(ADMIN_USAGE);
    return group ? 0 : 2;
  }
  let client: AdminClient | undefined;
  const db = () => (client ??= open());
  try {
    // audit takes no sub-command, so everything after it is its options.
    const cmd = group === "audit" ? "audit" : `${group} ${action ?? ""}`.trim();
    if (cmd === "audit" && action !== undefined) rest.unshift(action);
    switch (cmd) {
      case "namespace create": {
        const { positional, flags } = parseFlags(rest, { company: "bool" });
        const path = one(positional, "namespace path");
        const company = flags.company === true;
        if (company && checkPath(path).length !== 1) {
          throw new UsageError("--company goes on a city; its towers and cells are company namespaces already");
        }
        checkPath(path);
        const ns = await db().createNamespace(path, { company });
        io.out(`created ${ns.purpose} ${ns.level} ${ns.path}`);
        if (ns.purpose === "client" && ns.level !== "cell") io.err("Reminder: city and tower names must not name a client.");
        return 0;
      }
      case "namespace list": {
        parseFlags(rest, {});
        for (const ns of await db().listNamespaces()) io.out(`${ns.level.padEnd(5)}  ${ns.purpose.padEnd(7)}  ${ns.path}`);
        return 0;
      }
      case "actor create": {
        const { positional, flags } = parseFlags(rest, { kind: "value", display: "value" });
        const slug = one(positional, "actor name");
        if (typeof flags.kind !== "string") throw new UsageError("--kind is required");
        const display = typeof flags.display === "string" ? flags.display : slug;
        const actor = await db().createActor(slug, flags.kind as ActorKind, display);
        io.out(`created ${actor.kind} ${actor.slug} (${actor.display_name})`);
        return 0;
      }
      case "actor list": {
        parseFlags(rest, {});
        for (const a of await db().listActors()) {
          io.out(`${a.slug.padEnd(24)} ${a.kind.padEnd(7)} ${a.disabled_at ? `disabled ${when(a.disabled_at)}` : "enabled"}  ${a.display_name}`);
        }
        return 0;
      }
      case "actor disable":
      case "actor enable": {
        const { positional } = parseFlags(rest, {});
        const slug = one(positional, "actor name");
        const a = await db().setActorDisabled(slug, action === "disable");
        io.out(`${a.slug} is ${a.disabled_at ? "disabled; its keys stop working on their next request" : "enabled"}`);
        return 0;
      }
      case "key mint": {
        const { positional, flags } = parseFlags(rest, { namespace: "value", actor: "value", "read-only": "bool", "expires-in": "value" });
        if (positional.length) throw new UsageError(`unexpected argument ${positional[0]}`);
        if (typeof flags.namespace !== "string" || typeof flags.actor !== "string") {
          throw new UsageError("--namespace and --actor are required");
        }
        const request = {
          namespace: flags.namespace,
          actor: flags.actor,
          readOnly: flags["read-only"] === true,
          expiresInMs: typeof flags["expires-in"] === "string" ? parseDuration(flags["expires-in"]) : undefined,
        };
        const minted = await db().mintKey(request);
        io.err(
          `Minted ${minted.prefix} for ${minted.actor} in ${minted.namespace} (${minted.scopes.join(", ")}, ` +
            `${minted.expires_at ? `expires ${when(minted.expires_at)}` : "no expiry"}). ` +
            "It is shown once, below. Put it in your secrets manager now.",
        );
        io.out(minted.key);
        return 0;
      }
      case "audit": {
        const { positional, flags } = parseFlags(rest, {
          namespace: "value",
          actor: "value",
          since: "value",
          limit: "value",
          "writes-only": "bool",
        });
        if (positional.length) throw new UsageError(`unexpected argument ${positional[0]}`);
        let limit: number | undefined;
        if (typeof flags.limit === "string") {
          if (!/^\d{1,4}$/.test(flags.limit)) throw new UsageError("--limit takes a whole number from 1 to 1000");
          limit = Number(flags.limit);
        }
        const rows = await db().audit({
          namespace: typeof flags.namespace === "string" ? flags.namespace : undefined,
          actor: typeof flags.actor === "string" ? flags.actor : undefined,
          sinceMs: typeof flags.since === "string" ? parseDuration(flags.since) : undefined,
          limit,
          writesOnly: flags["writes-only"] === true,
        });
        for (const r of rows) {
          const via = r.event === "write" ? `${r.tool} via ${r.transport}${r.client ? ` (${r.client})` : ""}` : "";
          io.out(`${when(r.at)}  ${r.event.padEnd(11)}  ${r.namespace}  ${r.actor}  ${r.key_prefix}${via ? `  ${via}` : ""}`);
        }
        if (!rows.length) io.err("Nothing in the audit trail for that filter.");
        return 0;
      }
      case "key list": {
        const { positional, flags } = parseFlags(rest, { namespace: "value", all: "bool" });
        if (positional.length) throw new UsageError(`unexpected argument ${positional[0]}`);
        const filter = {
          namespace: typeof flags.namespace === "string" ? flags.namespace : undefined,
          includeInactive: flags.all === true,
        };
        const keys = await db().listKeys(filter);
        for (const k of keys) {
          io.out(
            `${k.prefix}  ${k.namespace}  ${k.actor}  ${k.scopes.join(",")}  ${keyState(k)}  last used ${when(k.last_used_at)}`,
          );
        }
        if (!keys.length) io.err(flags.all ? "No keys." : "No active keys. Add --all to include revoked and expired ones.");
        return 0;
      }
      case "key rotate": {
        const { positional, flags } = parseFlags(rest, { grace: "value", "expires-in": "value" });
        const graceMs = typeof flags.grace === "string" ? parseDuration(flags.grace) : 24 * 3_600_000;
        const expiresInMs = typeof flags["expires-in"] === "string" ? parseDuration(flags["expires-in"]) : undefined;
        const prefix = one(positional, "key prefix");
        checkPrefix(prefix);
        const { minted, old } = await db().rotateKey(prefix, graceMs, expiresInMs);
        io.err(
          `Minted ${minted.prefix} to replace ${old.prefix}, which is now ${keyState(old)}. ` +
            "The new key is shown once, below. Put it in your secrets manager now.",
        );
        io.out(minted.key);
        return 0;
      }
      case "key revoke": {
        const { positional } = parseFlags(rest, {});
        const prefix = one(positional, "key prefix");
        checkPrefix(prefix);
        const k = await db().revokeKey(prefix);
        io.out(`${k.prefix} (${k.actor} in ${k.namespace}) is revoked; it stops working on its next request`);
        return 0;
      }
      default:
        throw new UsageError(`unknown command: ${cmd}`);
    }
  } catch (err) {
    if (err instanceof UsageError) {
      io.err(`${err.message}\n\n${ADMIN_USAGE}`);
      return 2;
    }
    if (err instanceof AdminError) {
      io.err(err.message);
      return 1;
    }
    // Database errors can carry row values; show the class, not the detail.
    const code = (err as { code?: string })?.code;
    if (code === "23514" || code === "23505" || code === "P0001") {
      io.err(`refused by the database (${code})`);
      return 1;
    }
    io.err(`admin command failed${code ? ` (${code})` : ""}: ${code ? "database error" : String((err as Error)?.message ?? err)}`);
    return 1;
  } finally {
    await client?.close();
  }
}
