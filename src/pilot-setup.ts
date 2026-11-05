/**
 * Pilot setup: everything one pilot cell needs, from a reviewed config file
 * (founder decisions D-05 and D-06; docs/install.md).
 *
 *   engramport admin pilot setup --config <file> --namespace <city/tower/cell>
 *       A dry run. Reads the database in a READ ONLY transaction, prints
 *       what it would do and anything that stops it, and changes nothing.
 *
 *   ... --apply --confirm <city/tower/cell> --keys-out <new file>
 *       Does it, in one transaction: all of it or none of it.
 *
 * It fails closed:
 *   - the namespace is named twice (in the file and on the command line) and
 *     must be confirmed a third time to apply;
 *   - the cell must not exist yet, its city and tower must be client (not
 *     company) namespaces if they exist, and every actor name must be free,
 *     so it never adds to or takes over something already there;
 *   - the database must have every migration up to 0027;
 *   - the plan is checked again inside the transaction that applies it;
 *   - keys go only to a new file, created owner-read-only, outside any git
 *     working tree, and never to the screen or a log;
 *   - the owner's approval authority is only offered: it counts once they
 *     accept it with their own Google sign-in.
 */

import { closeSync, existsSync, fsyncSync, openSync, realpathSync, unlinkSync, writeSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { AdminClient, AdminError, parseDuration, type MintedKey, type PilotTarget } from "./admin.js";

const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const EMAIL = /^[^@\s\p{Cc}]+@[^@\s\p{Cc}]+\.[^@\s\p{Cc}]+$/u;
// A client cell's owner approves cell knowledge (approval_scope_for, 0016).
const SCOPES = ["cell_knowledge"];
const MAX_KEY_DAYS = 366;
const MAX_AGENTS = 8;

export interface PilotAgent {
  actor: string;
  display: string;
  read_only: boolean;
  /** Such as 90d. Keys always expire, within a year. */
  expires_in: string;
}

export interface PilotConfig {
  /** city/tower/cell */
  namespace: string;
  embedding_model: string;
  owner: {
    actor: string;
    display: string;
    email: string;
    authority: { scope: string; can_delegate: boolean; expires_in: string };
  };
  agents: PilotAgent[];
}

const fail = (msg: string): never => {
  throw new AdminError(msg);
};

function only(obj: unknown, keys: string[], where: string): Record<string, unknown> {
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) fail(`${where} must be an object`);
  const o = obj as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!keys.includes(k)) fail(`${where} has an unknown field: ${k}`);
  for (const k of keys) if (!(k in o)) fail(`${where} needs ${k}`);
  return o;
}
const str = (v: unknown, where: string): string => (typeof v === "string" ? v : fail(`${where} must be text`));
const bool = (v: unknown, where: string): boolean => (typeof v === "boolean" ? v : fail(`${where} must be true or false`));
const slug = (v: unknown, where: string): string => {
  const s = str(v, where);
  return SLUG.test(s) ? s : fail(`${where} is not a valid name: lowercase letters, digits and hyphens`);
};
const display = (v: unknown, where: string): string => {
  const s = str(v, where).trim();
  return s.length >= 1 && s.length <= 80 && !/\p{C}/u.test(s) ? s : fail(`${where} is 1 to 80 printable characters`);
};
const days = (v: unknown, where: string, maxDays: number): string => {
  const s = str(v, where);
  const ms = parseDuration(s);
  if (ms <= 0 || ms > maxDays * 86_400_000) fail(`${where} must be more than 0 and at most ${maxDays} days`);
  return s;
};

/** Reads and checks a pilot config. Anything unexpected is refused, not ignored. */
export function parsePilotConfig(text: string): PilotConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    fail("the config is not valid JSON");
  }
  const o = only(raw, ["namespace", "embedding_model", "owner", "agents"], "the config");
  const namespace = str(o.namespace, "namespace");
  const parts = namespace.split("/");
  if (parts.length !== 3 || parts.some((p) => !SLUG.test(p))) fail("namespace must be city/tower/cell, each lowercase letters, digits and hyphens");
  const embedding_model = str(o.embedding_model, "embedding_model");

  const ow = only(o.owner, ["actor", "display", "email", "authority"], "owner");
  const email = str(ow.email, "owner.email").trim().toLowerCase();
  if (email.length > 254 || !EMAIL.test(email)) fail("owner.email is not an email address");
  const au = only(ow.authority, ["scope", "can_delegate", "expires_in"], "owner.authority");
  const scope = str(au.scope, "owner.authority.scope");
  if (!SCOPES.includes(scope)) fail(`owner.authority.scope is one of ${SCOPES.join(", ")}`);
  const owner = {
    actor: slug(ow.actor, "owner.actor"),
    display: display(ow.display, "owner.display"),
    email,
    authority: { scope, can_delegate: bool(au.can_delegate, "owner.authority.can_delegate"), expires_in: days(au.expires_in, "owner.authority.expires_in", 3650) },
  };

  if (!Array.isArray(o.agents) || o.agents.length < 1 || o.agents.length > MAX_AGENTS) fail(`agents lists 1 to ${MAX_AGENTS} agents`);
  const agents = (o.agents as unknown[]).map((a, i) => {
    const ag = only(a, ["actor", "display", "read_only", "expires_in"], `agents[${i}]`);
    return {
      actor: slug(ag.actor, `agents[${i}].actor`),
      display: display(ag.display, `agents[${i}].display`),
      read_only: bool(ag.read_only, `agents[${i}].read_only`),
      expires_in: days(ag.expires_in, `agents[${i}].expires_in`, MAX_KEY_DAYS),
    };
  });
  const names = [owner.actor, ...agents.map((a) => a.actor)];
  if (new Set(names).size !== names.length) fail("every actor name in the config must be different");
  return { namespace, embedding_model, owner, agents };
}

/** o***@example.com: enough to recognise, not a full address on screen or in a log. */
export const maskEmail = (email: string): string => email.replace(/^(.)[^@]*/, "$1***");

export interface PilotPlan {
  steps: string[];
  problems: string[];
}

/** What applying `cfg` would do, and why it can't, from what the database holds. */
export function planFrom(cfg: PilotConfig, target: PilotTarget, canMintKeys: boolean): PilotPlan {
  const problems: string[] = [];
  const steps: string[] = [];
  if (!target.schemaReady) problems.push("The database is missing migrations: apply every migration up to 0027 first.");
  if (target.schemaReady && !target.models.includes(cfg.embedding_model)) {
    problems.push(`The database knows no embedding model ${cfg.embedding_model}.`);
  }
  if (!canMintKeys) problems.push("ENGRAMPORT_KEY_PEPPER is not set or shorter than 32 bytes, so no key can be minted.");
  const levels = ["city", "tower", "cell"];
  target.pieces.forEach((p, i) => {
    if (!p.exists) {
      steps.push(`create ${levels[i]} ${p.path}${i === 2 ? `, embeddings ${cfg.embedding_model}` : ""}`);
      return;
    }
    if (i === 2) problems.push(`The cell ${p.path} already exists. This tool only sets up a new cell; nothing is added to an existing one.`);
    else if (p.level !== levels[i]) problems.push(`${p.path} exists as a ${p.level}, not a ${levels[i]}.`);
    else if (p.purpose !== "client") problems.push(`${p.path} is a ${p.purpose} namespace; a pilot cell goes under a client city.`);
    else steps.push(`use existing ${levels[i]} ${p.path}`);
  });
  for (const a of target.takenActors) problems.push(`The actor name ${a} is already taken; choose a new one in the config.`);
  const o = cfg.owner;
  steps.push(`create person ${o.actor} (${o.display}), who signs in as ${maskEmail(o.email)}, read and write in the cell`);
  steps.push(
    `offer ${o.actor} approval authority over the cell (${o.authority.scope}${o.authority.can_delegate ? ", may delegate" : ""}, ` +
      `for ${o.authority.expires_in}); it counts only once they accept it with their own Google sign-in`,
  );
  for (const a of cfg.agents) {
    steps.push(`create agent ${a.actor} (${a.display}) and mint one ${a.read_only ? "read-only" : "read-write"} key for the cell, expiring in ${a.expires_in}`);
  }
  return { steps, problems };
}

/** Plan with a read-only transaction: the database refuses any write. */
export async function planPilot(admin: AdminClient, cfg: PilotConfig): Promise<PilotPlan> {
  const actors = [cfg.owner.actor, ...cfg.agents.map((a) => a.actor)];
  const target = await admin.transaction((a) => a.pilotTarget(cfg.namespace, actors), { readOnly: true });
  return planFrom(cfg, target, admin.canMintKeys);
}

/** Whether `path` sits inside a git working tree. */
function insideGitTree(path: string): boolean {
  let dir = dirname(path);
  for (;;) {
    if (existsSync(resolve(dir, ".git"))) return true;
    const up = dirname(dir);
    if (up === dir) return false;
    dir = up;
  }
}

/** Opens the keys file: new, owner-read-only, outside any repository. Before anything else happens. */
export function openKeysFile(path: string): { fd: number; path: string } {
  const full = resolve(path);
  if (!existsSync(dirname(full))) fail(`the folder for --keys-out does not exist: ${dirname(full)}`);
  const real = resolve(realpathSync(dirname(full)), full.slice(dirname(full).length + 1));
  if (insideGitTree(real)) fail("--keys-out is inside a git working tree; write keys outside any repository");
  try {
    return { fd: openSync(real, "wx", 0o600), path: real };
  } catch (err) {
    if ((err as { code?: string }).code === "EEXIST") fail(`--keys-out already exists: ${real}; keys never overwrite a file`);
    throw err;
  }
}

export interface PilotResult {
  steps: string[];
  keys: Pick<MintedKey, "prefix" | "actor" | "namespace" | "expires_at">[];
  keysFile: string;
}

/**
 * Applies `cfg` in one transaction, after checking the plan again inside it.
 * Keys are written to the already-open file only after the commit.
 */
export async function applyPilot(admin: AdminClient, cfg: PilotConfig, keysOut: string): Promise<PilotResult> {
  const file = openKeysFile(keysOut);
  let committed = false;
  try {
    const actors = [cfg.owner.actor, ...cfg.agents.map((a) => a.actor)];
    const { steps, minted } = await admin.transaction(async (tx) => {
      const target = await tx.pilotTarget(cfg.namespace, actors);
      const plan = planFrom(cfg, target, tx.canMintKeys);
      if (plan.problems.length) throw new AdminError(`Refused, nothing changed:\n- ${plan.problems.join("\n- ")}`);
      const parts = cfg.namespace.split("/");
      for (let i = 1; i <= 3; i++) {
        if (!target.pieces[i - 1].exists) {
          await tx.createNamespace(parts.slice(0, i).join("/"), i === 3 ? { embeddingModel: cfg.embedding_model } : {});
        }
      }
      const o = cfg.owner;
      await tx.createActor(o.actor, "human", o.display);
      await tx.addMember({ email: o.email, namespace: cfg.namespace, actor: o.actor });
      await tx.grantAuthority({
        actor: o.actor,
        namespace: cfg.namespace,
        scope: o.authority.scope,
        canDelegate: o.authority.can_delegate,
        expiresInMs: parseDuration(o.authority.expires_in),
      });
      const keys: MintedKey[] = [];
      for (const a of cfg.agents) {
        await tx.createActor(a.actor, "agent", a.display);
        keys.push(await tx.mintKey({ namespace: cfg.namespace, actor: a.actor, readOnly: a.read_only, expiresInMs: parseDuration(a.expires_in) }));
      }
      return { steps: plan.steps, minted: keys };
    });
    committed = true;
    const lines = minted.map((k) => JSON.stringify({
      actor: k.actor, namespace: k.namespace, prefix: k.prefix, key: k.key, expires_at: k.expires_at?.toISOString() ?? null,
    }));
    writeSync(file.fd, `${lines.join("\n")}\n`);
    fsyncSync(file.fd);
    return {
      steps,
      keys: minted.map(({ prefix, actor, namespace, expires_at }) => ({ prefix, actor, namespace, expires_at })),
      keysFile: file.path,
    };
  } catch (err) {
    if (committed) {
      throw new AdminError(
        `The setup was applied, but the keys could not be written to ${file.path}: ${(err as Error).message}. ` +
          "Revoke the new keys (engramport admin key list --namespace " + cfg.namespace + ", then key revoke) and mint new ones.",
      );
    }
    try {
      closeSync(file.fd);
    } catch { /* already closed */ }
    unlinkSync(file.path);
    throw err;
  } finally {
    try {
      closeSync(file.fd);
    } catch { /* already closed */ }
  }
}
