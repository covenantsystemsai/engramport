/**
 * The approval page: where a person approves or rejects one memory, with their
 * own Google sign-in, in their own browser (founder decision D-03B).
 *
 * It is a page and not an MCP tool on purpose: an agent that holds a person's
 * connection can ask for approval but cannot approve. Every rule lives in the
 * database (migration 0018); this file is the HTTP around three calls, all
 * with the one fresh sign-in this visit started:
 *
 *   GET  /approve/:memoryId   starts a fresh Google sign-in for this memory
 *   GET  /approve/callback    back from Supabase Auth: shows the memory
 *                             (memory.approval_review)
 *   POST /approve/review      the person picked approve or reject: takes a
 *                             challenge for that action on that exact version
 *                             (memory.issue_approval_challenge) and asks them
 *                             to confirm
 *   POST /approve/confirm     confirms: spends the challenge and the sign-in
 *                             together (memory.decide_approval_challenge)
 *
 * The browser carries the visit in an encrypted, signed, ten-minute cookie,
 * so any instance can serve any step. The challenge's secret is only ever in
 * that cookie, never in the page. Each form also carries a token tied to the
 * cookie, and the cookie is SameSite, so another site cannot submit for them.
 *
 * Served only with ENGRAMPORT_APPROVAL_PAGE=true, which needs OAuth set up.
 */

import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import express, { Request, Response, Router } from "express";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";

import type { IdentityProvider, OAuthDb } from "./oauth.js";

export interface ApprovalPageOptions {
  /** The server's public origin, e.g. https://mcp.example.com. */
  publicUrl: string;
  pepper: Buffer;
  db: OAuthDb;
  identity: IdentityProvider;
  /** Browser requests allowed per minute per address on one instance. Default 30. */
  perMinute?: number;
}

const COOKIE = "__Host-ep_approve";
const TTL_MS = 10 * 60 * 1000;
const MAX_SEALED = 3500;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX64 = /^[0-9a-f]{64}$/;

interface Base {
  exp: number;
  memoryId: string;
}
interface LoginStep extends Base {
  step: "login";
  idpVerifier: string;
}
interface Signed extends Base {
  userId: string;
  sessionId: string;
  /** Absent when it would not fit in the cookie. Only used to end the Supabase session. */
  idpToken?: string;
  csrf: string;
}
interface ReviewStep extends Signed {
  step: "review";
  sha: string;
  version: number;
}
interface ConfirmStep extends Signed {
  step: "confirm";
  action: "approve" | "reject";
  challengeId: string;
  secret: string;
}
type Visit = LoginStep | ReviewStep | ConfirmStep;

interface Review {
  memory_id: string;
  namespace_path: string;
  kind: string;
  claim_type: string;
  content: string;
  content_sha256: string;
  memory_version: number;
  status: string;
  approval_state: string;
  requested_at: Date | null;
  scope: string;
  created_at: Date;
  /** For a proposed revision (D-04): the approved version it would replace. */
  replaces_memory_id: string | null;
  replaces_content: string | null;
  replaces_content_sha256: string | null;
  replaces_current: boolean | null;
}

export const b64url = (buf: Buffer) => buf.toString("base64url");
export const s256 = (verifier: string) => b64url(createHash("sha256").update(verifier, "ascii").digest());
export const one = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

const VISIT_INFO = "engramport approval visit v1";

/** Each page seals its visits under a key of its own, so one page's cookie means nothing to another. */
function visitKey(pepper: Buffer, info: string): Buffer {
  return Buffer.from(hkdfSync("sha256", pepper, Buffer.alloc(0), info, 32));
}

/** AES-256-GCM under a key of its own, derived from the pepper. */
export function sealVisit<V = Visit>(pepper: Buffer, value: V, info = VISIT_INFO): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", visitKey(pepper, info), iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return b64url(Buffer.concat([iv, cipher.getAuthTag(), body]));
}

export function openVisit<V extends { exp: number } = Visit>(pepper: Buffer, sealed: string | undefined, now = Date.now(),
                                                         info = VISIT_INFO): V | undefined {
  if (!sealed || sealed.length > 8192) return undefined;
  try {
    const raw = Buffer.from(sealed, "base64url");
    if (raw.length < 29) return undefined;
    const decipher = createDecipheriv("aes-256-gcm", visitKey(pepper, info), raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(12, 28));
    const value = JSON.parse(Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8")) as V;
    if (typeof value.exp !== "number" || value.exp <= now) return undefined;
    return value;
  } catch {
    return undefined;
  }
}

export function readCookie(req: Request, name = COOKIE): string | undefined {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

const setCookie = (res: Response, value: string) =>
  res.append("Set-Cookie", `${COOKIE}=${value}; Path=/; Max-Age=${TTL_MS / 1000}; HttpOnly; Secure; SameSite=Lax`);
const clearCookie = (res: Response) =>
  res.append("Set-Cookie", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);

export const escape = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export function page(res: Response, status: number, title: string, body: string): void {
  // No scripts, no framing, nothing from elsewhere; forms post only here.
  res
    .status(status)
    .set({
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    })
    .send(
      `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
        `<meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)}</title>` +
        `<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a}` +
        `pre{white-space:pre-wrap;word-break:break-word;font:inherit;padding:.8rem 1rem;border:1px solid #ccc;border-radius:8px;background:#fafafa}` +
        `dl{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem}dt{color:#555}dd{margin:0;word-break:break-all}` +
        `button{font:inherit;padding:.5rem 1.2rem;margin:.5rem .5rem 0 0;border-radius:8px;border:1px solid #888;background:#fff}` +
        `button.go{background:#1a1a1a;color:#fff}small{color:#555}</style></head>` +
        `<body><h1>${escape(title)}</h1>${body}</body></html>`,
    );
}

const expired = (res: Response) =>
  page(res, 400, "This visit has expired",
    "<p>This approval has expired or was opened in another browser. Open the approval link again.</p>");

function details(r: Review): string {
  const when = (d: Date | null) => (d ? escape(new Date(d).toISOString().replace(".000Z", "Z")) : "not asked");
  return `<dl><dt>Namespace</dt><dd>${escape(r.namespace_path)}</dd>` +
    `<dt>Kind</dt><dd>${escape(r.kind)}, ${escape(r.claim_type.replace(/_/g, " "))}</dd>` +
    `<dt>Version</dt><dd>${r.memory_version}</dd>` +
    `<dt>Written</dt><dd>${when(r.created_at)}</dd>` +
    `<dt>Approval asked</dt><dd>${when(r.requested_at)}</dd>` +
    `<dt>Fingerprint</dt><dd><small>${escape(r.content_sha256)}</small></dd></dl>` +
    (r.replaces_memory_id
      ? (r.replaces_current
          ? `<p><strong>Proposed revision.</strong> Approving it replaces the approved version below, which stays ` +
            `current until then.</p>`
          : `<p><strong>Proposed revision.</strong> The approved version it was written against has since been ` +
            `replaced.</p>`) +
        `<h2>Proposed text</h2><pre>${escape(r.content)}</pre>` +
        `<h2>Approved text it would replace</h2>` +
        `<p><small>Fingerprint ${escape(r.replaces_content_sha256 ?? "")}</small></p>` +
        `<pre>${escape(r.replaces_content ?? "")}</pre>`
      : `<pre>${escape(r.content)}</pre>`);
}

/** Why this memory can't be decided now, or undefined if it can. */
function notDecidable(r: Review): string | undefined {
  if (r.status !== "active" && r.status !== "proposed") {
    return "This version is no longer active, so it can't be decided. Review the current one.";
  }
  if (r.approval_state === "approved" || r.approval_state === "rejected") return `This memory was already ${r.approval_state}.`;
  if (r.status === "proposed" && !r.replaces_current) {
    return "The approved version this revision would replace has changed, so it can't be decided. Review the current one.";
  }
  return undefined;
}

/** The database's own answer, which is written for the person, or a generic one. */
export function refusal(err: unknown): string | undefined {
  const e = err as { code?: string; message?: string };
  if (e && typeof e.message === "string" && (e.code === "42501" || e.code === "55000" || e.code === "22023")) {
    return e.message.charAt(0).toUpperCase() + e.message.slice(1) + ".";
  }
  return undefined;
}

type Handler = (req: Request, res: Response) => Promise<unknown>;
export const safe = (fn: Handler, what = "approval page") => (req: Request, res: Response) => {
  fn(req, res).catch((err) => {
    console.error(`[engramport] ${what} error:`, (err as Error).message);
    if (!res.headersSent) page(res, 503, "Try again shortly", "<p>Something went wrong on our side. Nothing was decided.</p>");
  });
};

export function createApprovalRouter(opts: ApprovalPageOptions): Router {
  const { db, pepper, identity } = opts;
  const issuer = opts.publicUrl;
  const router = express.Router();
  const form = express.urlencoded({ extended: false, limit: "4kb" });
  const limit = rateLimit({
    windowMs: 60_000,
    limit: opts.perMinute ?? 30,
    keyGenerator: (req) => ipKeyGenerator(req.ip ?? "unknown"),
    standardHeaders: "draft-7",
    legacyHeaders: false,
    handler: (_req, res) => page(res, 429, "Slow down", "<p>Too many tries from here. Wait a minute and open the link again.</p>"),
  });

  const store = (res: Response, value: Visit): boolean => {
    let sealed = sealVisit(pepper, value);
    if (sealed.length > MAX_SEALED && "idpToken" in value) sealed = sealVisit(pepper, { ...value, idpToken: undefined });
    if (sealed.length > MAX_SEALED) return false;
    setCookie(res, sealed);
    return true;
  };
  const csrfOk = (visit: Signed, sent: unknown) => {
    const csrf = one(sent) ?? "";
    return csrf.length === visit.csrf.length && timingSafeEqual(Buffer.from(csrf), Buffer.from(visit.csrf));
  };
  // The Supabase session is only for this one decision.
  const end = (res: Response, visit: { idpToken?: string }) => {
    clearCookie(res);
    return visit.idpToken ? identity.signOut(visit.idpToken).catch(() => undefined) : Promise.resolve();
  };
  const csrfField = (csrf: string) => `<input type="hidden" name="csrf" value="${csrf}">`;

  router.get("/approve/callback", limit, safe(async (req, res) => {
    const visit = openVisit(pepper, readCookie(req));
    if (!visit || visit.step !== "login") return expired(res);
    const code = one(req.query.code);
    if (!code || req.query.error !== undefined) {
      clearCookie(res);
      return page(res, 400, "Sign-in cancelled", "<p>Google sign-in was cancelled. Nothing was decided.</p>");
    }
    let who;
    try {
      who = await identity.exchange(code, visit.idpVerifier);
    } catch (err) {
      console.error("[engramport] approval sign-in exchange failed:", (err as Error).message);
      clearCookie(res);
      return page(res, 400, "Sign-in failed", "<p>Google sign-in did not complete. Open the approval link again.</p>");
    }
    const signed = { memoryId: visit.memoryId, userId: who.userId, sessionId: who.sessionId, idpToken: who.accessToken };
    let r: Review | undefined;
    try {
      r = (await db.query<Review>("SELECT * FROM memory.approval_review($1, $2, $3)",
        [who.userId, who.sessionId, visit.memoryId])).rows[0];
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, signed);
      return page(res, 403, "Nothing to decide here", `<p>${escape(why)}</p>`);
    }
    if (!r) throw new Error("the review returned nothing");
    const why = notDecidable(r);
    if (why) {
      await end(res, signed);
      return page(res, 200, "Nothing to decide here", `<p>${escape(why)}</p>${details(r)}`);
    }
    const csrf = b64url(randomBytes(24));
    if (!store(res, { step: "review", exp: Date.now() + TTL_MS, ...signed, csrf,
                      sha: r.content_sha256, version: r.memory_version })) {
      throw new Error("the visit does not fit in a cookie");
    }
    page(res, 200, "Review this memory",
      `<p>Read the memory below. Approving says it is right for <strong>${escape(r.namespace_path)}</strong>; ` +
      `rejecting says it is not. You'll be asked to confirm.</p>${details(r)}` +
      `<form method="post" action="/approve/review">${csrfField(csrf)}` +
      `<button class="go" name="action" value="approve">Approve</button>` +
      `<button name="action" value="reject">Reject</button>` +
      `<button name="action" value="cancel">Not now</button></form>`);
  }));

  router.post("/approve/review", limit, form, safe(async (req, res) => {
    const visit = openVisit(pepper, readCookie(req));
    if (!visit || visit.step !== "review" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    const action = one(req.body?.action);
    if (action !== "approve" && action !== "reject") {
      await end(res, visit);
      return page(res, 200, "Nothing was decided", "<p>You left this memory as it was.</p>");
    }
    let challenge: { challenge_id: string; secret: string } | undefined;
    let r: Review | undefined;
    try {
      challenge = (await db.query<{ challenge_id: string; secret: string }>(
        "SELECT challenge_id, secret FROM memory.issue_approval_challenge($1, $2, $3, $4, $5, $6)",
        [visit.userId, visit.sessionId, visit.memoryId, action, visit.sha, visit.version])).rows[0];
      r = (await db.query<Review>("SELECT * FROM memory.approval_review($1, $2, $3)",
        [visit.userId, visit.sessionId, visit.memoryId])).rows[0];
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was decided", `<p>${escape(why)}</p>`);
    }
    if (!challenge || !UUID.test(challenge.challenge_id) || !HEX64.test(challenge.secret) || !r) {
      throw new Error("the challenge came back malformed");
    }
    const csrf = b64url(randomBytes(24));
    const { sha: _sha, version: _version, step: _step, ...signed } = visit;
    if (!store(res, { ...signed, step: "confirm", exp: Date.now() + TTL_MS, csrf, action,
                      challengeId: challenge.challenge_id, secret: challenge.secret })) {
      throw new Error("the visit does not fit in a cookie");
    }
    const verb = action === "approve" ? "Approve" : "Reject";
    page(res, 200, `${verb} this memory?`,
      `<p>You are about to <strong>${action}</strong> version ${r.memory_version} of this memory in ` +
      `<strong>${escape(r.namespace_path)}</strong>. This is recorded with your name and can't be undone.</p>` +
      `${details(r)}<form method="post" action="/approve/confirm">${csrfField(csrf)}` +
      `<button class="go" name="choice" value="confirm">${verb} it</button>` +
      `<button name="choice" value="cancel">Go back without deciding</button></form>`);
  }));

  router.post("/approve/confirm", limit, form, safe(async (req, res) => {
    const visit = openVisit(pepper, readCookie(req));
    if (!visit || visit.step !== "confirm" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    if (one(req.body?.choice) !== "confirm") {
      await end(res, visit);
      return page(res, 200, "Nothing was decided", "<p>You left this memory as it was.</p>");
    }
    try {
      await db.query("SELECT memory.decide_approval_challenge($1, $2, $3, $4)",
        [visit.userId, visit.sessionId, visit.challengeId, visit.secret]);
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was decided", `<p>${escape(why)}</p>`);
    }
    await end(res, visit);
    page(res, 200, visit.action === "approve" ? "Approved" : "Rejected",
      `<p>Your decision is recorded. You can close this page.</p>`);
  }));

  // Last, so /approve/callback is never read as a memory id.
  router.get("/approve/:memoryId", limit, safe(async (req, res) => {
    const memoryId = one(req.params.memoryId);
    if (!memoryId || !UUID.test(memoryId)) {
      return page(res, 404, "Nothing to decide here", "<p>This approval link is not right. Ask for a new one.</p>");
    }
    const idpVerifier = b64url(randomBytes(32));
    store(res, { step: "login", exp: Date.now() + TTL_MS, memoryId: memoryId.toLowerCase(), idpVerifier });
    res.set("Cache-Control", "no-store").redirect(302, identity.signInUrl(s256(idpVerifier), `${issuer}/approve/callback`));
  }));

  return router;
}
