/**
 * The restore page: where a person with authority over a retracted memory
 * brings it back, within 30 days of its retraction, with their own Google
 * sign-in, in their own browser (founder decision D-02.3).
 *
 * It is a page and not an MCP tool on purpose: an agent can retract a memory
 * but never restore one. Every rule lives in the database (migration 0025);
 * this file is the HTTP around three calls, all with the one fresh sign-in this
 * visit started:
 *
 *   GET  /restore/:memoryId  starts a fresh Google sign-in for this memory
 *   GET  /restore/callback   back from Supabase Auth: shows the memory, when it
 *                            was retracted and until when it can come back
 *                            (memory.restore_review)
 *   POST /restore/review     the person chose to restore it: takes a challenge
 *                            bound to the retraction they were shown
 *                            (memory.issue_restore_challenge) and asks them to
 *                            confirm
 *   POST /restore/confirm    confirms: spends the challenge and the sign-in
 *                            together and restores (memory.decide_restore_challenge)
 *
 * The browser carries the visit in an encrypted, signed, ten-minute cookie of
 * its own, sealed under a key of its own, so no other page's visit can stand
 * in for it. The challenge's secret is only ever in that cookie. Each form
 * carries a token tied to the cookie, and the cookie is SameSite.
 *
 * Served only with ENGRAMPORT_RESTORE_PAGE=true, which needs OAuth set up.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import express, { Request, Response, Router } from "express";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";

import { b64url, escape, one, openVisit, page, readCookie, refusal, s256, safe, sealVisit } from "./approve.js";
import type { IdentityProvider, OAuthDb } from "./oauth.js";

export interface RestorePageOptions {
  /** The server's public origin, e.g. https://mcp.example.com. */
  publicUrl: string;
  pepper: Buffer;
  db: OAuthDb;
  identity: IdentityProvider;
  /** Browser requests allowed per minute per address on one instance. Default 30. */
  perMinute?: number;
}

const COOKIE = "__Host-ep_restore";
const INFO = "engramport restore visit v1";
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
  /** The retraction the person was shown, as the database gave it. */
  retractedAt: string;
}
interface ConfirmStep extends Signed {
  step: "confirm";
  challengeId: string;
  secret: string;
}
export type RestoreVisit = LoginStep | ReviewStep | ConfirmStep;

/** memory.restore_review's one row. retracted_at comes back as text, to keep its microseconds. */
interface Review {
  memory_id: string;
  namespace_path: string;
  kind: string;
  claim_type: string;
  approval_state: string;
  content: string;
  retracted_from: string | null;
  retracted_at: string | null;
  restorable_until: Date | null;
  refusal: string | null;
}

export const openRestoreVisit = (pepper: Buffer, sealed: string | undefined, now = Date.now()) =>
  openVisit<RestoreVisit>(pepper, sealed, now, INFO);

const setCookie = (res: Response, value: string) =>
  res.append("Set-Cookie", `${COOKIE}=${value}; Path=/; Max-Age=${TTL_MS / 1000}; HttpOnly; Secure; SameSite=Lax`);
const clearCookie = (res: Response) =>
  res.append("Set-Cookie", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);

const expired = (res: Response) =>
  page(res, 400, "This visit has expired",
    "<p>This restore has expired or was opened in another browser. Open the restore link again.</p>");

const when = (d: Date | string) => escape(new Date(d).toISOString().replace(/\.\d{3}Z$/, "Z"));
const BACK_TO: Record<string, string> = {
  active: "current again, as it was before it was retracted",
  proposed: "a proposed revision again, waiting for a person to decide on it",
};

/** The memory, when it was retracted, and what restoring would do. */
function details(r: Review): string {
  return `<dl><dt>Namespace</dt><dd>${escape(r.namespace_path)}</dd>` +
    `<dt>Kind</dt><dd>${escape(r.kind)}, ${escape(r.claim_type.replace(/_/g, " "))}` +
    `${r.approval_state !== "none" ? `, ${escape(r.approval_state)}` : ""}</dd>` +
    (r.retracted_at ? `<dt>Retracted</dt><dd>${when(r.retracted_at)}</dd>` : "") +
    (r.restorable_until ? `<dt>Can be restored until</dt><dd>${when(r.restorable_until)}</dd>` : "") +
    (r.retracted_from && BACK_TO[r.retracted_from] ? `<dt>Restoring makes it</dt><dd>${BACK_TO[r.retracted_from]}</dd>` : "") +
    `<dt>Memory</dt><dd><small>${escape(r.memory_id)}</small></dd></dl>` +
    `<pre>${escape(r.content)}</pre>`;
}

export function createRestoreRouter(opts: RestorePageOptions): Router {
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
  const safely = (fn: (req: Request, res: Response) => Promise<unknown>) => safe(fn, "restore page");

  const store = (res: Response, value: RestoreVisit): boolean => {
    let sealed = sealVisit(pepper, value, INFO);
    if (sealed.length > MAX_SEALED && "idpToken" in value) sealed = sealVisit(pepper, { ...value, idpToken: undefined }, INFO);
    if (sealed.length > MAX_SEALED) return false;
    setCookie(res, sealed);
    return true;
  };
  const visitOf = (req: Request) => openRestoreVisit(pepper, readCookie(req, COOKIE));
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
  const review = async (visit: { userId: string; sessionId: string; memoryId: string }) =>
    (await db.query<Review>(
      `SELECT memory_id, namespace_path, kind::text, claim_type::text, approval_state::text, content,
              retracted_from::text, retracted_at::text, restorable_until, refusal
       FROM memory.restore_review($1, $2, $3)`,
      [visit.userId, visit.sessionId, visit.memoryId])).rows[0];

  router.get("/restore/callback", limit, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "login") return expired(res);
    const code = one(req.query.code);
    if (!code || req.query.error !== undefined) {
      clearCookie(res);
      return page(res, 400, "Sign-in cancelled", "<p>Google sign-in was cancelled. Nothing was restored.</p>");
    }
    let who;
    try {
      who = await identity.exchange(code, visit.idpVerifier);
    } catch (err) {
      console.error("[engramport] restore sign-in exchange failed:", (err as Error).message);
      clearCookie(res);
      return page(res, 400, "Sign-in failed", "<p>Google sign-in did not complete. Open the restore link again.</p>");
    }
    const signed = { memoryId: visit.memoryId, userId: who.userId, sessionId: who.sessionId, idpToken: who.accessToken };
    let r: Review | undefined;
    try {
      r = await review(signed);
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, signed);
      return page(res, 403, "Nothing to restore here", `<p>${escape(why)}</p>`);
    }
    if (!r) throw new Error("the review returned nothing");
    if (r.refusal || !r.retracted_at) {
      await end(res, signed);
      return page(res, 200, "This memory can't be restored", `<p>${escape(r.refusal ?? "It is not retracted.")}</p>`);
    }
    const csrf = b64url(randomBytes(24));
    if (!store(res, { step: "review", exp: Date.now() + TTL_MS, ...signed, csrf, retractedAt: r.retracted_at })) {
      throw new Error("the visit does not fit in a cookie");
    }
    page(res, 200, "Restore this memory?",
      `<p>This memory in <strong>${escape(r.namespace_path)}</strong> was retracted. Read it before you decide. ` +
      `You'll be asked to confirm.</p>${details(r)}` +
      `<form method="post" action="/restore/review">${csrfField(csrf)}` +
      `<button class="go" name="action" value="restore">Restore this memory</button>` +
      `<button name="action" value="cancel">Leave it retracted</button></form>`);
  }));

  router.post("/restore/review", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "review" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    if (one(req.body?.action) !== "restore") {
      await end(res, visit);
      return page(res, 200, "Nothing was restored", "<p>The memory stays retracted.</p>");
    }
    let challenge: { challenge_id: string; secret: string } | undefined;
    let r: Review | undefined;
    try {
      challenge = (await db.query<{ challenge_id: string; secret: string }>(
        "SELECT challenge_id, secret FROM memory.issue_restore_challenge($1, $2, $3, $4::timestamptz)",
        [visit.userId, visit.sessionId, visit.memoryId, visit.retractedAt])).rows[0];
      r = await review(visit);
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was restored", `<p>${escape(why)}</p>`);
    }
    if (!challenge || !UUID.test(challenge.challenge_id) || !HEX64.test(challenge.secret) || !r) {
      throw new Error("the challenge came back malformed");
    }
    const csrf = b64url(randomBytes(24));
    const { retractedAt: _at, step: _step, ...signed } = visit;
    if (!store(res, { ...signed, step: "confirm", exp: Date.now() + TTL_MS, csrf,
                      challengeId: challenge.challenge_id, secret: challenge.secret })) {
      throw new Error("the visit does not fit in a cookie");
    }
    page(res, 200, "Restore it?",
      `<p>You are about to restore this memory in <strong>${escape(r.namespace_path)}</strong>. It becomes ` +
      `${BACK_TO[r.retracted_from ?? ""] ?? "what it was"}, and agents can find it again. This is recorded with ` +
      `your name.</p>${details(r)}` +
      `<form method="post" action="/restore/confirm">${csrfField(csrf)}` +
      `<button class="go" name="choice" value="confirm">Restore it</button>` +
      `<button name="choice" value="cancel">Go back without restoring</button></form>`);
  }));

  router.post("/restore/confirm", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "confirm" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    if (one(req.body?.choice) !== "confirm") {
      await end(res, visit);
      return page(res, 200, "Nothing was restored", "<p>The memory stays retracted.</p>");
    }
    let done: { restored_to?: string };
    try {
      done = (await db.query<{ r: { restored_to?: string } }>(
        "SELECT memory.decide_restore_challenge($1, $2, $3, $4) AS r",
        [visit.userId, visit.sessionId, visit.challengeId, visit.secret])).rows[0].r;
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was restored", `<p>${escape(why)}</p>`);
    }
    await end(res, visit);
    page(res, 200, "Restored",
      `<p>The memory is ${BACK_TO[done.restored_to ?? ""] ?? "back"}. The restoration is recorded with your name, ` +
      `without the memory's text.</p><p>You can close this page.</p>`);
  }));

  // Last, so /restore/callback is never read as a memory id.
  router.get("/restore/:memoryId", limit, safely(async (req, res) => {
    const memoryId = one(req.params.memoryId);
    if (!memoryId || !UUID.test(memoryId)) {
      return page(res, 404, "Nothing to restore here", "<p>This restore link is not right. Ask for a new one.</p>");
    }
    const idpVerifier = b64url(randomBytes(32));
    store(res, { step: "login", exp: Date.now() + TTL_MS, memoryId: memoryId.toLowerCase(), idpVerifier });
    res.set("Cache-Control", "no-store").redirect(302, identity.signInUrl(s256(idpVerifier), `${issuer}/restore/callback`));
  }));

  return router;
}
