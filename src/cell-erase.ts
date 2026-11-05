/**
 * The whole-cell erasure pages (founder decisions D-02.1 and D-02.1a): the
 * cell's owner starts it, and a different person holding the
 * cell-erasure-confirmer role confirms the exact operation after reviewing its
 * impact. Each with their own fresh Google sign-in, in their own browser.
 *
 * Every rule lives in the database (migration 0026); this file is the HTTP
 * around it. The confirmer sees counts and never memory content.
 *
 *   GET  /cell-erasure/start/:cellId  the owner: starts a fresh Google sign-in
 *   GET  /cell-erasure/:requestId     the confirmer: starts a fresh Google sign-in
 *   GET  /cell-erasure/callback       back from Supabase Auth. For the owner,
 *                                     what the cell holds (memory.cell_erasure_preview)
 *                                     and a reason to choose; for the confirmer,
 *                                     the request and fresh counts
 *                                     (memory.cell_erasure_review)
 *   POST /cell-erasure/start/review   the owner chose to start it: asks them to confirm
 *   POST /cell-erasure/start/confirm  starts it, which freezes the cell
 *                                     (memory.request_cell_erasure)
 *   POST /cell-erasure/review         the confirmer chose to erase: takes a challenge
 *                                     bound to what they were shown
 *                                     (memory.issue_cell_erasure_challenge)
 *   POST /cell-erasure/confirm        confirms: spends the challenge and the sign-in
 *                                     together and erases the cell
 *                                     (memory.decide_cell_erasure_challenge)
 *
 * The browser carries the visit in an encrypted, signed, ten-minute cookie of
 * its own, sealed under a key of its own, so no other page's visit can stand
 * in for it. The challenge's secret is only ever in that cookie. Each form
 * carries a token tied to the cookie, and the cookie is SameSite.
 *
 * Served only with ENGRAMPORT_CELL_ERASURE_PAGE=true, which needs OAuth set up.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import express, { Request, Response, Router } from "express";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";

import { b64url, escape, one, openVisit, page, readCookie, refusal, s256, safe, sealVisit } from "./approve.js";
import type { IdentityProvider, OAuthDb } from "./oauth.js";

export interface CellErasurePageOptions {
  /** The server's public origin, e.g. https://mcp.example.com. */
  publicUrl: string;
  pepper: Buffer;
  db: OAuthDb;
  identity: IdentityProvider;
  /** Browser requests allowed per minute per address on one instance. Default 30. */
  perMinute?: number;
}

const COOKIE = "__Host-ep_cell";
const INFO = "engramport cell erasure visit v1";
const TTL_MS = 10 * 60 * 1000;
const MAX_SEALED = 3500;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX64 = /^[0-9a-f]{64}$/;
const REASONS: Record<string, string> = {
  owner_request: "The owner asked for it",
  stored_in_error: "It was stored in error",
  legal: "A legal requirement",
};

/** Who is on this visit: the owner starting it, or a confirmer confirming one. */
type Target = { role: "owner"; cellId: string } | { role: "confirmer"; requestId: string };
interface LoginStep {
  step: "login";
  exp: number;
  target: Target;
  idpVerifier: string;
}
interface Signed {
  exp: number;
  userId: string;
  sessionId: string;
  /** Absent when it would not fit in the cookie. Only used to end the Supabase session. */
  idpToken?: string;
  csrf: string;
}
interface OwnerReview extends Signed {
  step: "owner-review";
  cellId: string;
}
interface OwnerConfirm extends Signed {
  step: "owner-confirm";
  cellId: string;
  reason: string;
}
interface ConfirmerReview extends Signed {
  step: "confirmer-review";
  requestId: string;
  /** The digest of what the confirmer was shown. */
  objects: string;
}
interface ConfirmerConfirm extends Signed {
  step: "confirmer-confirm";
  requestId: string;
  challengeId: string;
  secret: string;
}
export type CellErasureVisit = LoginStep | OwnerReview | OwnerConfirm | ConfirmerReview | ConfirmerConfirm;

type Counts = Record<string, number | string | boolean>;
interface Preview {
  namespace_path: string;
  counts: Counts;
  open_request_id: string | null;
}
interface Review {
  request_id: string;
  namespace_path: string;
  reason: string;
  initiated_by: string;
  created_at: Date;
  expires_at: Date;
  counts: Counts;
  objects_sha256: string;
}

export const openCellErasureVisit = (pepper: Buffer, sealed: string | undefined, now = Date.now()) =>
  openVisit<CellErasureVisit>(pepper, sealed, now, INFO);

const setCookie = (res: Response, value: string) =>
  res.append("Set-Cookie", `${COOKIE}=${value}; Path=/; Max-Age=${TTL_MS / 1000}; HttpOnly; Secure; SameSite=Lax`);
const clearCookie = (res: Response) =>
  res.append("Set-Cookie", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);

const expired = (res: Response) =>
  page(res, 400, "This visit has expired",
    "<p>This visit has expired or was opened in another browser. Open the link again.</p>");

const when = (d: Date | string) => escape(new Date(d).toISOString().replace(/\.\d{3}Z$/, "Z"));
const LABELS: Record<string, string> = {
  memories: "Memories, every version", active: "Current memories", approved: "Approved memories",
  embeddings: "Embeddings", entities: "Entities", aliases: "Entity aliases", relations: "Relations",
  mentions: "Entity mentions", links: "Memory links", versions: "Memory versions erased",
  approval_digests: "Approval digests removed", challenge_digests: "Challenge digests removed",
  provenance_scrubbed: "Provenance records scrubbed",
};
/** Counts only, never content. */
function countsTable(counts: Counts): string {
  const rows = Object.keys(LABELS).filter((k) => typeof counts[k] === "number")
    .map((k) => `<dt>${LABELS[k]}</dt><dd>${escape(String(counts[k]))}</dd>`).join("");
  return `<dl>${rows}</dl>`;
}

export function createCellErasureRouter(opts: CellErasurePageOptions): Router {
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
  const safely = (fn: (req: Request, res: Response) => Promise<unknown>) => safe(fn, "cell erasure page");

  const store = (res: Response, value: CellErasureVisit): boolean => {
    let sealed = sealVisit(pepper, value, INFO);
    if (sealed.length > MAX_SEALED && "idpToken" in value) sealed = sealVisit(pepper, { ...value, idpToken: undefined }, INFO);
    if (sealed.length > MAX_SEALED) return false;
    setCookie(res, sealed);
    return true;
  };
  const visitOf = (req: Request) => openCellErasureVisit(pepper, readCookie(req, COOKIE));
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
  const fresh = (signed: Omit<Signed, "csrf" | "exp">) => ({ ...signed, exp: Date.now() + TTL_MS, csrf: b64url(randomBytes(24)) });
  const keep = (res: Response, value: CellErasureVisit) => {
    if (!store(res, value)) throw new Error("the visit does not fit in a cookie");
  };

  const preview = async (v: { userId: string; sessionId: string; cellId: string }) =>
    (await db.query<Preview>(
      "SELECT namespace_path, counts, open_request_id FROM memory.cell_erasure_preview($1, $2, $3)",
      [v.userId, v.sessionId, v.cellId])).rows[0];
  const review = async (v: { userId: string; sessionId: string; requestId: string }) =>
    (await db.query<Review>(
      `SELECT request_id, namespace_path, reason::text, initiated_by, created_at, expires_at, counts, objects_sha256
       FROM memory.cell_erasure_review($1, $2, $3)`,
      [v.userId, v.sessionId, v.requestId])).rows[0];
  /** Whether the request is still waiting for this person's confirmation. */
  const stillOpen = async (v: { userId: string; sessionId: string; requestId: string }) =>
    (await db.query("SELECT 1 FROM memory.pending_cell_erasures($1, $2) WHERE request_id = $3",
      [v.userId, v.sessionId, v.requestId])).rows.length > 0;
  const requestDetails = (r: Review) =>
    `<dl><dt>Cell</dt><dd>${escape(r.namespace_path)}</dd>` +
    `<dt>Reason</dt><dd>${escape(REASONS[r.reason] ?? r.reason)}</dd>` +
    `<dt>Started by</dt><dd>${escape(r.initiated_by)}, ${when(r.created_at)}</dd>` +
    `<dt>Lapses</dt><dd>${when(r.expires_at)}</dd>` +
    `<dt>Request</dt><dd><small>${escape(r.request_id)}</small></dd></dl>${countsTable(r.counts)}`;

  router.get("/cell-erasure/callback", limit, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "login") return expired(res);
    const code = one(req.query.code);
    if (!code || req.query.error !== undefined) {
      clearCookie(res);
      return page(res, 400, "Sign-in cancelled", "<p>Google sign-in was cancelled. Nothing was changed.</p>");
    }
    let who;
    try {
      who = await identity.exchange(code, visit.idpVerifier);
    } catch (err) {
      console.error("[engramport] cell erasure sign-in exchange failed:", (err as Error).message);
      clearCookie(res);
      return page(res, 400, "Sign-in failed", "<p>Google sign-in did not complete. Open the link again.</p>");
    }
    const signed = { userId: who.userId, sessionId: who.sessionId, idpToken: who.accessToken };

    if (visit.target.role === "owner") {
      const cellId = visit.target.cellId;
      let p: Preview | undefined;
      try {
        p = await preview({ ...signed, cellId });
      } catch (err) {
        const why = refusal(err);
        if (!why) throw err;
        await end(res, signed);
        return page(res, 403, "Nothing to erase here", `<p>${escape(why)}</p>`);
      }
      if (!p) throw new Error("the preview returned nothing");
      if (p.open_request_id) {
        await end(res, signed);
        return page(res, 200, "Already waiting for confirmation",
          `<p>A whole-cell erasure of <strong>${escape(p.namespace_path)}</strong> is already waiting for a confirmer. ` +
          `The cell stays frozen until it is confirmed, cancelled or lapses.</p>` +
          `<p>Request <small>${escape(p.open_request_id)}</small></p>`);
      }
      const next = { ...fresh(signed), step: "owner-review" as const, cellId };
      keep(res, next);
      const choices = Object.entries(REASONS).map(([k, label], i) =>
        `<label><input type="radio" name="reason" value="${k}"${i === 0 ? " checked" : ""}> ${label}</label><br>`).join("");
      return page(res, 200, "Erase this whole cell?",
        `<p><strong>${escape(p.namespace_path)}</strong> holds what is counted below. Starting a whole-cell erasure ` +
        `freezes the cell: nothing new can be written to it until a different person, holding the ` +
        `cell-erasure-confirmer role, confirms it, it is cancelled, or 7 days pass. Once confirmed, everything in it ` +
        `is erased and can't be brought back. You'll be asked to confirm.</p>${countsTable(p.counts)}` +
        `<form method="post" action="/cell-erasure/start/review">${csrfField(next.csrf)}` +
        `<p>Why is it being erased?</p>${choices}` +
        `<button class="go" name="action" value="start">Start a whole-cell erasure</button>` +
        `<button name="action" value="cancel">Leave the cell as it is</button></form>`);
    }

    const requestId = visit.target.requestId;
    let r: Review | undefined;
    let open = false;
    try {
      r = await review({ ...signed, requestId });
      open = await stillOpen({ ...signed, requestId });
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, signed);
      return page(res, 403, "Nothing to confirm here", `<p>${escape(why)}</p>`);
    }
    if (!r) throw new Error("the review returned nothing");
    if (!open) {
      await end(res, signed);
      return page(res, 200, "This erasure is not waiting for confirmation",
        "<p>It was already confirmed, cancelled, or has lapsed. Nothing was changed.</p>");
    }
    if (!HEX64.test(r.objects_sha256)) throw new Error("the review digest came back malformed");
    const next = { ...fresh(signed), step: "confirmer-review" as const, requestId, objects: r.objects_sha256 };
    keep(res, next);
    page(res, 200, "Confirm this whole-cell erasure?",
      `<p>The owner of <strong>${escape(r.namespace_path)}</strong> asked to erase the whole cell. You see what it ` +
      `holds as counts only. Confirming erases all of it, and it can't be brought back. You'll be asked to ` +
      `confirm again.</p>${requestDetails(r)}` +
      `<form method="post" action="/cell-erasure/review">${csrfField(next.csrf)}` +
      `<button class="go" name="action" value="erase">Erase this cell</button>` +
      `<button name="action" value="cancel">Not now</button></form>`);
  }));

  router.post("/cell-erasure/start/review", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "owner-review" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    const reason = one(req.body?.reason) ?? "";
    if (one(req.body?.action) !== "start" || !Object.hasOwn(REASONS, reason)) {
      await end(res, visit);
      return page(res, 200, "Nothing was changed", "<p>The cell stays as it is.</p>");
    }
    let p: Preview | undefined;
    try {
      p = await preview(visit);
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was changed", `<p>${escape(why)}</p>`);
    }
    if (!p) throw new Error("the preview returned nothing");
    const { step: _s, ...signed } = visit;
    const next = { ...signed, ...fresh(signed), step: "owner-confirm" as const, reason };
    keep(res, next);
    page(res, 200, "Freeze the cell and send it for confirmation?",
      `<p>You are about to start erasing everything in <strong>${escape(p.namespace_path)}</strong> ` +
      `(${escape(REASONS[reason])}). The cell is frozen from now until a confirmer decides, it is cancelled, or ` +
      `7 days pass. This is recorded with your name.</p>${countsTable(p.counts)}` +
      `<form method="post" action="/cell-erasure/start/confirm">${csrfField(next.csrf)}` +
      `<button class="go" name="choice" value="confirm">Freeze it and ask for confirmation</button>` +
      `<button name="choice" value="cancel">Go back without starting</button></form>`);
  }));

  router.post("/cell-erasure/start/confirm", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "owner-confirm" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    if (one(req.body?.choice) !== "confirm") {
      await end(res, visit);
      return page(res, 200, "Nothing was changed", "<p>The cell stays as it is.</p>");
    }
    let id: string;
    try {
      id = (await db.query<{ id: string }>("SELECT memory.request_cell_erasure($1, $2, $3, $4::memory.erasure_reason) AS id",
        [visit.userId, visit.sessionId, visit.cellId, visit.reason])).rows[0].id;
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was changed", `<p>${escape(why)}</p>`);
    }
    await end(res, visit);
    page(res, 200, "Waiting for confirmation",
      `<p>The cell is frozen. Nothing is erased until a different person holding the cell-erasure-confirmer role ` +
      `confirms. Send them this link:</p><p><code>${escape(`${issuer}/cell-erasure/${id}`)}</code></p>` +
      `<p>If no one confirms within 7 days, the request lapses and the cell opens again.</p>`);
  }));

  router.post("/cell-erasure/review", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "confirmer-review" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    if (one(req.body?.action) !== "erase") {
      await end(res, visit);
      return page(res, 200, "Nothing was erased",
        "<p>The request stays open, and the cell frozen, until it is confirmed, cancelled or lapses.</p>");
    }
    let challenge: { challenge_id: string; secret: string } | undefined;
    let r: Review | undefined;
    try {
      challenge = (await db.query<{ challenge_id: string; secret: string }>(
        "SELECT challenge_id, secret FROM memory.issue_cell_erasure_challenge($1, $2, $3, $4)",
        [visit.userId, visit.sessionId, visit.requestId, visit.objects])).rows[0];
      r = await review(visit);
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was erased", `<p>${escape(why)}</p>`);
    }
    if (!challenge || !UUID.test(challenge.challenge_id) || !HEX64.test(challenge.secret) || !r) {
      throw new Error("the challenge came back malformed");
    }
    const { objects: _o, step: _s, ...signed } = visit;
    const next = { ...signed, ...fresh(signed), step: "confirmer-confirm" as const,
                   challengeId: challenge.challenge_id, secret: challenge.secret };
    keep(res, next);
    page(res, 200, "Erase it?",
      `<p>You are about to erase everything in <strong>${escape(r.namespace_path)}</strong>. It can't be ` +
      `brought back. This is recorded with your name, without any of the cell's content.</p>${requestDetails(r)}` +
      `<form method="post" action="/cell-erasure/confirm">${csrfField(next.csrf)}` +
      `<button class="go" name="choice" value="confirm">Erase the cell</button>` +
      `<button name="choice" value="cancel">Go back without erasing</button></form>`);
  }));

  router.post("/cell-erasure/confirm", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "confirmer-confirm" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    if (one(req.body?.choice) !== "confirm") {
      await end(res, visit);
      return page(res, 200, "Nothing was erased",
        "<p>The request stays open, and the cell frozen, until it is confirmed, cancelled or lapses.</p>");
    }
    let done: Counts;
    try {
      done = (await db.query<{ r: Counts }>("SELECT memory.decide_cell_erasure_challenge($1, $2, $3, $4) AS r",
        [visit.userId, visit.sessionId, visit.challengeId, visit.secret])).rows[0].r;
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was erased", `<p>${escape(why)}</p>`);
    }
    await end(res, visit);
    page(res, 200, "Cell erased",
      `<p>Everything in the cell was erased and the erasure was verified. It is recorded with your name and the ` +
      `owner's, with these counts and no content.</p>${countsTable(done)}<p>You can close this page.</p>`);
  }));

  const signIn = (res: Response, target: Target) => {
    const idpVerifier = b64url(randomBytes(32));
    store(res, { step: "login", exp: Date.now() + TTL_MS, target, idpVerifier });
    res.set("Cache-Control", "no-store").redirect(302, identity.signInUrl(s256(idpVerifier), `${issuer}/cell-erasure/callback`));
  };
  const badLink = (res: Response) =>
    page(res, 404, "Nothing here", "<p>This link is not right. Ask for a new one.</p>");

  router.get("/cell-erasure/start/:cellId", limit, safely(async (req, res) => {
    const cellId = one(req.params.cellId);
    if (!cellId || !UUID.test(cellId)) return badLink(res);
    signIn(res, { role: "owner", cellId: cellId.toLowerCase() });
  }));

  // Last, so /cell-erasure/callback is never read as a request id.
  router.get("/cell-erasure/:requestId", limit, safely(async (req, res) => {
    const requestId = one(req.params.requestId);
    if (!requestId || !UUID.test(requestId)) return badLink(res);
    signIn(res, { role: "confirmer", requestId: requestId.toLowerCase() });
  }));

  return router;
}
