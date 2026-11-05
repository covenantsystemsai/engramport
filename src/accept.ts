/**
 * The acceptance page: where a person decides, with their own fresh Google
 * sign-in, what has been offered to them (founder decisions D-03A, D-02 and
 * D-02.1a). Three kinds of offer count only once the person they name accepts
 * their exact terms:
 *
 *   - approval authority over a namespace, given by the admin or delegated by
 *     another approver (memory.pending_authority_grants,
 *     memory.decide_approval_authority);
 *   - an erase or export grant over one namespace, given by its owner
 *     (memory.pending_data_grants, memory.decide_data_grant);
 *   - the cell-erasure-confirmer role, assigned by the admin
 *     (memory.pending_confirmer_roles, memory.decide_confirmer_role).
 *
 *   GET  /accept           starts a fresh Google sign-in
 *   GET  /accept/callback  back from Supabase Auth: lists what is waiting
 *   POST /accept/review    the person picked one to accept or decline: shows
 *                          its terms again and asks them to confirm
 *   POST /accept/confirm   decides it, spending the sign-in, against the
 *                          fingerprint of the terms they were shown
 *
 * One decision per sign-in: to decide another, open the page again. The
 * browser carries the visit in an encrypted, signed, ten-minute cookie of its
 * own, sealed under a key of its own. Each form carries a token tied to the
 * cookie, and the cookie is SameSite.
 *
 * Served only with ENGRAMPORT_ACCEPT_PAGE=true, which needs OAuth set up.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import express, { Request, Response, Router } from "express";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";

import { b64url, escape, one, openVisit, page, readCookie, refusal, s256, safe, sealVisit } from "./approve.js";
import type { IdentityProvider, OAuthDb } from "./oauth.js";

export interface AcceptPageOptions {
  /** The server's public origin, e.g. https://mcp.example.com. */
  publicUrl: string;
  pepper: Buffer;
  db: OAuthDb;
  identity: IdentityProvider;
  /** Browser requests allowed per minute per address on one instance. Default 30. */
  perMinute?: number;
}

const COOKIE = "__Host-ep_accept";
const INFO = "engramport accept visit v1";
const TTL_MS = 10 * 60 * 1000;
const MAX_SEALED = 3500;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX64 = /^[0-9a-f]{64}$/;

type Kind = "authority" | "data" | "confirmer";
type Decision = "accept" | "reject";

interface LoginStep {
  step: "login";
  exp: number;
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
interface ListStep extends Signed {
  step: "list";
}
interface ConfirmStep extends Signed {
  step: "confirm";
  kind: Kind;
  id: string;
  /** The fingerprint of the terms the person was shown. */
  sha: string;
  decision: Decision;
}
export type AcceptVisit = LoginStep | ListStep | ConfirmStep;

/** One offer, whichever kind, as the page shows it. */
interface Offer {
  kind: Kind;
  id: string;
  sha: string;
  title: string;
  terms: [string, string][];
}

export const openAcceptVisit = (pepper: Buffer, sealed: string | undefined, now = Date.now()) =>
  openVisit<AcceptVisit>(pepper, sealed, now, INFO);

const setCookie = (res: Response, value: string) =>
  res.append("Set-Cookie", `${COOKIE}=${value}; Path=/; Max-Age=${TTL_MS / 1000}; HttpOnly; Secure; SameSite=Lax`);
const clearCookie = (res: Response) =>
  res.append("Set-Cookie", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);

const expired = (res: Response) =>
  page(res, 400, "This visit has expired",
    "<p>This visit has expired or was opened in another browser. Open the page again.</p>");

const when = (d: Date | string | null) =>
  d === null ? "no end date" : new Date(d).toISOString().replace(/\.\d{3}Z$/, "Z");
const words = (s: string) => s.replace(/_/g, " ");

interface AuthorityRow {
  id: string; path: string; scope: string; claim_types: string[] | null; can_delegate: boolean;
  expires_at: Date | null; delegated_from: string | null; granted_at: Date; sha: string;
}
interface DataRow { id: string; path: string; power: string; granted_by: string; expires_at: Date; sha: string }
interface RoleRow { id: string; path: string; assigned_at: Date; expires_at: Date; sha: string }

const DECIDE: Record<Kind, string> = {
  authority: "SELECT memory.decide_approval_authority($1, $2, $3, $4, $5)",
  data: "SELECT memory.decide_data_grant($1, $2, $3, $4, $5)",
  confirmer: "SELECT memory.decide_confirmer_role($1, $2, $3, $4, $5)",
};
const KINDS = Object.keys(DECIDE) as Kind[];

/** Everything waiting for this sign-in's person, without spending the sign-in. */
async function offers(db: OAuthDb, v: { userId: string; sessionId: string }): Promise<Offer[]> {
  const args = [v.userId, v.sessionId];
  const authority = (await db.query<AuthorityRow>(
    `SELECT authority_id AS id, namespace_path AS path, scope::text, claim_types::text[] AS claim_types, can_delegate,
            expires_at, delegated_from, granted_at, grant_sha256 AS sha
     FROM memory.pending_authority_grants($1, $2)`, args)).rows;
  const data = (await db.query<DataRow>(
    `SELECT grant_id AS id, namespace_path AS path, power::text, granted_by, expires_at, grant_sha256 AS sha
     FROM memory.pending_data_grants($1, $2)`, args)).rows;
  const roles = (await db.query<RoleRow>(
    `SELECT role_id AS id, scope_path AS path, assigned_at, expires_at, terms_sha256 AS sha
     FROM memory.pending_confirmer_roles($1, $2)`, args)).rows;
  return [
    ...authority.map((a): Offer => ({
      kind: "authority", id: a.id, sha: a.sha,
      title: `Approve memories in ${a.path}`,
      terms: [
        ["What", `Approval authority over ${a.path} and what is under it, for ${words(a.scope)}`],
        ["Claim types", a.claim_types?.length ? a.claim_types.map(words).join(", ") : "all of them"],
        ["Can pass it on", a.can_delegate ? "yes, to other people, never more than this" : "no"],
        ["From", a.delegated_from ? "delegated by another approver" : "given by the admin"],
        ["Offered", when(a.granted_at)],
        ["Ends", when(a.expires_at)],
      ],
    })),
    ...data.map((g): Offer => ({
      kind: "data", id: g.id, sha: g.sha,
      title: g.power === "erase" ? `Erase memories in ${g.path}` : `Export everything in ${g.path}`,
      terms: [
        ["What", g.power === "erase"
          ? `Decide erasure requests for memories in ${g.path} on its owner's behalf`
          : `Download all of ${g.path}'s memories, streamed and never stored on the server`],
        ["Given by", g.granted_by],
        ["Ends", when(g.expires_at)],
      ],
    })),
    ...roles.map((r): Offer => ({
      kind: "confirmer", id: r.id, sha: r.sha,
      title: `Confirm whole-cell erasures under ${r.path}`,
      terms: [
        ["What", `AN2B's cell-erasure-confirmer role for cells at or under ${r.path}. You confirm whole-cell ` +
          "erasures an owner has started, after seeing counts. It doesn't let you read any memory, start an " +
          "erasure, or confirm one you started"],
        ["Assigned", when(r.assigned_at)],
        ["Ends", when(r.expires_at)],
      ],
    })),
  ];
}

const termsList = (o: Offer) =>
  `<dl>${o.terms.map(([k, v]) => `<dt>${escape(k)}</dt><dd>${escape(v)}</dd>`).join("")}` +
  `<dt>Fingerprint</dt><dd><small>${escape(o.sha)}</small></dd></dl>`;

export function createAcceptRouter(opts: AcceptPageOptions): Router {
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
    handler: (_req, res) => page(res, 429, "Slow down", "<p>Too many tries from here. Wait a minute and open the page again.</p>"),
  });
  const safely = (fn: (req: Request, res: Response) => Promise<unknown>) => safe(fn, "accept page");

  const store = (res: Response, value: AcceptVisit) => {
    let sealed = sealVisit(pepper, value, INFO);
    if (sealed.length > MAX_SEALED && "idpToken" in value) sealed = sealVisit(pepper, { ...value, idpToken: undefined }, INFO);
    if (sealed.length > MAX_SEALED) throw new Error("the visit does not fit in a cookie");
    setCookie(res, sealed);
  };
  const visitOf = (req: Request) => openAcceptVisit(pepper, readCookie(req, COOKIE));
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

  router.get("/accept/callback", limit, safely(async (req, res) => {
    const visit = visitOf(req);
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
      console.error("[engramport] accept sign-in exchange failed:", (err as Error).message);
      clearCookie(res);
      return page(res, 400, "Sign-in failed", "<p>Google sign-in did not complete. Open the page again.</p>");
    }
    const signed = { userId: who.userId, sessionId: who.sessionId, idpToken: who.accessToken };
    let list: Offer[];
    try {
      list = await offers(db, signed);
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, signed);
      return page(res, 403, "Nothing to decide here", `<p>${escape(why)}</p>`);
    }
    if (!list.length) {
      await end(res, signed);
      return page(res, 200, "Nothing waiting for you", "<p>Nothing has been offered to you to accept.</p>");
    }
    const csrf = b64url(randomBytes(24));
    store(res, { step: "list", exp: Date.now() + TTL_MS, ...signed, csrf });
    page(res, 200, "Waiting for your decision",
      `<p>These were offered to you. Each counts only once you accept it. Pick one to accept or decline; ` +
      `you'll be asked to confirm, and you can decide one per visit.</p>` +
      list.map((o) =>
        `<h2>${escape(o.title)}</h2>${termsList(o)}` +
        `<form method="post" action="/accept/review">${csrfField(csrf)}` +
        `<input type="hidden" name="kind" value="${o.kind}"><input type="hidden" name="id" value="${escape(o.id)}">` +
        `<input type="hidden" name="sha" value="${escape(o.sha)}">` +
        `<button class="go" name="decision" value="accept">Accept</button>` +
        `<button name="decision" value="reject">Decline</button></form>`).join(""));
  }));

  router.post("/accept/review", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "list" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    const kind = one(req.body?.kind) as Kind;
    const id = (one(req.body?.id) ?? "").toLowerCase();
    const sha = one(req.body?.sha) ?? "";
    const decision = one(req.body?.decision);
    if (!KINDS.includes(kind) || !UUID.test(id) || !HEX64.test(sha) || (decision !== "accept" && decision !== "reject")) {
      await end(res, visit);
      return page(res, 400, "Nothing was decided", "<p>That choice wasn't one this page offered. Open the page again.</p>");
    }
    let o: Offer | undefined;
    try {
      o = (await offers(db, visit)).find((x) => x.kind === kind && x.id === id);
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was decided", `<p>${escape(why)}</p>`);
    }
    if (!o || o.sha !== sha) {
      await end(res, visit);
      return page(res, 409, "Nothing was decided",
        "<p>This offer is no longer waiting for you, or its terms changed. Open the page again.</p>");
    }
    const { step: _s, csrf: _c, ...signed } = visit;
    const csrf = b64url(randomBytes(24));
    store(res, { ...signed, step: "confirm", exp: Date.now() + TTL_MS, csrf, kind, id, sha, decision });
    const accept = decision === "accept";
    page(res, 200, accept ? "Accept this?" : "Decline this?",
      `<p>${accept
        ? "Once you accept, it counts from now until it ends or is revoked. This is recorded with your name."
        : "Once you decline, it can't be accepted later; it would have to be offered again. This is recorded with your name."}` +
      `</p><h2>${escape(o.title)}</h2>${termsList(o)}` +
      `<form method="post" action="/accept/confirm">${csrfField(csrf)}` +
      `<button class="go" name="choice" value="confirm">${accept ? "Accept it" : "Decline it"}</button>` +
      `<button name="choice" value="cancel">Go back without deciding</button></form>`);
  }));

  router.post("/accept/confirm", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "confirm" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    if (one(req.body?.choice) !== "confirm") {
      await end(res, visit);
      return page(res, 200, "Nothing was decided", "<p>The offer is still waiting for you.</p>");
    }
    try {
      await db.query(DECIDE[visit.kind], [visit.userId, visit.sessionId, visit.id, visit.decision, visit.sha]);
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was decided", `<p>${escape(why)}</p>`);
    }
    await end(res, visit);
    page(res, 200, visit.decision === "accept" ? "Accepted" : "Declined",
      `<p>${visit.decision === "accept" ? "It counts from now." : "It won't count."} The decision is recorded with ` +
      `your name. To decide anything else waiting for you, open <code>${escape(`${issuer}/accept`)}</code> again.</p>`);
  }));

  router.get("/accept", limit, safely(async (_req, res) => {
    const idpVerifier = b64url(randomBytes(32));
    store(res, { step: "login", exp: Date.now() + TTL_MS, idpVerifier });
    res.set("Cache-Control", "no-store").redirect(302, identity.signInUrl(s256(idpVerifier), `${issuer}/accept/callback`));
  }));

  return router;
}
