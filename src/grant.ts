/**
 * The grant page: where a namespace's owner offers another person the power to
 * erase in it or export it, by typing that person's email (founder decision
 * D-02 Grant Recipient Selection), with their own fresh Google sign-in.
 *
 * The page never shows who is a member, and its outcome never says whether the
 * address belongs to one: the server writes the grant only when it does, and
 * says the same either way (memory.offer_data_grant). The grant counts only
 * once the recipient accepts its exact terms on the acceptance page.
 *
 *   GET  /grant/:namespaceId  starts a fresh Google sign-in
 *   GET  /grant/callback      back from Supabase Auth: checks the person may give
 *                             grants here (memory.data_grant_giver_view) and asks
 *                             for the address, the power and how long
 *   POST /grant/review        shows the offer and asks them to confirm
 *   POST /grant/confirm       makes the offer, spending the sign-in
 *
 * The browser carries the visit in an encrypted, signed, ten-minute cookie of
 * its own, sealed under a key of its own. Each form carries a token tied to the
 * cookie, and the cookie is SameSite.
 *
 * Served only with ENGRAMPORT_GRANT_PAGE=true, which needs OAuth set up.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import express, { Request, Response, Router } from "express";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";

import { b64url, escape, one, openVisit, page, readCookie, refusal, s256, safe, sealVisit } from "./approve.js";
import type { IdentityProvider, OAuthDb } from "./oauth.js";

export interface GrantPageOptions {
  /** The server's public origin, e.g. https://mcp.example.com. */
  publicUrl: string;
  pepper: Buffer;
  db: OAuthDb;
  identity: IdentityProvider;
  /** Browser requests allowed per minute per address on one instance. Default 30. */
  perMinute?: number;
}

const COOKIE = "__Host-ep_grant";
const INFO = "engramport grant visit v1";
const TTL_MS = 10 * 60 * 1000;
const MAX_SEALED = 3500;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// The shape the database takes; the database checks it again.
const EMAIL = /^[^@\s]+@[^@\s]+$/;
const POWERS: Record<string, string> = {
  export: "export everything in it",
  erase: "decide erasure requests in it on your behalf",
};
const DAYS = [7, 30, 90];

interface LoginStep {
  step: "login";
  exp: number;
  namespaceId: string;
  idpVerifier: string;
}
interface Signed {
  exp: number;
  namespaceId: string;
  path: string;
  userId: string;
  sessionId: string;
  /** Absent when it would not fit in the cookie. Only used to end the Supabase session. */
  idpToken?: string;
  csrf: string;
}
interface FormStep extends Signed {
  step: "form";
}
interface ConfirmStep extends Signed {
  step: "confirm";
  email: string;
  power: string;
  days: number;
}
export type GrantVisit = LoginStep | FormStep | ConfirmStep;

export const openGrantVisit = (pepper: Buffer, sealed: string | undefined, now = Date.now()) =>
  openVisit<GrantVisit>(pepper, sealed, now, INFO);

const setCookie = (res: Response, value: string) =>
  res.append("Set-Cookie", `${COOKIE}=${value}; Path=/; Max-Age=${TTL_MS / 1000}; HttpOnly; Secure; SameSite=Lax`);
const clearCookie = (res: Response) =>
  res.append("Set-Cookie", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);

const expired = (res: Response) =>
  page(res, 400, "This visit has expired",
    "<p>This visit has expired or was opened in another browser. Open the grant link again.</p>");

export function createGrantRouter(opts: GrantPageOptions): Router {
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
  const safely = (fn: (req: Request, res: Response) => Promise<unknown>) => safe(fn, "grant page");

  const store = (res: Response, value: GrantVisit) => {
    let sealed = sealVisit(pepper, value, INFO);
    if (sealed.length > MAX_SEALED && "idpToken" in value) sealed = sealVisit(pepper, { ...value, idpToken: undefined }, INFO);
    if (sealed.length > MAX_SEALED) throw new Error("the visit does not fit in a cookie");
    setCookie(res, sealed);
  };
  const visitOf = (req: Request) => openGrantVisit(pepper, readCookie(req, COOKIE));
  const csrfOk = (visit: Signed, sent: unknown) => {
    const csrf = one(sent) ?? "";
    return csrf.length === visit.csrf.length && timingSafeEqual(Buffer.from(csrf), Buffer.from(visit.csrf));
  };
  // The Supabase session is only for this one offer.
  const end = (res: Response, visit: { idpToken?: string }) => {
    clearCookie(res);
    return visit.idpToken ? identity.signOut(visit.idpToken).catch(() => undefined) : Promise.resolve();
  };
  const csrfField = (csrf: string) => `<input type="hidden" name="csrf" value="${csrf}">`;

  router.get("/grant/callback", limit, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "login") return expired(res);
    const code = one(req.query.code);
    if (!code || req.query.error !== undefined) {
      clearCookie(res);
      return page(res, 400, "Sign-in cancelled", "<p>Google sign-in was cancelled. Nothing was offered.</p>");
    }
    let who;
    try {
      who = await identity.exchange(code, visit.idpVerifier);
    } catch (err) {
      console.error("[engramport] grant sign-in exchange failed:", (err as Error).message);
      clearCookie(res);
      return page(res, 400, "Sign-in failed", "<p>Google sign-in did not complete. Open the grant link again.</p>");
    }
    const signed = { namespaceId: visit.namespaceId, userId: who.userId, sessionId: who.sessionId, idpToken: who.accessToken };
    let path: string | undefined;
    try {
      path = (await db.query<{ namespace_path: string }>(
        "SELECT namespace_path FROM memory.data_grant_giver_view($1, $2, $3)",
        [signed.userId, signed.sessionId, signed.namespaceId])).rows[0]?.namespace_path;
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, signed);
      return page(res, 403, "Nothing to give here", `<p>${escape(why)}</p>`);
    }
    if (!path) throw new Error("the namespace came back empty");
    const csrf = b64url(randomBytes(24));
    store(res, { step: "form", exp: Date.now() + TTL_MS, ...signed, path, csrf });
    const powers = Object.entries(POWERS).map(([k, what], i) =>
      `<label><input type="radio" name="power" value="${k}"${i === 0 ? " checked" : ""}> ${k[0].toUpperCase()}${k.slice(1)}: ` +
      `${escape(what)}</label><br>`).join("");
    const days = DAYS.map((d) => `<label><input type="radio" name="days" value="${d}"${d === 30 ? " checked" : ""}> ${d} days</label> `).join("");
    page(res, 200, "Offer a grant",
      `<p>Offer another member of <strong>${escape(path)}</strong> a power over it. Type their email. It counts ` +
      `only once they sign in and accept its exact terms, and you or an admin can revoke it.</p>` +
      `<form method="post" action="/grant/review">${csrfField(csrf)}` +
      `<p><label>Their email<br><input type="email" name="email" required maxlength="254" autocomplete="off"></label></p>` +
      `<p>What they may do</p>${powers}<p>For how long</p><p>${days}</p>` +
      `<button class="go" name="action" value="review">Review the offer</button>` +
      `<button name="action" value="cancel">Offer nothing</button></form>`);
  }));

  router.post("/grant/review", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "form" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    if (one(req.body?.action) !== "review") {
      await end(res, visit);
      return page(res, 200, "Nothing was offered", "<p>No grant was made.</p>");
    }
    const email = (one(req.body?.email) ?? "").trim().toLowerCase();
    const power = one(req.body?.power) ?? "";
    const days = Number(one(req.body?.days));
    if (email.length > 254 || !EMAIL.test(email) || !Object.hasOwn(POWERS, power) || !DAYS.includes(days)) {
      await end(res, visit);
      return page(res, 400, "Nothing was offered",
        "<p>That wasn't an email address, or a choice this page offered. Open the grant link again.</p>");
    }
    const { step: _s, csrf: _c, ...signed } = visit;
    const csrf = b64url(randomBytes(24));
    store(res, { ...signed, step: "confirm", exp: Date.now() + TTL_MS, csrf, email, power, days });
    page(res, 200, "Make this offer?",
      `<dl><dt>Namespace</dt><dd>${escape(visit.path)}</dd><dt>To</dt><dd>${escape(email)}</dd>` +
      `<dt>They may</dt><dd>${escape(POWERS[power])}</dd><dt>For</dt><dd>${days} days from now</dd></dl>` +
      `<p>The offer goes only to a member of this namespace. This page won't say whether that address belongs ` +
      `to one. It is recorded with your name.</p>` +
      `<form method="post" action="/grant/confirm">${csrfField(csrf)}` +
      `<button class="go" name="choice" value="confirm">Make the offer</button>` +
      `<button name="choice" value="cancel">Go back without offering</button></form>`);
  }));

  router.post("/grant/confirm", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "confirm" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    if (one(req.body?.choice) !== "confirm") {
      await end(res, visit);
      return page(res, 200, "Nothing was offered", "<p>No grant was made.</p>");
    }
    try {
      await db.query(
        `SELECT memory.offer_data_grant($1, $2, $3, $4, $5::memory.data_power, now() + make_interval(days => $6::int))`,
        [visit.userId, visit.sessionId, visit.namespaceId, visit.email, visit.power, visit.days]);
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was offered", `<p>${escape(why)}</p>`);
    }
    await end(res, visit);
    // The same words whether or not the address belongs to a member.
    page(res, 200, "Offer recorded",
      `<p>If ${escape(visit.email)} belongs to a member of <strong>${escape(visit.path)}</strong>, the offer is ` +
      `waiting for them. Ask them to open <code>${escape(`${issuer}/accept`)}</code> and accept it. If it doesn't, ` +
      `nothing was created. This page doesn't say which.</p><p>You can close this page.</p>`);
  }));

  router.get("/grant/:namespaceId", limit, safely(async (req, res) => {
    const namespaceId = one(req.params.namespaceId);
    if (!namespaceId || !UUID.test(namespaceId)) {
      return page(res, 404, "Nothing here", "<p>This grant link is not right. Ask for a new one.</p>");
    }
    const idpVerifier = b64url(randomBytes(32));
    store(res, { step: "login", exp: Date.now() + TTL_MS, namespaceId: namespaceId.toLowerCase(), idpVerifier });
    res.set("Cache-Control", "no-store").redirect(302, identity.signInUrl(s256(idpVerifier), `${issuer}/grant/callback`));
  }));

  return router;
}
