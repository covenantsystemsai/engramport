/**
 * The erasure page: where a person with authority over a namespace reviews an
 * erasure request and confirms it, with their own Google sign-in, in their
 * own browser (founder decision D-02).
 *
 * It is a page and not an MCP tool on purpose: an agent can ask for an
 * erasure (request_erasure) but never carry one out. Every rule lives in the
 * database (migration 0022); this file is the HTTP around three calls, all
 * with the one fresh sign-in this visit started:
 *
 *   GET  /erase/:requestId   starts a fresh Google sign-in for this request
 *   GET  /erase/callback     back from Supabase Auth: shows what would be
 *                            erased (memory.erasure_review)
 *   POST /erase/review       the person chose to erase: takes a challenge
 *                            bound to the request they were shown
 *                            (memory.issue_erasure_challenge) and asks them
 *                            to confirm
 *   POST /erase/confirm      confirms: spends the challenge and the sign-in
 *                            together and erases (memory.decide_erasure_challenge)
 *
 * The browser carries the visit in an encrypted, signed, ten-minute cookie of
 * its own, sealed under a key of its own, so an approval visit can't stand in
 * for an erasure visit. The challenge's secret is only ever in that cookie.
 * Each form carries a token tied to the cookie, and the cookie is SameSite.
 *
 * Served only with ENGRAMPORT_ERASURE_PAGE=true, which needs OAuth set up.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import express, { Request, Response, Router } from "express";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";

import { b64url, escape, one, openVisit, page, readCookie, refusal, s256, safe, sealVisit } from "./approve.js";
import type { IdentityProvider, OAuthDb } from "./oauth.js";

export interface ErasurePageOptions {
  /** The server's public origin, e.g. https://mcp.example.com. */
  publicUrl: string;
  pepper: Buffer;
  db: OAuthDb;
  identity: IdentityProvider;
  /** Browser requests allowed per minute per address on one instance. Default 30. */
  perMinute?: number;
}

const COOKIE = "__Host-ep_erase";
const INFO = "engramport erasure visit v1";
const TTL_MS = 10 * 60 * 1000;
const MAX_SEALED = 3500;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX64 = /^[0-9a-f]{64}$/;
const SQLSTATE = /^[0-9A-Z]{5}$/;

interface Base {
  exp: number;
  requestId: string;
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
  itemsSha: string;
}
interface ConfirmStep extends Signed {
  step: "confirm";
  challengeId: string;
  secret: string;
}
export type ErasureVisit = LoginStep | ReviewStep | ConfirmStep;

/** One row of memory.erasure_review: the request, and one memory it names. */
interface Item {
  request_id: string;
  namespace_path: string;
  reason: string;
  state: string;
  requested_by: string;
  requested_at: Date;
  items_sha256: string;
  memory_id: string;
  kind: string;
  claim_type: string;
  status: string;
  approval_state: string;
  content: string;
  versions: number;
  embeddings: string;
  mentions: string;
  links: string;
  relations: string;
}

const REASONS: Record<string, string> = {
  owner_request: "the owner asked for it to be deleted",
  stored_in_error: "it was stored in error",
  legal: "a legal requirement",
};

export const openErasureVisit = (pepper: Buffer, sealed: string | undefined, now = Date.now()) =>
  openVisit<ErasureVisit>(pepper, sealed, now, INFO);

const setCookie = (res: Response, value: string) =>
  res.append("Set-Cookie", `${COOKIE}=${value}; Path=/; Max-Age=${TTL_MS / 1000}; HttpOnly; Secure; SameSite=Lax`);
const clearCookie = (res: Response) =>
  res.append("Set-Cookie", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);

const expired = (res: Response) =>
  page(res, 400, "This visit has expired",
    "<p>This erasure has expired or was opened in another browser. Open the erasure link again.</p>");

const n = (v: string | number) => Number(v);
const plural = (count: number, one: string, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;

/** What would go: the request, then each memory with its text and what is derived from it. */
function details(items: Item[]): string {
  const r = items[0];
  const when = (d: Date) => escape(new Date(d).toISOString().replace(".000Z", "Z"));
  const total = (k: "versions" | "embeddings" | "mentions" | "links" | "relations") =>
    items.reduce((sum, i) => sum + n(i[k]), 0);
  const head = `<dl><dt>Namespace</dt><dd>${escape(r.namespace_path)}</dd>` +
    `<dt>Asked by</dt><dd>${escape(r.requested_by)}, ${when(r.requested_at)}</dd>` +
    `<dt>Why</dt><dd>${escape(REASONS[r.reason] ?? r.reason)}</dd>` +
    `<dt>Memories named</dt><dd>${items.length}</dd>` +
    `<dt>Would remove</dt><dd>${plural(total("versions"), "version")}, ${plural(total("embeddings"), "embedding")}, ` +
    `${plural(total("mentions"), "entity mention")}, ${plural(total("links"), "memory link")}, ` +
    `${plural(total("relations"), "relation")} they are evidence for</dd>` +
    `<dt>Request</dt><dd><small>${escape(r.request_id)}</small></dd></dl>`;
  const each = items.map((i, k) =>
    `<h2>Memory ${k + 1} of ${items.length}</h2>` +
    `<p><small>${escape(i.kind)}, ${escape(i.claim_type.replace(/_/g, " "))}, ${escape(i.status)}` +
    `${i.approval_state !== "none" ? `, ${escape(i.approval_state)}` : ""}; ` +
    `${plural(n(i.versions), "version")}, ${plural(n(i.embeddings), "embedding")}, ` +
    `${plural(n(i.mentions), "mention")}, ${plural(n(i.links), "link")}, ${plural(n(i.relations), "relation")}</small></p>` +
    (i.status === "erased" ? "<p>Already erased.</p>" : `<pre>${escape(i.content)}</pre>`) +
    (n(i.versions) > 1 ? "<p><small>Only the version named is shown; every version goes.</small></p>" : ""),
  ).join("");
  return head + each;
}

export function createErasureRouter(opts: ErasurePageOptions): Router {
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
  const safely = (fn: (req: Request, res: Response) => Promise<unknown>) => safe(fn, "erasure page");

  const store = (res: Response, value: ErasureVisit): boolean => {
    let sealed = sealVisit(pepper, value, INFO);
    if (sealed.length > MAX_SEALED && "idpToken" in value) sealed = sealVisit(pepper, { ...value, idpToken: undefined }, INFO);
    if (sealed.length > MAX_SEALED) return false;
    setCookie(res, sealed);
    return true;
  };
  const visitOf = (req: Request) => openErasureVisit(pepper, readCookie(req, COOKIE));
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
  const review = async (visit: { userId: string; sessionId: string; requestId: string }) =>
    (await db.query<Item>("SELECT * FROM memory.erasure_review($1, $2, $3)",
      [visit.userId, visit.sessionId, visit.requestId])).rows;
  // A failed attempt is recorded by its error class only; recording it never hides the answer.
  const noteFailure = async (requestId: string, err: unknown) => {
    const code = (err as { code?: string })?.code;
    if (!code || !SQLSTATE.test(code)) return;
    await db.query("SELECT memory.note_erasure_failure($1, $2)", [requestId, code]).catch(() => undefined);
  };

  router.get("/erase/callback", limit, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "login") return expired(res);
    const code = one(req.query.code);
    if (!code || req.query.error !== undefined) {
      clearCookie(res);
      return page(res, 400, "Sign-in cancelled", "<p>Google sign-in was cancelled. Nothing was erased.</p>");
    }
    let who;
    try {
      who = await identity.exchange(code, visit.idpVerifier);
    } catch (err) {
      console.error("[engramport] erasure sign-in exchange failed:", (err as Error).message);
      clearCookie(res);
      return page(res, 400, "Sign-in failed", "<p>Google sign-in did not complete. Open the erasure link again.</p>");
    }
    const signed = { requestId: visit.requestId, userId: who.userId, sessionId: who.sessionId, idpToken: who.accessToken };
    let items: Item[];
    try {
      items = await review(signed);
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, signed);
      return page(res, 403, "Nothing to erase here", `<p>${escape(why)}</p>`);
    }
    if (!items.length) throw new Error("the review returned nothing");
    if (items[0].state !== "proposed") {
      await end(res, signed);
      return page(res, 200, "Nothing to erase here", "<p>This erasure was already carried out.</p>");
    }
    const csrf = b64url(randomBytes(24));
    if (!store(res, { step: "review", exp: Date.now() + TTL_MS, ...signed, csrf, itemsSha: items[0].items_sha256 })) {
      throw new Error("the visit does not fit in a cookie");
    }
    page(res, 200, "Review this erasure",
      `<p>Read what this request would erase from <strong>${escape(items[0].namespace_path)}</strong>. If you go ` +
      `ahead, every version of each memory below is erased, with its embeddings, graph links and fingerprints. ` +
      `Only a record that it happened, with no text, is kept. You'll be asked to confirm.</p>${details(items)}` +
      `<form method="post" action="/erase/review">${csrfField(csrf)}` +
      `<button class="go" name="action" value="erase">Erase these memories</button>` +
      `<button name="action" value="cancel">Not now</button></form>`);
  }));

  router.post("/erase/review", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "review" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    if (one(req.body?.action) !== "erase") {
      await end(res, visit);
      return page(res, 200, "Nothing was erased", "<p>You left these memories as they were.</p>");
    }
    let challenge: { challenge_id: string; secret: string } | undefined;
    let items: Item[];
    try {
      challenge = (await db.query<{ challenge_id: string; secret: string }>(
        "SELECT challenge_id, secret FROM memory.issue_erasure_challenge($1, $2, $3, $4)",
        [visit.userId, visit.sessionId, visit.requestId, visit.itemsSha])).rows[0];
      items = await review(visit);
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was erased", `<p>${escape(why)}</p>`);
    }
    if (!challenge || !UUID.test(challenge.challenge_id) || !HEX64.test(challenge.secret) || !items.length) {
      throw new Error("the challenge came back malformed");
    }
    const csrf = b64url(randomBytes(24));
    const { itemsSha: _sha, step: _step, ...signed } = visit;
    if (!store(res, { ...signed, step: "confirm", exp: Date.now() + TTL_MS, csrf,
                      challengeId: challenge.challenge_id, secret: challenge.secret })) {
      throw new Error("the visit does not fit in a cookie");
    }
    page(res, 200, `Erase ${plural(items.length, "memory", "memories")}?`,
      `<p>You are about to erase ${plural(items.length, "memory", "memories")}, and every version of ` +
      `${items.length === 1 ? "it" : "each"}, from ` +
      `<strong>${escape(items[0].namespace_path)}</strong>. This is recorded with your name. It can't be undone, ` +
      `and there is no recovery window.</p>${details(items)}` +
      `<form method="post" action="/erase/confirm">${csrfField(csrf)}` +
      `<button class="go" name="choice" value="confirm">Erase them</button>` +
      `<button name="choice" value="cancel">Go back without erasing</button></form>`);
  }));

  router.post("/erase/confirm", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "confirm" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    if (one(req.body?.choice) !== "confirm") {
      await end(res, visit);
      return page(res, 200, "Nothing was erased", "<p>You left these memories as they were.</p>");
    }
    let evidence: Record<string, number | boolean>;
    try {
      evidence = (await db.query<{ e: Record<string, number | boolean> }>(
        "SELECT memory.decide_erasure_challenge($1, $2, $3, $4) AS e",
        [visit.userId, visit.sessionId, visit.challengeId, visit.secret])).rows[0].e;
    } catch (err) {
      await noteFailure(visit.requestId, err);
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was erased", `<p>${escape(why)}</p>`);
    }
    await end(res, visit);
    const count = (k: string) => Number(evidence[k] ?? 0);
    page(res, 200, "Erased",
      `<p>${plural(count("versions"), "version")} erased, with ${plural(count("embeddings"), "embedding")}, ` +
      `${plural(count("mentions"), "entity mention")}, ${plural(count("links"), "memory link")} and ` +
      `${plural(count("relations"), "relation")}. A check found nothing of the text left in the live database.</p>` +
      `<p>Backups taken before now are not erased by this. They expire on the backup schedule, and if one is ever ` +
      `restored, this erasure is applied again before anything is served.</p><p>You can close this page.</p>`);
  }));

  // Last, so /erase/callback is never read as a request id.
  router.get("/erase/:requestId", limit, safely(async (req, res) => {
    const requestId = one(req.params.requestId);
    if (!requestId || !UUID.test(requestId)) {
      return page(res, 404, "Nothing to erase here", "<p>This erasure link is not right. Ask for a new one.</p>");
    }
    const idpVerifier = b64url(randomBytes(32));
    store(res, { step: "login", exp: Date.now() + TTL_MS, requestId: requestId.toLowerCase(), idpVerifier });
    res.set("Cache-Control", "no-store").redirect(302, identity.signInUrl(s256(idpVerifier), `${issuer}/erase/callback`));
  }));

  return router;
}
