/**
 * The export page: where a person with an owner's grant over a namespace
 * downloads everything in it, with their own Google sign-in, in their own
 * browser (founder decision D-02.4).
 *
 * The export is streamed straight from the database to the person's browser as
 * JSON lines. Nothing is written to a file, kept or cached by EngramPort.
 * Every rule lives in the database (migration 0023):
 *
 *   GET  /export            starts a fresh Google sign-in
 *   GET  /export/callback   back from Supabase Auth: lists the namespaces this
 *                           person may export (memory.export_namespaces)
 *   POST /export/review     the person picked one: takes a single-use challenge
 *                           for it (memory.issue_export_challenge) and asks
 *                           them to confirm
 *   POST /export/download   spends the sign-in and the challenge and records
 *                           the start (memory.start_export, committed on its
 *                           own), then streams memory.export_rows in one
 *                           transaction that records the export delivered only
 *                           when the whole download has gone out
 *
 * The visit cookie is the export page's own, sealed under a key of its own.
 * Served only with ENGRAMPORT_EXPORT_PAGE=true, which needs OAuth set up.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";
import express, { Request, Response, Router } from "express";
import { ipKeyGenerator, rateLimit } from "express-rate-limit";
import type pg from "pg";

import { b64url, escape, one, openVisit, page, readCookie, refusal, s256, safe, sealVisit } from "./approve.js";
import type { IdentityProvider } from "./oauth.js";

/** A pool: the stream needs one connection for its whole transaction. */
export type ExportDb = Pick<pg.Pool, "query" | "connect">;

export interface ExportPageOptions {
  /** The server's public origin, e.g. https://mcp.example.com. */
  publicUrl: string;
  pepper: Buffer;
  db: ExportDb;
  identity: IdentityProvider;
  /** Browser requests allowed per minute per address on one instance. Default 30. */
  perMinute?: number;
  /** Rows fetched from the database per step of the stream. Default 500. */
  batch?: number;
  /**
   * How long the stream waits for the browser to take more before giving up,
   * in milliseconds. Default 60 seconds. The whole download also has to finish
   * within ten minutes of its start.
   */
  stallMs?: number;
}

const COOKIE = "__Host-ep_export";
const INFO = "engramport export visit v1";
const TTL_MS = 10 * 60 * 1000;
const MAX_SEALED = 3500;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX64 = /^[0-9a-f]{64}$/;

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
interface PickStep extends Signed {
  step: "pick";
}
interface ConfirmStep extends Signed {
  step: "confirm";
  namespaceId: string;
  namespacePath: string;
  exportId: string;
  secret: string;
}
export type ExportVisit = LoginStep | PickStep | ConfirmStep;

interface Offered {
  namespace_id: string;
  namespace_path: string;
  memories: string;
}

export const openExportVisit = (pepper: Buffer, sealed: string | undefined, now = Date.now()) =>
  openVisit<ExportVisit>(pepper, sealed, now, INFO);

const setCookie = (res: Response, value: string) =>
  res.append("Set-Cookie", `${COOKIE}=${value}; Path=/; Max-Age=${TTL_MS / 1000}; HttpOnly; Secure; SameSite=Lax`);
const clearCookie = (res: Response) =>
  res.append("Set-Cookie", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);

const expired = (res: Response) =>
  page(res, 400, "This visit has expired",
    "<p>This export has expired or was opened in another browser. Open the export link again.</p>");

const plural = (count: number, one: string, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;

/** A file name made only of safe characters, from the namespace path and the date. */
export function exportFileName(path: string, now = new Date()): string {
  const slug = path.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "namespace";
  return `engramport-export-${slug}-${now.toISOString().slice(0, 10)}.jsonl`;
}

export function createExportRouter(opts: ExportPageOptions): Router {
  const { db, pepper, identity } = opts;
  const issuer = opts.publicUrl;
  const batch = opts.batch ?? 500;
  const stallMs = opts.stallMs ?? 60_000;
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
  const safely = (fn: (req: Request, res: Response) => Promise<unknown>) => safe(fn, "export page");

  const store = (res: Response, value: ExportVisit): boolean => {
    let sealed = sealVisit(pepper, value, INFO);
    if (sealed.length > MAX_SEALED && "idpToken" in value) sealed = sealVisit(pepper, { ...value, idpToken: undefined }, INFO);
    if (sealed.length > MAX_SEALED) return false;
    setCookie(res, sealed);
    return true;
  };
  const visitOf = (req: Request) => openExportVisit(pepper, readCookie(req, COOKIE));
  const csrfOk = (visit: Signed, sent: unknown) => {
    const csrf = one(sent) ?? "";
    return csrf.length === visit.csrf.length && timingSafeEqual(Buffer.from(csrf), Buffer.from(visit.csrf));
  };
  // The Supabase session is only for this one export.
  const end = (res: Response, visit: { idpToken?: string }) => {
    clearCookie(res);
    return visit.idpToken ? identity.signOut(visit.idpToken).catch(() => undefined) : Promise.resolve();
  };
  const csrfField = (csrf: string) => `<input type="hidden" name="csrf" value="${csrf}">`;
  const offered = async (visit: { userId: string; sessionId: string }) =>
    (await db.query<Offered>("SELECT * FROM memory.export_namespaces($1, $2)", [visit.userId, visit.sessionId])).rows;

  router.get("/export/callback", limit, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "login") return expired(res);
    const code = one(req.query.code);
    if (!code || req.query.error !== undefined) {
      clearCookie(res);
      return page(res, 400, "Sign-in cancelled", "<p>Google sign-in was cancelled. Nothing was exported.</p>");
    }
    let who;
    try {
      who = await identity.exchange(code, visit.idpVerifier);
    } catch (err) {
      console.error("[engramport] export sign-in exchange failed:", (err as Error).message);
      clearCookie(res);
      return page(res, 400, "Sign-in failed", "<p>Google sign-in did not complete. Open the export link again.</p>");
    }
    const signed = { userId: who.userId, sessionId: who.sessionId, idpToken: who.accessToken };
    let rows: Offered[];
    try {
      rows = await offered(signed);
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, signed);
      return page(res, 403, "Nothing to export here", `<p>${escape(why)}</p>`);
    }
    if (!rows.length) {
      await end(res, signed);
      return page(res, 403, "Nothing to export here",
        "<p>You don't hold an owner's grant over any namespace, so there is nothing you can export.</p>");
    }
    const csrf = b64url(randomBytes(24));
    if (!store(res, { step: "pick", exp: Date.now() + TTL_MS, ...signed, csrf })) {
      throw new Error("the visit does not fit in a cookie");
    }
    page(res, 200, "Export a namespace",
      "<p>Pick the namespace to export. You'll see what the export holds and be asked to confirm.</p>" +
      rows.map((r) =>
        `<form method="post" action="/export/review">${csrfField(csrf)}` +
        `<input type="hidden" name="namespace" value="${escape(r.namespace_id)}">` +
        `<p><strong>${escape(r.namespace_path)}</strong> <small>${plural(Number(r.memories), "memory", "memories")}</small><br>` +
        `<button name="action" value="pick">Export this</button></p></form>`).join("") +
      `<form method="post" action="/export/review">${csrfField(csrf)}<button name="action" value="cancel">Not now</button></form>`);
  }));

  router.post("/export/review", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "pick" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    const namespaceId = one(req.body?.namespace);
    if (one(req.body?.action) !== "pick" || !namespaceId || !UUID.test(namespaceId)) {
      await end(res, visit);
      return page(res, 200, "Nothing was exported", "<p>You left without exporting anything.</p>");
    }
    let challenge: { export_id: string; secret: string } | undefined;
    let rows: Offered[];
    try {
      rows = await offered(visit);
      challenge = (await db.query<{ export_id: string; secret: string }>(
        "SELECT export_id, secret FROM memory.issue_export_challenge($1, $2, $3)",
        [visit.userId, visit.sessionId, namespaceId])).rows[0];
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was exported", `<p>${escape(why)}</p>`);
    }
    const ns = rows.find((r) => r.namespace_id === namespaceId.toLowerCase());
    if (!challenge || !UUID.test(challenge.export_id) || !HEX64.test(challenge.secret) || !ns) {
      throw new Error("the export challenge came back malformed");
    }
    const csrf = b64url(randomBytes(24));
    const { step: _step, ...signed } = visit;
    if (!store(res, { ...signed, step: "confirm", exp: Date.now() + TTL_MS, csrf, namespaceId: ns.namespace_id,
                      namespacePath: ns.namespace_path, exportId: challenge.export_id, secret: challenge.secret })) {
      throw new Error("the visit does not fit in a cookie");
    }
    page(res, 200, `Export ${ns.namespace_path}?`,
      `<p>You are about to download everything in <strong>${escape(ns.namespace_path)}</strong>: ` +
      `${plural(Number(ns.memories), "memory", "memories")} with every version and its text, who wrote each and ` +
      `through which tool, the entities, relations and links between them, the approval trail, and the records of ` +
      `anything erased. Embeddings are left out.</p>` +
      `<p>The file comes straight to this browser and isn't kept anywhere by EngramPort. Keep it safe: it holds ` +
      `everything stored there. This export is recorded with your name.</p>` +
      `<form method="post" action="/export/download">${csrfField(csrf)}` +
      `<button class="go" name="choice" value="confirm">Download the export</button>` +
      `<button name="choice" value="cancel">Go back without exporting</button></form>`);
  }));

  router.post("/export/download", limit, form, safely(async (req, res) => {
    const visit = visitOf(req);
    if (!visit || visit.step !== "confirm" || !csrfOk(visit, req.body?.csrf)) return expired(res);
    if (one(req.body?.choice) !== "confirm") {
      await end(res, visit);
      return page(res, 200, "Nothing was exported", "<p>You left without exporting anything.</p>");
    }
    try {
      await db.query("SELECT memory.start_export($1, $2, $3, $4)",
        [visit.userId, visit.sessionId, visit.exportId, visit.secret]);
    } catch (err) {
      const why = refusal(err);
      if (!why) throw err;
      await end(res, visit);
      return page(res, 409, "Nothing was exported", `<p>${escape(why)}</p>`);
    }
    await end(res, visit);

    // One transaction for the whole stream: it records the export delivered,
    // and commits only once every row has gone out.
    const c = await db.connect();
    let open = false;
    // A connection that fails while the stream waits on the browser is
    // reported here, so the wait ends and the connection is thrown away.
    let broken: Error | undefined;
    const onClientError = (err: Error) => { broken = err; };
    c.on("error", onClientError);
    const deadline = Date.now() + 10 * 60 * 1000;
    try {
      await c.query("BEGIN");
      open = true;
      await c.query("SET LOCAL statement_timeout = '120s'");
      // A backstop: Postgres ends a stream left idle this long, even if this
      // process stops looking after it.
      await c.query("SET LOCAL idle_in_transaction_session_timeout = '300s'");
      await c.query("DECLARE export_rows NO SCROLL CURSOR FOR SELECT r::text AS line FROM memory.export_rows($1, $2, $3) r",
        [visit.sessionId, visit.exportId, visit.secret]);
      const fetch = async () => (await c.query<{ line: string }>(`FETCH ${batch} FROM export_rows`)).rows;
      let rows: Array<{ line: string }>;
      try {
        rows = await fetch();
      } catch (err) {
        await c.query("ROLLBACK");
        open = false;
        const why = refusal(err);
        if (!why) throw err;
        return page(res, 409, "Nothing was exported", `<p>${escape(why)}</p>`);
      }
      res.status(200).set({
        "Content-Type": "application/jsonl; charset=utf-8",
        "Content-Disposition": `attachment; filename="${exportFileName(visit.namespacePath)}"`,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "Referrer-Policy": "no-referrer",
      });
      let closed = false;
      res.on("close", () => { closed = true; });
      const gone = () => new Error("the browser went away before the export finished");
      // Wait for the browser to take more, but not for ever: a closed response
      // never drains, and a browser that stops reading may never close. Either
      // way the transaction must end and the connection go back.
      const drained = () => new Promise<void>((resolve, reject) => {
        const done = () => { off(); resolve(); };
        const fail = () => { off(); reject(gone()); };
        const stalled = () => { off(); reject(new Error("the browser stopped taking the export")); };
        const lost = (err: Error) => { off(); reject(err); };
        const timer = setTimeout(stalled, Math.max(0, Math.min(stallMs, deadline - Date.now())));
        const off = () => {
          clearTimeout(timer);
          res.off("drain", done); res.off("close", fail); res.off("error", fail); c.off("error", lost);
        };
        res.once("drain", done);
        res.once("close", fail);
        res.once("error", fail);
        c.once("error", lost);
        if (closed || res.destroyed) fail();
        else if (broken) lost(broken);
      });
      while (rows.length) {
        if (closed || res.destroyed) throw gone();
        if (broken) throw broken;
        if (Date.now() > deadline) throw new Error("the export took too long");
        const chunk = rows.map((r) => r.line).join("\n") + "\n";
        if (!res.write(chunk)) await drained();
        rows = await fetch();
      }
      await c.query("CLOSE export_rows");
      await c.query("COMMIT");
      open = false;
      res.end();
    } catch (err) {
      if (open && !broken) {
        await c.query("ROLLBACK").then(() => { open = false; }, (e: Error) => { broken = e; });
      }
      if (res.headersSent) {
        // Part of the file went out; end it broken so it can't pass for a whole one.
        console.error("[engramport] export stream failed:", (err as Error).message);
        res.destroy();
        return;
      }
      throw err;
    } finally {
      c.off("error", onClientError);
      // A connection that failed, or whose transaction could not be ended, is
      // thrown away rather than handed to the next request.
      c.release(broken ?? (open ? true : undefined));
    }
  }));

  router.get("/export", limit, safely(async (_req, res) => {
    const idpVerifier = b64url(randomBytes(32));
    store(res, { step: "login", exp: Date.now() + TTL_MS, idpVerifier });
    res.set("Cache-Control", "no-store").redirect(302, identity.signInUrl(s256(idpVerifier), `${issuer}/export/callback`));
  }));

  return router;
}
