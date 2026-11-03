/**
 * OAuth 2.1 for the hosted server: what lets claude.ai (or any MCP client)
 * connect with "sign in with Google" instead of a pasted key.
 *
 * EngramPort is its own authorization server. Supabase Auth only answers "who
 * is this person": the browser signs in with Google there, and the session it
 * gets back is checked by the database (migration 0009), which picks the
 * namespaces that email is a member of. The person picks one, and the client
 * gets an access token that is an ordinary namespace-bound key, valid for an
 * hour, plus a rotating refresh token. Every rule that matters (fresh Google
 * session, PKCE, single-use codes, reuse revokes the grant, scopes no wider
 * than the membership) lives in the database functions; this file is the
 * HTTP around them.
 *
 * Endpoints, all under the public URL:
 *   GET  /.well-known/oauth-protected-resource[/mcp]   RFC 9728
 *   GET  /.well-known/oauth-authorization-server       RFC 8414
 *   POST /oauth/register     dynamic client registration (RFC 7591), public clients only
 *   GET  /oauth/authorize    starts the Google sign-in
 *   GET  /oauth/callback     back from Supabase Auth: shows the namespace choice
 *   POST /oauth/decision     approve or deny
 *   POST /oauth/token        authorization_code and refresh_token grants
 *   POST /oauth/revoke       RFC 7009
 *
 * Nothing is kept in server memory between steps except the registration rate
 * limit: the browser carries the in-flight request in an encrypted, signed,
 * ten-minute cookie, so any instance can serve any step.
 */

import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import express, { Request, Response, Router } from "express";

import { hashKey, mintKey, parseKey, randomBase62 } from "./keys.js";

export const OAUTH_SCOPES = ["read", "write"] as const;

/** The database calls OAuth makes, as the engramport_app role. A pg.Pool fits. */
export interface OAuthDb {
  query<R = Record<string, unknown>>(text: string, values?: unknown[]): Promise<{ rows: R[] }>;
}

/** The person's Supabase Auth session, as the server got it straight from Supabase. */
export interface SignedIn {
  userId: string;
  sessionId: string;
  /** Used only to end the Supabase session once the choice is made. */
  accessToken: string;
}

/** Supabase Auth, as OAuth uses it. Swapped for a stand-in in tests. */
export interface IdentityProvider {
  /** Where to send the browser to sign in with Google. */
  signInUrl(codeChallenge: string, returnTo: string): string;
  /** Trade the code Supabase sent back for the session it stands for. */
  exchange(code: string, codeVerifier: string): Promise<SignedIn>;
  /** End the Supabase session. Best effort. */
  signOut(accessToken: string): Promise<void>;
}

export interface OAuthOptions {
  /** The server's public origin, e.g. https://mcp.example.com. The issuer. */
  publicUrl: string;
  /** Hosts a client may register an https redirect on. Loopback http is always allowed. */
  redirectHosts: string[];
  pepper: Buffer;
  db: OAuthDb;
  identity: IdentityProvider;
  /** Registrations allowed per address per hour on one instance. */
  registerLimit?: number;
}

const STATE_COOKIE = "__Host-ep_oauth";
const STATE_TTL_MS = 10 * 60 * 1000;
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const CODE = /^epa_[A-Za-z0-9_-]{43}$/;
const REFRESH = /^epr_[A-Za-z0-9_-]{43}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

const b64url = (buf: Buffer) => buf.toString("base64url");
const s256 = (verifier: string) => b64url(createHash("sha256").update(verifier, "ascii").digest());

/** The resource clients ask for: the MCP endpoint. */
export function resourceUrl(publicUrl: string): string {
  return `${publicUrl}/mcp`;
}

/** Where a 401 on /mcp points clients to start sign-in. */
export function resourceMetadataUrl(publicUrl: string): string {
  return `${publicUrl}/.well-known/oauth-protected-resource/mcp`;
}

// ── The in-flight request, carried by the browser ─────────────────────────────

interface LoginState {
  step: "login";
  exp: number;
  clientId: string;
  redirectUri: string;
  state?: string;
  challenge: string;
  scopes: string[];
  idpVerifier: string;
}

interface ChooseState extends Omit<LoginState, "step" | "idpVerifier"> {
  step: "choose";
  userId: string;
  sessionId: string;
  idpToken: string;
  csrf: string;
}

type FlowState = LoginState | ChooseState;

function stateKey(pepper: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", pepper, Buffer.alloc(0), "engramport oauth state v1", 32));
}

/** AES-256-GCM under a key derived from the pepper: unreadable and tamper-evident. */
export function sealState(pepper: Buffer, value: FlowState): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", stateKey(pepper), iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return b64url(Buffer.concat([iv, cipher.getAuthTag(), body]));
}

export function openState(pepper: Buffer, sealed: string | undefined, now = Date.now()): FlowState | undefined {
  if (!sealed || sealed.length > 8192) return undefined;
  try {
    const raw = Buffer.from(sealed, "base64url");
    if (raw.length < 29) return undefined;
    const decipher = createDecipheriv("aes-256-gcm", stateKey(pepper), raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(12, 28));
    const text = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8");
    const value = JSON.parse(text) as FlowState;
    if (typeof value.exp !== "number" || value.exp <= now) return undefined;
    return value;
  } catch {
    return undefined;
  }
}

function readCookie(req: Request, name: string): string | undefined {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

function setStateCookie(res: Response, value: string): void {
  res.append(
    "Set-Cookie",
    `${STATE_COOKIE}=${value}; Path=/; Max-Age=${STATE_TTL_MS / 1000}; HttpOnly; Secure; SameSite=Lax`,
  );
}

function clearStateCookie(res: Response): void {
  res.append("Set-Cookie", `${STATE_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
}

// ── Checks ────────────────────────────────────────────────────────────────────

/**
 * A redirect URI a client may register: https on an allowed host, or http on
 * loopback (native apps and local tools). No credentials, no fragment.
 */
export function redirectAllowed(uri: string, hosts: string[]): boolean {
  if (typeof uri !== "string" || uri.length > 2000 || /[\s\x00-\x1f\x7f#]/.test(uri)) return false;
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.username || url.password) return false;
  if (url.protocol === "http:") return LOOPBACK.has(url.hostname);
  return url.protocol === "https:" && hosts.includes(url.hostname.toLowerCase());
}

/** "read write" → ["read", "write"]; undefined for anything else. Empty means all. */
function parseScope(scope: unknown): string[] | undefined {
  if (scope === undefined || scope === "") return [...OAUTH_SCOPES];
  if (typeof scope !== "string") return undefined;
  const parts = [...new Set(scope.split(" ").filter(Boolean))];
  if (!parts.length || parts.some((s) => !(OAUTH_SCOPES as readonly string[]).includes(s))) return undefined;
  return OAUTH_SCOPES.filter((s) => parts.includes(s));
}

const one = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

type Handler = (req: Request, res: Response) => Promise<unknown>;

/** Express 4 drops a rejected handler on the floor; answer instead of hanging. */
const safe = (fn: Handler) => (req: Request, res: Response) => {
  fn(req, res).catch((err) => {
    console.error("[engramport] oauth error:", (err as Error).message);
    if (!res.headersSent) res.status(503).set("Cache-Control", "no-store").json({ error: "temporarily_unavailable" });
  });
};

interface Trade {
  status: string;
  scopes: string[] | null;
  access_expires_at: Date | null;
}

// ── Pages ─────────────────────────────────────────────────────────────────────

const escape = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

function page(res: Response, status: number, title: string, body: string, formTarget?: string): void {
  // No scripts, no framing, nothing loaded from elsewhere. A form may post here
  // and its redirect may go to the client's own origin.
  res
    .status(status)
    .set({
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy":
        `default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; ` +
        `form-action 'self'${formTarget ? ` ${formTarget}` : ""}`,
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    })
    .send(
      `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
        `<meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)}</title>` +
        `<style>body{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem;color:#1a1a1a}` +
        `label{display:block;padding:.6rem .8rem;border:1px solid #ccc;border-radius:8px;margin:.5rem 0}` +
        `button{font:inherit;padding:.5rem 1.2rem;margin:.5rem .5rem 0 0;border-radius:8px;border:1px solid #888;background:#fff}` +
        `button[value=approve]{background:#1a1a1a;color:#fff}small{color:#555}</style></head>` +
        `<body><h1>${escape(title)}</h1>${body}</body></html>`,
    );
}

/** Back to the client with a result. Only ever to a redirect URI its registration holds. */
function backToClient(res: Response, issuer: string, redirectUri: string, state: string | undefined, params: Record<string, string>) {
  const url = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  if (state !== undefined) url.searchParams.set("state", state);
  url.searchParams.set("iss", issuer);
  res.set("Cache-Control", "no-store").redirect(302, url.toString());
}

// ── The router ────────────────────────────────────────────────────────────────

export function createOAuthRouter(opts: OAuthOptions): Router {
  const issuer = opts.publicUrl;
  const resource = resourceUrl(issuer);
  const hosts = opts.redirectHosts.map((h) => h.toLowerCase());
  const { db, pepper, identity } = opts;
  const hash = (token: string) => hashKey(token, pepper);
  const limit = opts.registerLimit ?? 20;
  const registrations = new Map<string, number[]>();

  const router = express.Router();
  const form = express.urlencoded({ extended: false, limit: "16kb" });

  // ── Discovery ──
  const protectedResource = (_req: Request, res: Response) => {
    res.set("Cache-Control", "public, max-age=3600").json({
      resource,
      authorization_servers: [issuer],
      scopes_supported: OAUTH_SCOPES,
      bearer_methods_supported: ["header"],
      resource_name: "EngramPort",
    });
  };
  router.get("/.well-known/oauth-protected-resource", protectedResource);
  router.get("/.well-known/oauth-protected-resource/mcp", protectedResource);

  router.get("/.well-known/oauth-authorization-server", (_req, res) => {
    res.set("Cache-Control", "public, max-age=3600").json({
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      registration_endpoint: `${issuer}/oauth/register`,
      revocation_endpoint: `${issuer}/oauth/revoke`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      revocation_endpoint_auth_methods_supported: ["none"],
      scopes_supported: OAUTH_SCOPES,
      authorization_response_iss_parameter_supported: true,
    });
  });

  // ── Registration ──
  router.post("/oauth/register", express.json({ limit: "16kb" }), safe(async (req, res) => {
    const fail = (error: string, description: string) =>
      res.status(400).set("Cache-Control", "no-store").json({ error, error_description: description });

    const who = req.ip ?? "unknown";
    const now = Date.now();
    const recent = (registrations.get(who) ?? []).filter((t) => now - t < 3_600_000);
    if (recent.length >= limit) {
      res.status(429).set("Retry-After", "3600").json({ error: "too_many_requests" });
      return;
    }
    if (registrations.size > 10_000) registrations.clear();

    const body = (req.body && typeof req.body === "object" ? req.body : {}) as Record<string, unknown>;
    const uris = body.redirect_uris;
    if (!Array.isArray(uris) || uris.length < 1 || uris.length > 5) {
      return fail("invalid_redirect_uri", "send one to five redirect_uris");
    }
    if (!uris.every((u) => redirectAllowed(u as string, hosts))) {
      return fail("invalid_redirect_uri", "a redirect URI must be https on an allowed host, or http on loopback");
    }
    const name = body.client_name === undefined ? "MCP client" : body.client_name;
    if (typeof name !== "string" || !name.trim() || name.length > 100 || /[\x00-\x1f\x7f]/.test(name)) {
      return fail("invalid_client_metadata", "client_name must be 1 to 100 printable characters");
    }
    if (body.token_endpoint_auth_method !== undefined && body.token_endpoint_auth_method !== "none") {
      return fail("invalid_client_metadata", "only public clients (token_endpoint_auth_method none) are supported");
    }
    const grants = body.grant_types ?? ["authorization_code", "refresh_token"];
    if (!Array.isArray(grants) || !grants.every((g) => g === "authorization_code" || g === "refresh_token")) {
      return fail("invalid_client_metadata", "grant_types may hold authorization_code and refresh_token only");
    }
    const responses = body.response_types ?? ["code"];
    if (!Array.isArray(responses) || !responses.every((r) => r === "code")) {
      return fail("invalid_client_metadata", "response_types may hold code only");
    }

    recent.push(now);
    registrations.set(who, recent);
    const clientId = `epc_${randomBase62(24)}`;
    try {
      const r = await db.query<{ created_at: Date }>(
        "SELECT memory.oauth_register_client($1, $2, $3) AS created_at",
        [clientId, name.trim(), uris],
      );
      res.status(201).set("Cache-Control", "no-store").json({
        client_id: clientId,
        client_id_issued_at: Math.floor(new Date(r.rows[0].created_at).getTime() / 1000),
        client_name: name.trim(),
        redirect_uris: uris,
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      });
    } catch (err) {
      console.error("[engramport] oauth register failed:", (err as Error).message);
      fail("invalid_client_metadata", "the registration was refused");
    }
  }));

  // ── Authorization ──
  router.get("/oauth/authorize", safe(async (req, res) => {
    const q = req.query;
    const clientId = one(q.client_id);
    const redirectUri = one(q.redirect_uri);
    const client = clientId && /^epc_[A-Za-z0-9]{24}$/.test(clientId)
      ? (await db.query<{ client_name: string; redirect_uris: string[] }>(
          "SELECT client_name, redirect_uris FROM memory.oauth_client($1)", [clientId],
        )).rows[0]
      : undefined;
    // Until the redirect is known good, errors stay on this page: sending them
    // to an unchecked address would make this an open redirector.
    if (!client) {
      return page(res, 400, "Unknown app", "<p>This app is not registered with EngramPort. Try connecting again from the app.</p>");
    }
    if (!redirectUri || !client.redirect_uris.includes(redirectUri) || !redirectAllowed(redirectUri, hosts)) {
      return page(res, 400, "Wrong return address", "<p>This app asked to come back to an address it did not register.</p>");
    }
    const state = one(q.state);
    const back = (error: string, description: string) =>
      backToClient(res, issuer, redirectUri, state, { error, error_description: description });
    if (state !== undefined && state.length > 1024) return back("invalid_request", "state is too long");
    if (q.response_type !== "code") return back("unsupported_response_type", "response_type must be code");
    if (q.code_challenge_method !== "S256") return back("invalid_request", "PKCE with S256 is required");
    const challenge = one(q.code_challenge);
    if (!challenge || !CHALLENGE.test(challenge)) return back("invalid_request", "code_challenge is missing or malformed");
    const askedResource = one(q.resource);
    if (askedResource !== undefined && askedResource !== resource) {
      return back("invalid_target", `resource must be ${resource}`);
    }
    const scopes = parseScope(q.scope);
    if (!scopes) return back("invalid_scope", "scope may hold read and write only");

    const idpVerifier = b64url(randomBytes(32));
    setStateCookie(res, sealState(pepper, {
      step: "login",
      exp: Date.now() + STATE_TTL_MS,
      clientId: clientId!,
      redirectUri,
      ...(state !== undefined ? { state } : {}),
      challenge,
      scopes,
      idpVerifier,
    }));
    res.set("Cache-Control", "no-store").redirect(302, identity.signInUrl(s256(idpVerifier), `${issuer}/oauth/callback`));
  }));

  router.get("/oauth/callback", safe(async (req, res) => {
    const flow = openState(pepper, readCookie(req, STATE_COOKIE));
    if (!flow || flow.step !== "login") {
      return page(res, 400, "Sign-in expired", "<p>This sign-in has expired or was opened in another browser. Start again from the app.</p>");
    }
    const code = one(req.query.code);
    if (!code || req.query.error !== undefined) {
      clearStateCookie(res);
      return backToClient(res, issuer, flow.redirectUri, flow.state, {
        error: "access_denied", error_description: "sign-in was cancelled or failed",
      });
    }
    let who: SignedIn;
    try {
      who = await identity.exchange(code, flow.idpVerifier);
    } catch (err) {
      console.error("[engramport] oauth sign-in exchange failed:", (err as Error).message);
      clearStateCookie(res);
      return page(res, 400, "Sign-in failed", "<p>Google sign-in did not complete. Start again from the app.</p>");
    }
    const [client, choices] = await Promise.all([
      db.query<{ client_name: string }>("SELECT client_name FROM memory.oauth_client($1)", [flow.clientId]),
      db.query<{ member_id: string; namespace_path: string; actor_slug: string; scopes: string[] }>(
        "SELECT member_id, namespace_path, actor_slug, scopes FROM memory.oauth_member_choices($1, $2)",
        [who.userId, who.sessionId],
      ),
    ]);
    const csrf = b64url(randomBytes(24));
    setStateCookie(res, sealState(pepper, {
      step: "choose",
      exp: Date.now() + STATE_TTL_MS,
      clientId: flow.clientId,
      redirectUri: flow.redirectUri,
      ...(flow.state !== undefined ? { state: flow.state } : {}),
      challenge: flow.challenge,
      scopes: flow.scopes,
      userId: who.userId,
      sessionId: who.sessionId,
      idpToken: who.accessToken,
      csrf,
    }));

    const app = escape(client.rows[0]?.client_name ?? "An app");
    const host = escape(new URL(flow.redirectUri).host);
    const target = new URL(flow.redirectUri).origin;
    const hidden = `<input type="hidden" name="csrf" value="${csrf}">`;
    if (!choices.rows.length) {
      return page(res, 200, "No access yet",
        `<p>This Google account has no EngramPort access. Ask your EngramPort admin to add you, then connect again.</p>` +
        `<form method="post" action="/oauth/decision">${hidden}<button name="action" value="deny">Go back</button></form>`,
        target);
    }
    const rows = choices.rows.map((c, i) => {
      const can = c.scopes.includes("write") && flow.scopes.includes("write") ? "read and write" : "read";
      return `<label><input type="radio" name="member_id" value="${escape(c.member_id)}"${i === 0 ? " checked" : ""}> ` +
        `<strong>${escape(c.namespace_path)}</strong><br><small>as ${escape(c.actor_slug)}, can ${can}</small></label>`;
    }).join("");
    page(res, 200, "Connect to EngramPort",
      `<p><strong>${app}</strong> wants to use your EngramPort memory. It will return to <strong>${host}</strong>.</p>` +
      `<p>Pick the namespace it may use. It can reach only that one.</p>` +
      `<form method="post" action="/oauth/decision">${hidden}${rows}` +
      `<button name="action" value="approve">Allow</button><button name="action" value="deny">Deny</button></form>`,
      target);
  }));

  router.post("/oauth/decision", form, safe(async (req, res) => {
    const flow = openState(pepper, readCookie(req, STATE_COOKIE));
    const csrf = one(req.body?.csrf) ?? "";
    if (!flow || flow.step !== "choose" || csrf.length !== flow.csrf.length ||
        !timingSafeEqual(Buffer.from(csrf), Buffer.from(flow.csrf))) {
      return page(res, 400, "Sign-in expired", "<p>This sign-in has expired or was opened in another browser. Start again from the app.</p>");
    }
    clearStateCookie(res);
    const done = () => identity.signOut(flow.idpToken).catch(() => undefined);
    const memberId = one(req.body?.member_id);
    if (req.body?.action !== "approve" || !memberId || !UUID.test(memberId)) {
      await done();
      return backToClient(res, issuer, flow.redirectUri, flow.state, {
        error: "access_denied", error_description: "the request was denied",
      });
    }
    // Scopes are what the client asked for, cut down to what the membership has.
    const member = (await db.query<{ scopes: string[] }>(
      "SELECT scopes FROM memory.oauth_member_choices($1, $2) WHERE member_id = $3",
      [flow.userId, flow.sessionId, memberId],
    )).rows[0];
    const scopes = member ? flow.scopes.filter((s) => member.scopes.includes(s)) : [];
    const code = `epa_${b64url(randomBytes(32))}`;
    const issued = scopes.length > 0 && (await db.query<{ ok: boolean }>(
      "SELECT memory.oauth_issue_code($1, $2, $3, $4, $5, $6, $7, $8, $9) AS ok",
      [flow.userId, flow.sessionId, flow.clientId, memberId, flow.redirectUri, flow.challenge, resource, scopes, hash(code)],
    )).rows[0]?.ok === true;
    await done();
    if (!issued) {
      return backToClient(res, issuer, flow.redirectUri, flow.state, {
        error: "access_denied", error_description: "that choice is no longer available; sign in again",
      });
    }
    backToClient(res, issuer, flow.redirectUri, flow.state, { code });
  }));

  // ── Tokens ──
  const tokenError = (res: Response, status: number, error: string, description: string) =>
    res.status(status).set({ "Cache-Control": "no-store", Pragma: "no-cache" }).json({ error, error_description: description });

  router.post("/oauth/token", form, safe(async (req, res) => {
    const b = (req.body ?? {}) as Record<string, unknown>;
    const clientId = one(b.client_id);
    if (!clientId || b.client_secret !== undefined || req.headers.authorization) {
      return tokenError(res, 401, "invalid_client", "public clients send client_id only");
    }
    const asked = one(b.resource);
    if (asked !== undefined && asked !== resource) return tokenError(res, 400, "invalid_target", `resource must be ${resource}`);
    if (b.scope !== undefined && !parseScope(b.scope)) return tokenError(res, 400, "invalid_scope", "scope may hold read and write only");

    const access = mintKey();
    const refresh = `epr_${b64url(randomBytes(32))}`;
    let row: Trade | undefined;
    if (b.grant_type === "authorization_code") {
      const code = one(b.code);
      if (!code || !CODE.test(code)) return tokenError(res, 400, "invalid_grant", "the code is not valid");
      row = (await db.query<Trade>(
        "SELECT status, scopes, access_expires_at FROM memory.oauth_exchange_code($1, $2, $3, $4, $5, $6, $7, $8)",
        [clientId, hash(code), one(b.code_verifier) ?? null, one(b.redirect_uri) ?? null, resource,
          access.prefix, hash(access.key), hash(refresh)],
      )).rows[0];
    } else if (b.grant_type === "refresh_token") {
      const token = one(b.refresh_token);
      if (!token || !REFRESH.test(token)) return tokenError(res, 400, "invalid_grant", "the refresh token is not valid");
      row = (await db.query<Trade>(
        "SELECT status, scopes, access_expires_at FROM memory.oauth_refresh($1, $2, $3, $4, $5, $6)",
        [clientId, hash(token), asked ?? null, access.prefix, hash(access.key), hash(refresh)],
      )).rows[0];
    } else {
      return tokenError(res, 400, "unsupported_grant_type", "use authorization_code or refresh_token");
    }
    if (!row || row.status !== "ok" || !row.access_expires_at) {
      return tokenError(res, 400, "invalid_grant", "the grant is not valid, expired or was revoked");
    }
    res.status(200).set({ "Cache-Control": "no-store", Pragma: "no-cache" }).json({
      access_token: access.key,
      token_type: "Bearer",
      expires_in: Math.max(0, Math.floor((new Date(row.access_expires_at).getTime() - Date.now()) / 1000)),
      refresh_token: refresh,
      scope: (row.scopes ?? []).join(" "),
    });
  }));

  router.post("/oauth/revoke", form, safe(async (req, res) => {
    const b = (req.body ?? {}) as Record<string, unknown>;
    const clientId = one(b.client_id);
    const token = one(b.token);
    if (!clientId) return tokenError(res, 401, "invalid_client", "send client_id");
    // RFC 7009: an unknown or malformed token is not an error.
    if (token) {
      const asKey = parseKey(token);
      if (asKey) {
        await db.query("SELECT memory.oauth_revoke($1, $2, $3)", [clientId, hash(asKey.key), asKey.prefix]);
      } else if (REFRESH.test(token)) {
        await db.query("SELECT memory.oauth_revoke($1, $2, NULL)", [clientId, hash(token)]);
      }
    }
    res.status(200).set("Cache-Control", "no-store").end();
  }));

  return router;
}

// ── Supabase Auth ─────────────────────────────────────────────────────────────

const decodeClaims = (jwt: string): Record<string, unknown> => {
  const part = jwt.split(".")[1];
  if (!part) throw new Error("not a JWT");
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
};

/**
 * Google sign-in through Supabase Auth's PKCE flow, server side. The token
 * comes straight from Supabase over TLS, and the database checks the session
 * it names again (fresh, Google, verified email) before anything is issued.
 */
export function supabaseIdentity(supabaseUrl: string, publishableKey: string): IdentityProvider {
  const base = supabaseUrl.replace(/\/+$/, "");
  const issuer = `${base}/auth/v1`;
  return {
    signInUrl(codeChallenge, returnTo) {
      const url = new URL(`${issuer}/authorize`);
      url.searchParams.set("provider", "google");
      url.searchParams.set("redirect_to", returnTo);
      url.searchParams.set("code_challenge", codeChallenge);
      url.searchParams.set("code_challenge_method", "s256");
      return url.toString();
    },
    async exchange(code, codeVerifier) {
      const res = await fetch(`${issuer}/token?grant_type=pkce`, {
        method: "POST",
        headers: { apikey: publishableKey, "Content-Type": "application/json" },
        body: JSON.stringify({ auth_code: code, code_verifier: codeVerifier }),
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) throw new Error(`Supabase Auth answered ${res.status}`);
      const body = (await res.json()) as { access_token?: string };
      if (!body.access_token) throw new Error("Supabase Auth sent no session");
      const claims = decodeClaims(body.access_token);
      const userId = claims.sub;
      const sessionId = claims.session_id;
      if (claims.iss !== issuer || typeof userId !== "string" || !UUID.test(userId) ||
          typeof sessionId !== "string" || !UUID.test(sessionId)) {
        throw new Error("Supabase Auth sent an unexpected session");
      }
      return { userId, sessionId, accessToken: body.access_token };
    },
    async signOut(accessToken) {
      await fetch(`${issuer}/logout?scope=local`, {
        method: "POST",
        headers: { apikey: publishableKey, Authorization: `Bearer ${accessToken}` },
        signal: AbortSignal.timeout(5_000),
      }).catch(() => undefined);
    },
  };
}
