/**
 * Per-request caller identity for the hosted server.
 *
 * In HTTP mode every request carries the caller's own key, and that key (not a
 * server-wide one) is what reaches the backend. The key travels through the
 * request's async context, so tool code needs no extra parameters and two
 * concurrent callers can never see each other's key.
 *
 * Fail closed: once the hosted server marks a caller as required, a backend
 * call with no caller in context throws instead of falling back to the
 * server's own ENGRAMPORT_API_KEY.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";

export interface Caller {
  /** The caller's API key, forwarded to the backend as-is. Never logged. */
  apiKey: string;
  /**
   * This HTTP request's id: the client's X-Request-Id when it is well formed,
   * otherwise one the server made. Stored with every write's provenance and
   * returned in the response, so a write can be traced to one request.
   */
  requestId?: string;
}

const store = new AsyncLocalStorage<Caller>();
let callerRequired = false;

export function runAsCaller<T>(caller: Caller, fn: () => T): T {
  return store.run(caller, fn);
}

export function currentCaller(): Caller | undefined {
  return store.getStore();
}

/** The current request's id, or undefined outside an HTTP request (stdio). */
export function currentRequestId(): string | undefined {
  return store.getStore()?.requestId;
}

const REQUEST_ID = /^[A-Za-z0-9._:-]{8,128}$/;

/**
 * The id to use for a request: the client's X-Request-Id when it is 8 to 128
 * plain characters (letters, digits, . _ : -), so a client can match its own
 * logs to ours; anything else is replaced by a fresh random id, so a header
 * can never put arbitrary text into logs or provenance.
 */
export function requestIdFromHeaders(headers: Record<string, string | string[] | undefined>): string {
  const raw = headers["x-request-id"];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return value && REQUEST_ID.test(value) ? value : randomUUID();
}

/** Hosted mode calls this once at startup; stdio mode never does. */
export function setCallerRequired(required: boolean): void {
  callerRequired = required;
}

/**
 * The key to send to the backend for the current call: the caller's key when
 * there is one, the configured key only when no caller is required (stdio).
 */
export function backendKey(configuredKey: string): string {
  const caller = store.getStore();
  if (caller) return caller.apiKey;
  if (callerRequired) {
    throw new Error("No authenticated caller for this request");
  }
  return configuredKey;
}

const MAX_KEY_LENGTH = 512;

/**
 * Pull the caller's key from a request's headers. MCP clients send
 * `Authorization: Bearer <key>`; REST bots may send `X-API-Key: <key>`.
 * Returns undefined for a missing or malformed credential.
 */
export function keyFromHeaders(headers: Record<string, string | string[] | undefined>): string | undefined {
  const auth = headers["authorization"];
  const authValue = Array.isArray(auth) ? auth[0] : auth;
  let key: string | undefined;
  if (authValue) {
    const match = /^Bearer\s+(\S+)\s*$/i.exec(authValue);
    if (!match) return undefined;
    key = match[1];
  } else {
    const raw = headers["x-api-key"];
    key = (Array.isArray(raw) ? raw[0] : raw)?.trim();
  }
  if (!key || key.length > MAX_KEY_LENGTH || /\s/.test(key)) return undefined;
  return key;
}
