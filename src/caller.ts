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

export interface Caller {
  /** The caller's API key, forwarded to the backend as-is. Never logged. */
  apiKey: string;
}

const store = new AsyncLocalStorage<Caller>();
let callerRequired = false;

export function runAsCaller<T>(caller: Caller, fn: () => T): T {
  return store.run(caller, fn);
}

export function currentCaller(): Caller | undefined {
  return store.getStore();
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
