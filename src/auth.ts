/**
 * EngramPort — Cloud Run OIDC token mint.
 *
 * Ports the five Python fixes from
 * C:\Users\j_dev\genesis\mcp-servers\personal-engramport\server.py
 * into TypeScript so the hosted (or local) EngramPort can clear Cloud Run's
 * auth gate when calling Eidetic V3.
 *
 *   1. Absolute path resolution for gcloud (probe well-known install paths,
 *      env override via GCLOUD_CMD_PATH, PATH fallback).
 *   2. Async subprocess via child_process.spawn with Promise + timeout,
 *      SIGTERM then SIGKILL escalation.
 *   3. Inline Promise mutex serializes concurrent mints, with
 *      double-checked locking against caches.
 *   4. GCLOUD_ACCOUNT identity pin via --account flag; JWT email decoded
 *      after mint and logged for diagnostic visibility.
 *   5. stdin: 'ignore' (gcloud cannot block on inherited stdin); cross-process
 *      disk cache at ~/.engramport/oidc_token.json (50min default TTL);
 *      prewarmToken() CLI populates the cache from a working shell.
 *
 * No --audiences flag — required by SA creds, rejected by user creds. The
 * plain user token's audience (gcloud OAuth client ID) is accepted by
 * Cloud Run when the identity has roles/run.invoker.
 */

import { spawn } from "child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { homedir } from "os";
import { dirname, join, sep } from "path";

// ── Config (read once at module load) ─────────────────────────────────────────

const GCLOUD_ACCOUNT = process.env.GCLOUD_ACCOUNT || "";
const GCLOUD_CMD_PATH_OVERRIDE = process.env.GCLOUD_CMD_PATH || "";
const TOKEN_CACHE_PATH =
  process.env.OIDC_TOKEN_CACHE_PATH ||
  join(homedir(), ".engramport", "oidc_token.json");
const TOKEN_TTL_MS =
  (parseInt(process.env.OIDC_TOKEN_TTL_MINUTES || "50", 10) || 50) * 60 * 1000;
const MINT_TIMEOUT_MS = 10_000;

// Probe order for gcloud binary: env override, well-known Windows install paths,
// well-known Linux container paths, PATH fallback.
const GCLOUD_CANDIDATES: string[] = [
  GCLOUD_CMD_PATH_OVERRIDE,
  "C:\\Program Files (x86)\\Google\\Cloud SDK\\google-cloud-sdk\\bin\\gcloud.cmd",
  "C:\\Program Files\\Google\\Cloud SDK\\google-cloud-sdk\\bin\\gcloud.cmd",
  process.env.LOCALAPPDATA
    ? join(process.env.LOCALAPPDATA, "Google", "Cloud SDK", "google-cloud-sdk", "bin", "gcloud.cmd")
    : "",
  "/usr/local/google-cloud-sdk/bin/gcloud",
  "/google-cloud-sdk/bin/gcloud",
  "/usr/lib/google-cloud-sdk/bin/gcloud",
  "gcloud.cmd",
  "gcloud",
].filter(Boolean);

let resolvedGcloudPath: string | null = null;

function resolveGcloud(): string {
  if (resolvedGcloudPath !== null) return resolvedGcloudPath;
  for (const cand of GCLOUD_CANDIDATES) {
    const isAbsolute = cand.includes(sep) || cand.includes("/");
    if (isAbsolute) {
      if (existsSync(cand)) {
        resolvedGcloudPath = cand;
        return cand;
      }
    } else {
      // PATH-relative; let the spawn attempt resolve via PATH.
      resolvedGcloudPath = cand;
      return cand;
    }
  }
  resolvedGcloudPath = "";
  return "";
}

function log(msg: string): void {
  const ts = new Date().toISOString().replace(/\.\d+Z$/, "Z");
  process.stderr.write(`[engramport-mcp ${ts}] ${msg}\n`);
}

// ── Inline Promise mutex (no async-mutex dependency) ──────────────────────────

class Mutex {
  private locked = false;
  private waiters: Array<() => void> = [];

  async acquire(): Promise<() => void> {
    if (this.locked) {
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    this.locked = true;
    return () => {
      this.locked = false;
      const next = this.waiters.shift();
      if (next) next();
    };
  }
}

const mintMutex = new Mutex();

// ── Cache state ───────────────────────────────────────────────────────────────

interface CacheEntry {
  token: string;
  identity: string;
  expiresAt: number; // epoch millis
}

interface DiskCacheRecord {
  token: string;
  identity: string;
  audience: string;
  minted_at: string;
  expires_at: number; // epoch millis
}

let memoryCache: CacheEntry | null = null;

function decodeJwtEmail(token: string): string {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return "?";
    const padded = parts[1] + "=".repeat((4 - (parts[1].length % 4)) % 4);
    const payload = JSON.parse(
      Buffer.from(padded, "base64url").toString("utf-8"),
    ) as Record<string, unknown>;
    const email = (payload.email as string) || (payload.sub as string) || "?";
    return String(email);
  } catch {
    return "?";
  }
}

function readDiskCache(): CacheEntry | null {
  try {
    if (!existsSync(TOKEN_CACHE_PATH)) return null;
    const raw = readFileSync(TOKEN_CACHE_PATH, "utf-8");
    const rec = JSON.parse(raw) as DiskCacheRecord;
    if (!rec.token || typeof rec.expires_at !== "number") return null;
    if (rec.expires_at <= Date.now() + 60_000) return null; // require 1min slack
    return { token: rec.token, identity: rec.identity, expiresAt: rec.expires_at };
  } catch {
    return null;
  }
}

function writeDiskCache(token: string, identity: string, audience: string): void {
  try {
    mkdirSync(dirname(TOKEN_CACHE_PATH), { recursive: true });
    const rec: DiskCacheRecord = {
      token,
      identity,
      audience,
      minted_at: new Date().toISOString(),
      expires_at: Date.now() + TOKEN_TTL_MS,
    };
    writeFileSync(TOKEN_CACHE_PATH, JSON.stringify(rec, null, 2), "utf-8");
  } catch (err) {
    log(`could not write token cache file ${TOKEN_CACHE_PATH}: ${String(err)}`);
  }
}

// ── Subprocess: spawn gcloud, timeout-safe, stdin=ignore ──────────────────────

function spawnGcloud(gcloud: string, args: string[]): Promise<{
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}> {
  return new Promise((resolve) => {
    // Windows .cmd/.bat scripts cannot be spawned directly by Node without
    // shell mediation: spawn() returns EINVAL. Route through the shell in
    // that case. The gcloud binary path may contain spaces (Program Files);
    // quote it explicitly when passing as a shell command.
    const isWindowsScript = /\.(cmd|bat)$/i.test(gcloud) && process.platform === "win32";

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    let proc: ReturnType<typeof spawn>;
    try {
      if (isWindowsScript) {
        const cmdline = [`"${gcloud}"`, ...args].join(" ");
        proc = spawn(cmdline, {
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
          shell: true,
        });
      } else {
        proc = spawn(gcloud, args, {
          stdio: ["ignore", "pipe", "pipe"],
          windowsHide: true,
        });
      }
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      resolve({ code: null, stdout: "", stderr: `[spawn threw] ${e.code || ""} ${e.message}`, timedOut: false });
      return;
    }

    proc.stdout?.on("data", (d: Buffer) => {
      stdout += d.toString("utf-8");
    });
    proc.stderr?.on("data", (d: Buffer) => {
      stderr += d.toString("utf-8");
    });

    const timer = setTimeout(() => {
      timedOut = true;
      try {
        proc.kill("SIGTERM");
      } catch {
        /* noop */
      }
      setTimeout(() => {
        try {
          if (proc.exitCode === null) proc.kill("SIGKILL");
        } catch {
          /* noop */
        }
      }, 1_000);
    }, MINT_TIMEOUT_MS);

    const done = (code: number | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut });
    };

    proc.on("error", (err: NodeJS.ErrnoException) => {
      stderr += `\n[spawn error] ${err.code || ""} ${err.message}`;
      done(null);
    });
    proc.on("exit", (code) => done(code));
  });
}

// ── Mint: GCE/Cloud Run metadata server (primary, production) ─────────────────
// On Cloud Run the container's service account identity is available via the
// metadata server, audience-scoped, with no gcloud install required. This
// mirrors the pattern in runtime/eidetic_client.py used by genesis-runtime.
// Off-cloud the metadata host is unreachable; the AbortSignal.timeout fast-fails
// in ~1.5s and we fall through to the gcloud subprocess path.

async function fetchTokenFromMetadataServer(audience: string): Promise<string> {
  try {
    const url =
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity" +
      `?audience=${encodeURIComponent(audience)}`;
    const res = await fetch(url, {
      headers: { "Metadata-Flavor": "Google" },
      signal: AbortSignal.timeout(1500),
    });
    if (!res.ok) {
      log(`metadata server returned ${res.status}; falling through to gcloud`);
      return "";
    }
    const tok = (await res.text()).trim();
    if (!tok) return "";
    log(`OIDC token from GCE metadata server (length ${tok.length}, audience=${audience})`);
    return tok;
  } catch {
    // Not on Cloud Run, or metadata host unreachable. Silent fall-through.
    return "";
  }
}

// ── Mint: gcloud subprocess (fallback, local dev) ─────────────────────────────

async function mintIdToken(audience: string): Promise<string> {
  // Primary: GCE/Cloud Run metadata server. Works in-cluster; fast-fails off-cloud.
  const fromMeta = await fetchTokenFromMetadataServer(audience);
  if (fromMeta) {
    const identity = decodeJwtEmail(fromMeta);
    memoryCache = { token: fromMeta, identity, expiresAt: Date.now() + TOKEN_TTL_MS };
    writeDiskCache(fromMeta, identity, audience);
    return fromMeta;
  }

  const gcloud = resolveGcloud();
  if (!gcloud) {
    log("no gcloud binary found in any candidate path; requests will go without OIDC and likely 403");
    return "";
  }

  const args = ["auth", "print-identity-token"];
  if (GCLOUD_ACCOUNT) {
    args.push(`--account=${GCLOUD_ACCOUNT}`);
    log(`minting OIDC token via ${gcloud} pinned to account=${GCLOUD_ACCOUNT}`);
  } else {
    log(
      `minting OIDC token via ${gcloud} (NO account pin; using gcloud's active account). ` +
        `Set GCLOUD_ACCOUNT env var to pin identity explicitly.`,
    );
  }

  const result = await spawnGcloud(gcloud, args);

  if (result.timedOut) {
    log(`gcloud token mint hit ${MINT_TIMEOUT_MS}ms timeout; subprocess killed`);
    return "";
  }
  if (result.code !== 0) {
    log(`gcloud failed rc=${result.code}: ${JSON.stringify(result.stderr.slice(0, 300))}`);
    return "";
  }
  const tok = result.stdout.trim();
  if (!tok) {
    log("gcloud returned 0 but stdout was empty");
    return "";
  }
  const identity = decodeJwtEmail(tok);
  const expiresAt = Date.now() + TOKEN_TTL_MS;
  memoryCache = { token: tok, identity, expiresAt };
  writeDiskCache(tok, identity, audience);
  log(`OIDC token minted ok (length ${tok.length}, identity=${identity})`);
  return tok;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Get a Cloud Run OIDC identity token. Three-layer resolution:
 *   1. in-memory cache (warm, same process)
 *   2. cross-process disk cache (warm, survives restarts; populatable from terminal)
 *   3. gcloud subprocess (cold path; populates both caches)
 *
 * Returns empty string on failure. Callers should still proceed to the HTTP
 * request so the 403 surfaces visibly rather than silently swallowing.
 *
 * The `audience` argument is recorded in the disk cache for diagnostic purposes
 * but is intentionally NOT passed to gcloud (--audiences requires SA creds and
 * rejects user creds). The plain user token works because Cloud Run accepts
 * tokens whose audience is the gcloud OAuth client ID when the identity has
 * invoker permission on the target service.
 */
export async function getIdToken(audience: string): Promise<string> {
  // Layer 1
  if (memoryCache && memoryCache.expiresAt > Date.now() + 60_000) {
    return memoryCache.token;
  }
  // Layer 2
  const fromDisk = readDiskCache();
  if (fromDisk) {
    memoryCache = fromDisk;
    log(`loaded OIDC token from disk cache (identity=${fromDisk.identity})`);
    return fromDisk.token;
  }
  // Layer 3 (serialized)
  const release = await mintMutex.acquire();
  try {
    if (memoryCache && memoryCache.expiresAt > Date.now() + 60_000) {
      return memoryCache.token;
    }
    const recheck = readDiskCache();
    if (recheck) {
      memoryCache = recheck;
      return recheck.token;
    }
    return await mintIdToken(audience);
  } finally {
    release();
  }
}

/**
 * CLI: pre-mint an OIDC token from a working shell context and write to the
 * cross-process cache. Use periodically from a terminal where gcloud works
 * cleanly; the hosted server then reads the disk cache and never has to
 * shell out itself.
 */
export async function prewarmToken(audience: string): Promise<number> {
  log("prewarm mode: minting token in this process and writing to disk cache");
  // Force the cold path: skip the cache layers entirely.
  const tok = await mintIdToken(audience);
  if (!tok) {
    log("prewarm FAILED: gcloud subprocess returned no token");
    return 1;
  }
  const identity = decodeJwtEmail(tok);
  process.stdout.write(
    `OK: minted OIDC token (identity=${identity}, cache file=${TOKEN_CACHE_PATH})\n`,
  );
  return 0;
}
