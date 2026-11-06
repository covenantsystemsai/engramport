/** Legacy transport only. Cloud Run verifies Google tokens; the backend
 * verifies the caller key and namespace. Neither credential replaces the other.
 * See docs/legacy-cloud-run-auth.md for the separate IAM rollout gate.
 */
import { getIdToken } from "./auth.js";
import { configProblems, type Config } from "./config.js";

export async function legacyFetch(
  cfg: Config,
  url: string,
  init: RequestInit,
  deps: { fetchImpl?: typeof fetch; idToken?: typeof getIdToken } = {},
  requireKey = true,
): Promise<Response> {
  // Validate here as well as at startup: direct callers/tests cannot bypass it.
  if (cfg.store !== "eidetic" || configProblems(cfg).length) {
    throw new Error("Invalid legacy backend configuration; run engramport doctor.");
  }
  if (new URL(url).origin !== new URL(cfg.apiUrl).origin) {
    throw new Error("Legacy request must stay on the configured backend origin.");
  }
  const headers = new Headers(init.headers);
  if (requireKey && !headers.get("X-API-Key")?.trim()) {
    throw new Error("Legacy backend requires the caller's API key.");
  }
  // Never trust an incoming serverless header or switch modes after a failure.
  headers.delete("X-Serverless-Authorization");
  if (cfg.legacyAuth === "cloud-run") {
    let token: string;
    try {
      token = await (deps.idToken ?? getIdToken)(cfg.oidcAudience || cfg.apiUrl);
    } catch {
      throw new Error("Legacy Cloud Run identity unavailable; no request sent.");
    }
    if (!token?.trim() || /\s/.test(token)) {
      throw new Error("No Cloud Run ID token available; no request sent. Check the approved service identity or developer sign-in; see docs/legacy-cloud-run-auth.md.");
    }
    headers.set("X-Serverless-Authorization", `Bearer ${token}`);
  }
  // Redirects must not carry an API key or Google token to another destination.
  return (deps.fetchImpl ?? fetch)(url, { ...init, headers, redirect: "error" });
}
