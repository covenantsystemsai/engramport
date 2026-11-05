# Legacy Cloud Run authentication (D-09): review and rollout plan

Status: **proposed change, files and local tests only**. No deployment, release,
IAM write, production configuration change, customer write, or extraction
activation is authorized by this PR. Merging it does not close D-09. The actual
backend gate is Cloud Run IAM and still needs a separate approved change window.

## Evidence and limits (2026-11-05)

- `covenantsystemsai/engramport` main at `dbcd55d` includes merged PR #65.
  Its D-07 guards cover the Postgres write paths; this is not evidence that the
  separate legacy service runs those guards. Keep real customer writes off.
- `src/eidetic.ts` is a client, not the legacy server. All its operations share
  one request function. `src/auth.ts` obtains Google identity tokens from the
  runtime metadata server, then falls back to developer gcloud credentials.
- Hosted MCP binds a request's own application key through `src/caller.ts`.
  The legacy HTTP branch does not validate that key locally: the upstream
  application must validate it and enforce its namespace. The Postgres branch
  uses `store.checkKey` and database row security. Neither is replaced here.
- Separate legacy gateway source was inspected read-only: it forwards caller
  application credentials and replaces the incoming serverless header with
  its own audience-scoped Google token. Thus a legitimate gateway caller may
  have no Google credential of its own. The gateway is a trusted deputy, not
  proof that its caller may read a namespace.
- A local legacy backend source checkout was also inspected read-only. Its
  memory routes use an authentication dependency and namespace checks, with
  a development-only key bypass in the authentication code. Its mapping to
  the live image is unverified. Do not assume that bypass is disabled, that
  all routes are protected, or that revocation is immediate in production.
- Read-only Cloud Run `describe` and `get-iam-policy` attempts failed because
  the saved credentials require reauthentication. No tokens or secret values
  were read into this record. Current service identity, IAM policy, Invoker
  check, traffic, custom domains, serving image and caller inventory remain
  **unknown**, not absent. No live request or customer-data test was made.
- The separate AWS Fargate/Postgres D-06 design and its Terraform are unchanged.
  This repository does not own a verified Cloud Run Terraform state. Do not
  import or recreate the legacy service here as a competing source of truth.

## Enforcement choice: both layers, with different jobs

**Cloud Run Invoker IAM** must guard the legacy backend itself, including its
canonical URL, custom-domain routes and tagged revisions. Require the Invoker
check and remove public invocation grants. Grant `roles/run.invoker` at the
service only to inventoried, owner-approved service identities and any explicit
human maintenance identity. Inspect inherited and custom roles as well. A
Google identity alone does not grant access to customer memory.

**Application authorization** must remain in place behind IAM: validate the
caller's key or supported sign-in token and its namespace/operation permissions.
An approved gateway identity must not substitute its own privileged application
key for the caller's. Do not introduce a blanket browser-login redirect: machine
clients need credential-based requests, not interactive pages. The new Postgres
OAuth and human decision pages are separate from this legacy IAM change.

The gateway's public ingress is a separate service. Do not make it private as
an accidental side effect of hardening the backend: browser clients and other
integrations may depend on it. Conversely, retaining its Invoker grant leaves
its approved API surface reachable through application authentication. If the
owner wants **no access at all** to the old store, that requires a distinct
retirement decision and gateway/client changes, not a claim that IAM alone
achieves retirement.

Google documents the two independent public-access mechanisms: a disabled
Invoker check and an `allUsers` Invoker binding. Address both, and also reject
`allAuthenticatedUsers` as a substitute for a named allowlist.
[Cloud Run access control](https://docs.cloud.google.com/run/docs/securing/managing-access).
Use an ID token for the receiving service audience in
`X-Serverless-Authorization`, preserving the application's own credential.
[Service-to-service authentication](https://docs.cloud.google.com/run/docs/authenticating/service-to-service).

## Code in this PR

- Direct mode is `ENGRAMPORT_LEGACY_AUTH=cloud-run` (the default). If token
  acquisition fails, is empty or produces whitespace, the request is refused
  locally before any backend call. No retry drops authentication, changes
  route, or falls back to a shared server key.
- `ENGRAMPORT_OIDC_AUDIENCE` optionally names the canonical receiving service
  URL when the API URL is a custom domain or tagged address. Otherwise the API
  URL is the audience. Operators must verify the exact accepted audience.
  `prewarm` uses the same audience. Memory/disk cache entries for another
  audience, and disk entries conflicting with a pinned developer identity,
  are not reused. This is cache selection, not local JWT signature verification;
  Cloud Run still verifies the token, expiry and permission.
- `ENGRAMPORT_LEGACY_AUTH=gateway` is an **explicit deployment choice**, only
  for a reviewed HTTPS gateway domain. The client requires the caller's key
  but does not mint or send a Google token; the trusted gateway does that for
  its upstream. Direct `run.app` URLs and invalid modes are rejected. This
  setting is server configuration, never request input. A hostname check does
  not establish gateway ownership: owner verification is mandatory.
- All tool operations require an application key. Redirects are refused in
  both modes so credentials cannot follow to another destination. Upstream
  error bodies are not echoed. The diagnostic `/health` request (`/healthz` in gateway mode) may omit an
  application key; direct mode still needs a Google identity token. A healthy
  diagnostic does not establish namespace authorization.
- No changes to the Postgres default selection, extraction code, write policy,
  migrations, grants, pilot setup or infrastructure definitions.

**Compatibility notice:** callers previously relying on token-mint failure
being ignored now get an explicit error. Before release, classify every caller
as direct or gateway. Configure existing gateway users explicitly; verify
service accounts can mint for the exact audience; preserve approved developer
access. No npm tag/release is part of this work (D-08). Local legacy fixtures
also need a synthetic token provider in tests; there is no anonymous fallback.

On Google Cloud, metadata tokens preserve the existing service-to-service
path. The gcloud fallback is for developers; set `GCLOUD_ACCOUNT` and, if
needed, `GCLOUD_CMD_PATH` explicitly. This PR does not add a new external-cloud
workload federation or service-account impersonation implementation. Such
callers need their existing identity path independently proven before rollout.
[Developer authentication](https://docs.cloud.google.com/run/docs/authenticating/developers).

## Identity and authorization matrix

All identities below are roles to inventory, **not new grants**. Exact emails,
principal IDs, secrets and production policy snapshots belong in a private
operator record, not this public repository.

| Caller/path | Cloud Run credential | Application credential/authority | Expected result after approved rollout |
| --- | --- | --- | --- |
| Anonymous direct caller | None | None or API key alone | Denied by IAM before application |
| Google identity without Invoker permission | Valid ID token | Any | Denied by IAM |
| Approved service account, direct | ID token for receiving service + service Invoker | Caller key limited to required namespace/operation | Allowed only within that scope |
| Approved service account without valid caller key | Valid ID token + Invoker | Missing, unknown, expired or revoked key | Memory API denied by application |
| Approved service account, wrong namespace | Valid ID token + Invoker | Valid key for a different namespace | Denied/no other namespace data |
| Approved human maintenance caller | Developer ID token + explicit effective Invoker | Separate scoped application credential | Allowed within approved maintenance scope; no new human authority |
| Existing gateway client | No Google token required at client | Valid supported application credential | Gateway invokes as its approved service account; backend still checks caller |
| Anonymous/forged-key gateway client | Gateway's own Google token upstream | Missing/invalid caller credential | Memory API denied even though gateway passes IAM |
| Incoming forged serverless header | Replaced by trusted client/gateway token | Still needs caller key | Cannot nominate a privileged upstream identity |
| Browser user / callback / signed webhook | Existing gateway route, if approved | Route-specific validated identity/signature | Inventory and test separately; do not convert to interactive login |
| Health probes | Platform probe or approved monitoring identity as applicable | No memory access | Preserve platform health; unauthenticated external direct calls denied |
| New Postgres MCP or human approval pages | Outside this legacy Cloud Run boundary | Existing OAuth/key, RLS and accepted human authority | Unchanged; no new authority or activation |

## Operator preflight — read only, still required

1. Resolve exact project, region and service from the current inventory, not
   this document. Resolve gateway, domain mappings, traffic tags and any load
   balancer/IAP route. Match each serving image digest to its source. Verify
   the legacy application validates credentials in every memory route and
   debug bypass is off. If unavailable, stop the rollout.
2. Capture a timestamped private baseline: service IAM with version, conditions
   and etag; Invoker-check setting; inherited/custom permissions; exact traffic,
   revisions, image digests, ingress, scaling and pause state. Read only selected
   service fields; don't export secret environment values into a PR or log.
3. Record every caller's owner, source, runtime identity, target route,
   canonical audience, application auth type, namespace, read/write needs,
   revocation behavior and a synthetic regression case. Logs establish observed
   callers only; dormant schedulers, gateways and webhooks require an owner
   inventory too. No observed calls does not prove no dependencies.
4. Resolve each matrix row to an explicit approved principal or an intentional
   denial. Check IAM groups, inherited broad roles and custom roles containing
   `run.routes.invoke`; service-only policy reads are not effective-access proof.
5. Check the existing IaC/deployment owner. Encode the reviewed IAM delta there
   if it is authoritative. Preserve unrelated bindings and their conditions;
   do not install a blanket replacement policy from this repository.
6. Rehearse all positive and negative cases on an isolated synthetic service.
   Do not reactivate a paused production backend to run tests.

Read-only command shapes (operator supplies verified values; not run by tests):

```sh
gcloud run services describe "$LEGACY_SERVICE" \
  --project="$LEGACY_PROJECT" --region="$LEGACY_REGION" \
  --format='json(metadata.name,metadata.annotations,status.url,status.traffic,status.latestReadyRevisionName,spec.template.spec.serviceAccountName,spec.template.metadata.annotations)'
gcloud run services get-iam-policy "$LEGACY_SERVICE" \
  --project="$LEGACY_PROJECT" --region="$LEGACY_REGION" --format=json
```

## Proposed rollout — separate founder approval required; NOT executed

1. Approve the exact target, caller allowlist, synthetic test scope, operator,
   bounded UTC window, rollback owner and outage threshold. Approve client
   release/configuration separately. Customer writes stay off throughout.
2. Re-read the baseline immediately before changing anything. Stop on drift.
   Ensure each approved direct caller and gateway already has the necessary
   effective Invoker permission; add only missing, explicitly approved
   service-scoped grants. Check the application's auth on the isolated rehearsal.
3. Enable the Invoker check and remove public grants on the **backend**.
   These are the intended command shapes for an authorized operator, not an
   executable script or authorization to run them:

   ```sh
   gcloud run services update "$LEGACY_SERVICE" \
     --project="$LEGACY_PROJECT" --region="$LEGACY_REGION" --invoker-iam-check
   # For an observed unconditional public Invoker binding only:
   gcloud run services remove-iam-policy-binding "$LEGACY_SERVICE" \
     --project="$LEGACY_PROJECT" --region="$LEGACY_REGION" \
     --member=allUsers --role=roles/run.invoker --condition=None
   gcloud run services remove-iam-policy-binding "$LEGACY_SERVICE" \
     --project="$LEGACY_PROJECT" --region="$LEGACY_REGION" \
     --member=allAuthenticatedUsers --role=roles/run.invoker --condition=None
   ```

   Do not run a removal for a binding that is absent. Conditional public
   bindings and other roles granting invocation need their own exact reviewed
   removal; these example commands do not cover them. Require the IAM check
   enabled AND no public effective invocation permission as the postcondition.
   Do not change image, traffic, scaling, ingress, secrets or gateway policy.
4. Re-read policy and service state. Compare traffic, digests and pause state
   with baseline. IAM applies across service revisions: a no-traffic revision
   alone cannot stage this access change. Test both direct and gateway paths
   under the separately approved synthetic scope. If the service is paused,
   keep it paused; IAM configuration evidence alone is not execution proof.
5. Observe sanitized auth-failure rates and owner-confirmed caller success.
   Record time, route class, synthetic test ID, expected/observed status and
   denial layer, never tokens, keys, bodies or customer identifiers. Mark D-09
   enforcement verified only after the exact rollout matrix passes.

## Rollback / containment

On any unexpected denial of an approved caller, unexpected success of a denied
caller, unrelated configuration drift, or inability to verify the result: halt
rollout and keep customer writes off. Preserve the current pause state. Prefer
fixing an explicitly approved missing Invoker binding or reverting the client
version/configuration while **retaining** the backend IAM gate. Never retry by
stripping a credential, enabling debug mode, changing a caller to gateway mode
without review, or substituting a founder key.

A revision rollback does not restore IAM. If a policy reversal is necessary,
compare fresh state with the private baseline and reverse only this change's
reviewed delta, preserving intervening legitimate changes, conditions and
concurrency controls. Restoring public access or disabling the Invoker check
would reopen the exposure and needs a new explicit founder decision; it is
not an automatic rollback. No broad `set-iam-policy` snapshot overwrite.

## Access regression plan and evidence levels

Local automated tests in this PR use synthetic data and fake token/fetch
providers, plus the existing local HTTP tests. They verify request refusal,
credential separation, explicit gateway behavior, caller isolation, all legacy
client entry points, no redirect following, no anonymous retry after 401/403,
sanitized upstream failures, audience cache separation and the diagnostic path.
They do **not** verify Google signatures, live IAM, the separate gateway's
runtime, or legacy tenant enforcement.

Before rollout, run the following against an isolated service with the real
Cloud Run gate and the exact application image, then the separately authorized
production synthetic check. Record expected and actual results for each:

| Case | Required outcome |
| --- | --- |
| No credentials; application key only; forged Google token; expired Google token; Google access token instead of ID token; wrong audience | Rejected at direct IAM gate; no application data or write |
| Valid Google token without effective Invoker permission | Rejected at IAM gate |
| Approved service identity + valid scoped application key | Synthetic own-namespace read succeeds; write only in isolated fixture |
| Approved Google identity + missing, malformed, revoked or expired application credential | Memory route denied by application; no rows changed |
| Valid caller key requesting another namespace via direct URL, gateway, download/export or resumed request | Denied/no other namespace content; same result after retries |
| Gateway missing/invalid key, spoofed serverless header, or invalid user sign-in token | Application denies memory access; gateway IAM grant does not bypass it |
| Unknown or removed service identity; IAM/identity provider unavailable | Denial/failure, no anonymous fallback |
| Revocation after an initial successful call | Denial within documented, owner-approved cache interval; record measured delay |
| Canonical URL, custom domain and every traffic-tag URL | Same required gate; no alternate-route bypass |
| Existing browser, signed webhook, scheduler and monitoring paths | Their approved credential flow works without a surprise login redirect |
| Redirect returned by legacy endpoint | Client fails without following or leaking credentials |
| New Postgres HTTP/OAuth and D-02–D-07 suites | Existing authorization and governance tests still pass |

## Owner decisions still needed

1. Exact live service/source/IaC owner, and whether it is paused; who can refresh
   read-only access and supply private evidence (saved credentials expired here).
2. Named Invoker allowlist, removal of inherited/broad access if present, and
   whether the gateway remains an approved legacy entry point or is retired.
3. Caller-by-caller direct/gateway mode and canonical audience, external-cloud
   identity solution where needed, and migration/release coordination under D-08.
4. Whether route-specific public signup/docs/webhook capabilities are retained;
   required application sign-in/key/signature rules, debug-off proof and accepted
   revocation interval. This PR grants no exception to memory authorization.
5. Isolated test environment, independent reviewer, rollout operator/window,
   rollback owner, outage threshold and explicit live change approval.
6. Formal recording of the proposed D-01 Max policy below; no activation.

## Max pilot extraction — proposed D-01 policy record

Founder preference received 2026-11-05: **automatic extraction = NONE** for the
Max pilot. Proposed policy: no automatic entity/relation extraction, no provider
selection, no extraction worker/schedule or activation. Revisit only with a
separate scoped proposal and founder decision. This records the preference as
proposed policy, not as evidence that an existing deployment has been inspected
or configured. Existing explicitly asserted `link` behavior is unchanged and
is not authorization to enable customer writes.

D-02 erasure/export/retention, D-03 human approval authority, D-04 proposal-based
supersession, D-05 files-only preparation, D-06 AWS hosting and D-07 never-store
enforcement and review gates all stand. No sign-in or Invoker grant creates
approval, erasure, export, restore or customer-write authority.
