# Hosting: ECS Fargate behind an Application Load Balancer

Founder decision D-06 (Nov 5, 2026): the EngramPort server runs on Amazon ECS
with Fargate, behind an Application Load Balancer, in us-east-1. Data stays on
the existing Supabase project (Postgres, pgvector, graph tables, RLS, Supabase
Auth, the `embed` Edge Function). Secrets live in AWS Secrets Manager.

This document is the design the deploy files follow. It is not a deployment.
Nothing in it has been provisioned, and having it, or the files that follow
it, does not qualify EngramPort for production. Each step that touches a live
system (creating AWS resources, applying migrations, setting secrets, opening
public access, connecting Max) is its own founder decision.

The comparison behind the decision, with the other options and their limits, is
in the D-06 decision document. In short: App Runner no longer takes new
customers; Lambda and Supabase Edge Functions cut long MCP sessions and
exports short; Cloud Run and Fly.io are not AWS-first.

## The pieces

```
 clients (Claude, ChatGPT, Codex, AN2X agents, people's browsers)
   │ HTTPS 443, TLS 1.2+ (TLS 1.3 preferred)
   ▼
 Application Load Balancer  (us-east-1, two zones; internal until public access is decided)
   │ HTTP 8080 inside the VPC, only from the load balancer's security group
   ▼
 ECS service on Fargate (Graviton, 0.5 vCPU / 1 GB per task; one task for the pilot)
   │ outbound HTTPS only, through a NAT gateway
   ▼
 Supabase project engramport-memory (us-east-1)
   ├─ Postgres via the session-mode pooler, TLS verified against Supabase's CA
   ├─ Supabase Auth (Google sign-in exchange)
   └─ embed Edge Function (gte-small)
```

- **Network.** One VPC with two public subnets (load balancer, NAT gateway)
  and two private subnets (tasks) across two availability zones. Tasks have no
  public address. Their security group admits port 8080 from the load
  balancer's security group and nothing else. Outbound is HTTPS to the
  internet through one NAT gateway, which is how tasks reach Supabase, Secrets
  Manager, ECR and CloudWatch.
- **Load balancer.** HTTPS listener on 443 with an ACM certificate for the
  EngramPort domain and a TLS 1.3 policy. Port 80 redirects to 443. The
  listener adds `Strict-Transport-Security` and removes the `Server` header.
  Deletion protection on. Access logs off: they record every full URL,
  including the one-time codes on sign-in callbacks, which the server itself
  never logs. Turned on only for an investigation, to an encrypted bucket that
  keeps them a few days.
- **Public access is off by default.** The Terraform builds an internal load
  balancer unless a variable says otherwise. Turning it internet-facing is the
  step that makes EngramPort reachable by Claude and the other clients, and it
  waits for its own founder decision (see "Before real customer data").
- **Compute.** One ECS service. The image comes from ECR, pinned by digest,
  never `latest`. The container runs as a non-root user with a read-only root
  filesystem, no added Linux capabilities, and ECS Exec turned off.
- **Data.** Unchanged. The server connects to Postgres through Supabase's
  session-mode pooler, which reaches IPv4 from AWS at no extra cost. The direct
  connection is IPv6 only, so it would need Supabase's IPv4 add-on (about $4 a
  month). Supabase PrivateLink exists but only on the Team plan and above, and
  covers the database only.
- **Infrastructure as code.** Terraform, version-pinned, runnable under
  OpenTofu. State is kept in a versioned, encrypted S3 bucket with public
  access blocked. Every resource is in a reviewable file.

## HTTPS

- TLS ends at the load balancer with an ACM certificate (free, renewed by
  AWS). The security policy allows TLS 1.2 and 1.3 only.
- Inside the VPC, the load balancer reaches tasks over HTTP on a private
  subnet that nothing else can reach. Encrypting that hop as well is possible
  later with a certificate in the container; it is not needed for the pilot.
- The server's own links and cookies already assume HTTPS: `ENGRAMPORT_PUBLIC_URL`
  must be `https://`, every page cookie is `__Host-` prefixed and `Secure`,
  and the embed URL must be `https://`.
- To the database: TLS with the certificate verified against Supabase's CA,
  shipped in the image and named by `ENGRAMPORT_DATABASE_CA_FILE`.

## MCP streaming

- `/mcp` is MCP's streamable HTTP transport in stateless mode with JSON
  responses: each request stands alone, so any task can answer it and the load
  balancer needs no sticky sessions. `GET` and `DELETE` on `/mcp` answer 405,
  because stateless mode has no server-initiated stream.
- `/stream` is a server-sent-events stream that sends a keep-alive every 30
  seconds.
- Owner exports stream rows for up to minutes.
- The load balancer's idle timeout is raised from 60 to 300 seconds, so a slow
  tool call, the event stream and an export are not cut while they wait. The
  target group's deregistration delay is 60 seconds, so a task being replaced
  finishes what it is serving.
- Database calls stay bounded: 15 seconds per statement, 120 seconds for an
  export's.
- Claude, ChatGPT, Codex and AN2X agents all connect to one remote MCP
  endpoint, `https://<domain>/mcp`, with OAuth. None has been tried live yet.
  Each is a verification step in the install guide, done only after public
  access is approved.

## Sessions

The server keeps no session in memory, so tasks can be added, replaced or
restarted without losing anyone's place.

- MCP: stateless; each request carries its key or OAuth access token.
- OAuth: registered clients, codes, access and refresh tokens are rows in
  Postgres (`memory.oauth_*`), not memory.
- Pages (sign-in, approval, erasure, export, restore, whole-cell erasure,
  accept, grant): each visit lives in its own encrypted, signed, ten-minute
  cookie, sealed with a key derived from `ENGRAMPORT_KEY_PEPPER`. Every task
  holds the same pepper, so any task can serve any step of a visit.
- Rate limits are kept in each task's memory. With one task that is exact.
  With more, each caller's limit multiplies by the number of tasks, so an edge
  rate limit (WAF) belongs with scaling out.
- `trust proxy` is set to exactly one hop, the load balancer, so the address
  rate limits use is the client's and can't be spoofed with a forged header.

## OAuth callbacks

People sign in with Google through Supabase Auth. Once the domain is chosen:

- `ENGRAMPORT_PUBLIC_URL` is `https://<domain>`.
- In Supabase, **Authentication** > **URL Configuration** > **Redirect URLs**
  lists, written out in full with no wildcard, `https://<domain>/oauth/callback`
  plus the callback of each page that is turned on: `/approve/callback`,
  `/erase/callback`, `/export/callback`, `/restore/callback`,
  `/cell-erasure/callback`, `/accept/callback`, `/grant/callback`.
- `ENGRAMPORT_OAUTH_REDIRECT_HOSTS` names the MCP clients allowed to receive
  OAuth codes. It defaults to `claude.ai,claude.com`. ChatGPT, Codex and AN2X
  each need their exact redirect host added, checked during their live tests;
  nothing else is accepted.
- Every page stays off until its own `ENGRAMPORT_*_PAGE=true` is set.

Details: `docs/oauth-setup.md`.

## Restarts and deploys

- **Health.** The target group checks `GET /health` every 15 seconds: 2
  passes make a task healthy, 3 failures make it unhealthy, and ECS replaces
  it. `/health` reveals nothing beyond the service name, version and "ok".
- **Deploys.** Rolling, with minimum healthy 100% and maximum 200%: the new
  task must pass its health checks before the old one is drained. The ECS
  deployment circuit breaker rolls back a deploy whose tasks keep failing.
- **Stopping.** ECS sends `SIGTERM`, waits up to 30 seconds, then stops the
  task. On `SIGTERM` the server stops taking connections, lets requests in
  flight finish for up to 25 seconds, closes its database pool and exits
  (`src/shutdown.ts`). A
  request still running at the deadline, such as a very long export, is cut;
  the person starts it again. Single-use sign-ins and challenges mean a cut
  decision is never half-applied: each decision is one database transaction.
- **Crashes.** An unhandled error in one request is logged and the process
  stays up. If the process dies, ECS starts a new task, and the load balancer
  sends traffic only once it passes health checks.
- **One task.** For the pilot, a restart means a short gap while the new task
  starts (under a minute). Two tasks across two zones remove the gap; it is a
  one-line change and about $14 more a month.

## Secrets isolation

| Secret | Holds | Who can read it |
|---|---|---|
| `engramport/<env>/database-url` | The app role's Postgres connection string | The task, at start |
| `engramport/<env>/key-pepper` | The pepper API keys and page cookies are sealed with | The task, at start |
| `engramport/<env>/embed-secret` | The shared secret for the `embed` function | The task, at start |

- Terraform creates each secret's name and access policy, never its value.
  A person sets each value once, outside Terraform, so values never appear in
  the repository, in plans or in Terraform state.
- Only the task's execution role may read them, scoped to exactly these three
  secrets. The task's own role has no AWS permissions at all: the server needs
  none at run time.
- Values reach the container as environment variables at start. They are not
  in the image, the task definition, logs or `/health`. The server logs one
  line per request (id, method, route, status, time) and never a key, a body,
  a query string or memory text.
- Secrets, log groups and the alarm topic are encrypted with one
  customer-managed KMS key for the stack ($1 a month, rotated yearly). Its key
  policy lets CloudWatch Logs use it only for this stack's log groups and
  CloudWatch alarms only to publish to the alarm topic. The execution role
  may decrypt with it only through Secrets Manager.
- The Supabase URL and publishable key are configuration, not secrets: the
  publishable key is public by design.
- **The key pepper is never rotated casually.** Every API key is stored only
  as a peppered hash, and every page visit is sealed with it, so a new pepper
  invalidates every key. Keep an offline copy, held by the founder, outside
  AWS. Rotating the database password is routine: set the new value, then
  force a new deployment.

## Monthly cost (Max pilot, us-east-1)

List prices checked Nov 5, 2026, before free credits and tax. Light pilot
traffic.

| Item | Rate | One task | Two tasks |
|---|---|---|---|
| Fargate, Graviton, 0.5 vCPU and 1 GB per task | $0.03238 per vCPU-hour, $0.00356 per GB-hour | $14.40 | $28.80 |
| Application Load Balancer | $0.0225 an hour plus $0.008 per capacity unit-hour | $17 to $20 | $17 to $20 |
| NAT gateway | $0.045 an hour plus $0.045 per GB through it | $33 to $34 | $33 to $34 |
| Public IPv4 addresses (NAT gateway; load balancer in two zones once public) | $0.005 an hour each | $3.65 now, $11 once public | $3.65 now, $11 once public |
| Secrets Manager, 3 secrets, and the stack's KMS key | $0.40 each a month; $1 for the key | $2.20 | $2.20 |
| CloudWatch logs and alarms | $0.50 per GB ingested; first 5 GB and 10 alarms free | $0 to $3 | $0 to $3 |
| ECR image storage, S3 state, Route 53 zone | | about $1 | about $1 |
| **AWS subtotal** | | **about $73 to $84** | **about $87 to $99** |
| Supabase Pro (includes Micro compute) | $25, or $30 with Small compute | $25 to $30 | $25 to $30 |
| **Total** | | **about $98 to $114** | **about $112 to $129** |

Optional, not included:

- Supabase point-in-time recovery, 7 days: $100 a month. Required before real
  customer data (below).
- AWS WAF with managed rules and a rate rule: about $8 to $10 a month plus
  $0.60 per million requests. Deferred (below).
- Supabase IPv4 add-on, only if direct database connections are wanted: about
  $4 a month.
- Placing tasks in public subnets with public addresses instead of the NAT
  gateway saves about $30 a month. It is not the default, because it gives
  every task a public address.
- AWS data transfer out: the first 100 GB a month are free, then $0.09 per GB.
- Supabase egress: 250 GB included on Pro.

An AWS Budgets alert at $150 a month is part of the Terraform, so a surprise
shows up in days, not on the bill.

## Backup and restore

What must hold before real customer data, and how a restore runs.

- **The database is the only state.** Tasks, the load balancer and the image
  can be rebuilt from the repository and the pinned image digest.
- **Supabase backups.** Pro keeps daily backups for 7 days. That allows losing
  up to a day of memory. Point-in-time recovery (7 days, $100 a month) cuts
  that to minutes and is required before real customer data.
- **Erasures survive a restore.** A restored database brings back text erased
  after the backup was taken. Before the restored database serves anyone, the
  database owner reapplies every erasure and whole-cell erasure from the ledger
  kept outside the database. Steps: `docs/erasure.md`, "Restoring from a
  backup". Keep that ledger export current (ids and times only) wherever the
  founder keeps the pepper's offline copy.
- **Erased text can remain in Supabase's own backups** for up to their
  retention period, because single rows can't be removed from them. That is
  said plainly, as D-02 requires; nothing more is claimed.
- **A restore drill comes first.** Before real customer data: restore a backup
  into a separate development project, reapply the ledger, check the counts,
  and record how long it took. That time is the recovery time objective until
  measured again.
- **Secrets.** Secrets Manager keeps a deleted secret recoverable for 7 to 30
  days. The pepper's offline copy is what makes a lost AWS account
  recoverable.
- **Terraform state.** Versioned S3 bucket, so an earlier state can be
  recovered.

## WAF is deferred, with a trigger

AWS WAF is not in the first files. It is the edge filter for managed rule
sets (common exploits, known bad inputs, IP reputation) and a per-address
rate rule. While the load balancer is internal and one task runs, it protects
nothing that isn't already covered: the server's own per-key and per-address
rate limits, size limits, and refusal of anything without a valid key, token
or fresh sign-in.

It is turned on, before or together with whichever comes first:

- the load balancer becoming internet-facing;
- a second task, when in-memory rate limits stop being exact;
- real customer data.

The Terraform will carry it behind a variable, off by default, so turning it
on is one reviewed change.

## Before real customer data

Each is its own step, and each needs the founder's yes. Building the deploy
files completes none of them.

1. **Never-store policy (D-09)** written and approved, so what Max must never
   store is a written rule before anything is stored.
2. **Migrations.** The remaining migrations (0002 to 0027) reviewed and
   applied to `engramport-memory`, with Supabase's security and performance
   advisors clean afterwards.
3. **Secrets.** The three values set in Secrets Manager by a person; the
   pepper's offline copy made.
4. **Backups.** Point-in-time recovery on; a restore drill done, with erasures
   reapplied, and its time recorded.
5. **Edge protection.** WAF on with managed rules and a rate rule.
6. **Monitoring.** Alarms on 5xx rate, unhealthy tasks and task restarts,
   sent to someone who will act on them; the budget alert on.
7. **Public access.** The load balancer made internet-facing, with the domain,
   certificate and Supabase redirect URLs in place.
8. **Live checks.** Real Google sign-in through Supabase; connections from
   Claude, ChatGPT, Codex and an AN2X agent, each reading and writing only its
   own namespace; each page tried once on a test namespace.
9. **The old backend.** Authentication required on the old eidetic-v3 service
   (D-07), so nothing reaches the old store.
10. **Repository.** Branch protection on `main`.
11. **Max.** The Max city and cell created and keys minted by the setup
    script, run in dry-run first, then for real, on its own yes.

Supabase Pro does not include a SOC 2 report; the Team plan does. That matters
for a customer's security review, not for the pilot.

## What comes next in files

In separate pull requests, each locally validated and independently reviewed:

1. Container (done): the `Dockerfile`, `.dockerignore`, graceful shutdown on
   `SIGTERM`, `deploy/engramport.env.example` naming every setting with no
   secret values, and `deploy/certs/` for Supabase's CA certificate. See
   "The container" below.
2. Terraform (done): `deploy/terraform/`, with public access and WAF off by
   default. See `deploy/terraform/README.md`.
3. The Max pilot setup script (done): `engramport admin pilot setup`, a dry
   run by default, scoped to one named namespace, fail-closed, with the
   install and verification guide in `docs/install.md`.

## The container

- `Dockerfile`: two stages. The first runs `npm ci` and the TypeScript build,
  then drops development packages; the second carries only `package.json`,
  `node_modules` and `dist`, plus `deploy/certs/`. The Node 22 base image is
  pinned by digest, a multi-architecture index, so the same pin builds for
  Graviton (arm64). The image runs as the `node` user; every file in it is
  owned by root, so the server can't change its own code.
- `.dockerignore` lets in only `package.json`, `package-lock.json`,
  `tsconfig.json`, `src/` and `deploy/certs/`. Any `.env` file, the tests, the
  docs and the database folder stay out of the build.
- `deploy/engramport.env.example` names every production setting, which ones
  come from Secrets Manager, and every page left off.
- `deploy/certs/README.md` says where to get Supabase's CA certificate. If it
  is missing or wrong, the server can't connect and the task never becomes
  healthy: it fails closed.
- Missing or invalid settings stop the server at start with exit code 1 and a
  message naming each one.

Checked locally (Nov 5, 2026) on an x86 build: the image runs with a
read-only root filesystem, `/tmp` as a scratch mount, every Linux capability
dropped and no new privileges; `/health` answers 200; `/mcp` refuses a missing
or unknown key with 401 after a real database lookup; `docker stop` ends it in
under a second with exit code 0, "stopped cleanly" and its database
connection closed; no key appears in its logs. An arm64 build is part of the
install guide.
