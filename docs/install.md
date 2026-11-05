# Installing the Max pilot, and checking each step

The order of every step from these files to a running Max pilot cell, and the
check that shows each one worked. The design behind it is in
`docs/hosting.md` (founder decision D-06); the Terraform is described in
`deploy/terraform/README.md`.

Nothing in this guide has been done. Writing these files completes none of the
steps, and a finished install does not by itself qualify EngramPort for real
customer data: that needs every control in `docs/hosting.md`, "Before real
customer data".

Each step is marked:

- **Local**: runs on a laptop or in CI, touches nothing live.
- **Yes**: changes a live system or spends money, and waits for the
  founder's own yes to that step. A yes to one step is not a yes to the next.

If a check fails, stop there. Fix forward in a reviewed pull request; don't
loosen a check to get past it.

## What you need

- An AWS account for EngramPort, with an administrator who can use it from the
  command line (AWS CLI v2, signed in through IAM Identity Center, not with
  long-lived access keys).
- Terraform 1.10 or later, Docker with `buildx` able to build `linux/arm64`,
  Node 22, and `psql`.
- The Supabase project `engramport-memory` (us-east-1) and its database
  owner's connection string, kept in a password manager, never in a file in
  the repository.
- A domain for the server, such as `memory.<company domain>`, whose DNS you
  control.

## 1. Check the repository (Local)

```bash
npm ci
npx tsc --noEmit -p .
npm test
ENGRAMPORT_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:5432/engramport_test npm run test:store
DATABASE_URL=postgres://postgres@127.0.0.1:5432/engramport_sql_test bash db/test/run.sh
terraform -chdir=deploy/terraform fmt -check -recursive
```

Check: every command exits 0. The store and SQL suites need a local Postgres
with pgvector; they never touch Supabase. On the pull request, the Terraform
workflow also runs `terraform validate` on both stacks and a Checkov scan with
0 failures.

## 2. Build the image (Local)

1. Download Supabase's CA certificate into `deploy/certs/supabase-ca.crt`
   (`deploy/certs/README.md`). It is public, so commit it in its own pull
   request.
2. Build for Graviton, from a clean checkout of the reviewed commit:

   ```bash
   docker buildx build --platform linux/arm64 -t engramport:$(git rev-parse --short HEAD) --load .
   docker run --rm engramport:$(git rev-parse --short HEAD) node -e "console.log(process.getuid())"
   ```

Check: the build finishes, and the second command prints `1000`, not `0`. The
image holds `dist/`, production `node_modules`, `package.json` and
`deploy/certs/`, and nothing else from the repository.

## 3. The Terraform state bucket (Yes)

Creates one S3 bucket in the AWS account. Applied once, by a person.

```bash
cd deploy/terraform/bootstrap
terraform init
terraform plan -out=bootstrap.plan -var aws_account_id=<account id>
terraform apply bootstrap.plan
```

Check: the plan creates only the bucket and its settings (versioning,
encryption, public access block, TLS-only policy, lifecycle). Copy
`pilot/backend.hcl.example` to `pilot/backend.hcl` (ignored by git) with the
bucket's name.

## 4. The certificate (Yes)

Request a certificate for the server's domain in AWS Certificate Manager, in
us-east-1, with DNS validation, and add the validation record at your DNS
provider.

Check: `aws acm describe-certificate --certificate-arn <arn> --query Certificate.Status`
prints `ISSUED`. Put the ARN in `terraform.tfvars` as `certificate_arn`.

## 5. The database (Yes)

1. Review migrations `0002` to `0027` as one set. Apply them to
   `engramport-memory` as the database owner:

   ```bash
   DATABASE_URL='<owner connection string>' db/migrate.sh
   ```

   The script applies each file once, in order, in its own transaction, and
   stops if a file applied earlier has changed.
2. Deploy the `embed` Edge Function and set its shared secret
   (`docs/embeddings.md`, steps 1 and 2).

Check:

- `select version from engramport_meta.schema_migrations order by version;`
  lists `0001` to `0027`.
- `select to_regprocedure('memory.offer_data_grant(uuid,uuid,uuid,text,memory.data_power,timestamptz)');`
  is not null.
- Supabase's security and performance advisors show no new warnings.
- `engramport admin embedding models` (step 10's settings) lists `gte-small`.

## 6. The stack (Yes)

Copy `pilot/terraform.tfvars.example` to `pilot/terraform.tfvars` (ignored by
git) and fill it in. Leave `public_access = false`, `enable_waf = false`,
`desired_count = 1` and every page `false`: each is its own decision.

The service needs an image digest, and the image needs the repository, so the
repository goes first:

```bash
cd deploy/terraform/pilot
terraform init -backend-config=backend.hcl
terraform plan -out=ecr.plan -target=aws_ecr_repository.server
terraform apply ecr.plan
```

That plan also makes the key the repository is encrypted with, and nothing
else. Push the image built in step 2 and take its digest:

```bash
tag=$(git rev-parse --short HEAD)
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account id>.dkr.ecr.us-east-1.amazonaws.com
docker tag engramport:$tag <repository url>:$tag
docker push <repository url>:$tag
aws ecr describe-images --repository-name engramport-pilot --image-ids imageTag=$tag --query 'imageDetails[0].imageDigest'
```

Set `image` in `terraform.tfvars` to `<repository url>@<digest>`. Then:

```bash
terraform plan -out=pilot.plan
terraform apply pilot.plan
```

Commit the `.terraform.lock.hcl` the first `init` wrote, in its own pull
request.

Check:

- The plan was read in full before applying. It creates no internet-facing
  load balancer, no WAF, and nothing outside us-east-1.
- `terraform output load_balancer_internal` is `true`.
- `terraform output secret_names` lists three secrets, still empty.

The tasks can't start yet: their secrets have no values. That is expected,
and the "no healthy task" alarm will say so until step 7.

## 7. The secrets (Yes)

A person sets the three values. Nothing prints them, and they never pass
through a chat, a ticket or the repository.

| Secret | Value |
|---|---|
| `engramport/pilot/database-url` | The `engramport_app` role's connection string through Supabase's session-mode pooler. Never the `postgres` or service role |
| `engramport/pilot/key-pepper` | At least 32 random bytes, such as `openssl rand -hex 32` |
| `engramport/pilot/embed-secret` | The same secret set on the `embed` function in step 5 |

Set each from a file only you can read, then delete the file:

```bash
umask 077
openssl rand -hex 32 > pepper.txt
aws secretsmanager put-secret-value --secret-id engramport/pilot/key-pepper --secret-string file://pepper.txt
```

Make the pepper's offline copy before deleting `pepper.txt`, and keep it where
the founder keeps the erasure ledger (`docs/hosting.md`, "Backup and
restore"). API keys are stored only as hashes peppered with it, so losing it
means minting every key again.

Then restart the service so its tasks read the values:

```bash
aws ecs update-service --cluster <cluster_name> --service <service_name> --force-new-deployment
```

Check:

- `aws ecs describe-services --cluster <cluster_name> --services <service_name> --query 'services[0].[runningCount,deployments[0].rolloutState]'`
  shows `1` and `COMPLETED`.
- The target group shows one healthy target.
- The log group shows the server's start line and no setting's value.

## 8. Reach it, privately (Local to your network)

The load balancer is internal: only addresses in `internal_ingress_cidrs` can
reach it, such as an office network or VPN joined to the VPC. That network is
outside these files. From inside it:

```bash
curl -fsS https://<domain>/health
curl -fsS https://<domain>/.well-known/oauth-authorization-server
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<domain>/mcp
curl -sI https://<domain>/health | grep -i strict-transport-security
```

Check: `/health` answers, the metadata names `https://<domain>` endpoints,
`/mcp` with no key answers `401`, and the HSTS header is there. Plain `http://`
redirects to `https://`.

## 9. Sign-in (Yes)

Follow `docs/oauth-setup.md`, steps 1 to 3. In Supabase's redirect URLs add
only `https://<domain>/oauth/callback`. Each page's callback is added on the
day that page is turned on, not before.

Check: `docs/oauth-setup.md`, "Check the first sign-in", done by the founder
with their own Google account on a test namespace. Revoke that test
membership afterwards.

## 10. The Max cell (Yes, twice)

The setup script makes everything one pilot cell needs, from a config file,
in one transaction. It runs as the `engramport_admin` role, which can't read
memory content.

1. Copy `deploy/pilot/pilot.example.json` to a new file in `deploy/pilot/`
   (ignored by git) and fill in the real names. The cell's names and the
   owner's email are the founder's to choose.
2. Set the admin settings for this shell only:

   ```bash
   export ENGRAMPORT_ADMIN_DATABASE_URL='<a login granted SET on engramport_admin>'
   export ENGRAMPORT_DATABASE_CA_FILE=deploy/certs/supabase-ca.crt
   export ENGRAMPORT_KEY_PEPPER="$(aws secretsmanager get-secret-value --secret-id engramport/pilot/key-pepper --query SecretString --output text)"
   ```

3. **Dry run** (reads only, in a read-only transaction):

   ```bash
   engramport admin pilot setup --config deploy/pilot/<file>.json --namespace <city/tower/cell>
   ```

   It prints each step it would take and anything that stops it, then exits.
   It refuses if the cell already exists, if its city or tower is a company
   namespace, if any actor name is taken, if a migration is missing, or if
   the embedding model is unknown. Show the founder this output.
4. **Apply**, on the founder's yes to that dry run:

   ```bash
   engramport admin pilot setup --config deploy/pilot/<file>.json --namespace <city/tower/cell> \
     --apply --confirm <city/tower/cell> --keys-out ~/max-keys.jsonl
   ```

   The namespace is typed three times on purpose. The plan is checked again
   inside the transaction, and either everything is made or nothing is. The
   keys go only to the new file, readable by you alone; the command refuses a
   path inside a git working tree or one that already exists.
5. Move each key from the file into the secrets store of the agent that uses
   it, then delete the file.

Check:

```bash
engramport admin namespace list
engramport admin member list --namespace <city/tower/cell>
engramport admin key list --namespace <city/tower/cell>
engramport admin authority list --namespace <city/tower/cell>
```

The cell is a client cell, the owner is its one member, there is one key per
agent with the expiry the config set, and the owner's authority shows
"waiting for the holder to accept". It counts only once the owner accepts it
on the acceptance page with their own Google sign-in, and that page stays off
until its own decision.

## 11. Each agent, live (Yes, one at a time)

For each, connect, write one test memory, read it back, and confirm it can't
see any other namespace. Then retract the test memory.

| Agent | How it connects | Reachable while the load balancer is internal |
|---|---|---|
| Claude Code, Codex, Grok Bot, an AN2X agent | `https://<domain>/mcp` with its key in the `X-API-Key` header | Yes, from inside the private network |
| claude.ai | Custom connector, Google sign-in (`docs/oauth-setup.md`, step 5) | No: needs public access |
| ChatGPT | MCP connector with Google sign-in, after its host is added to `ENGRAMPORT_OAUTH_REDIRECT_HOSTS` once its live test is approved | No: needs public access |

Check: `engramport admin audit --namespace <city/tower/cell>` shows each write
with the right actor, client and tool, and nothing from any other namespace.

## Turning more on

Each is one reviewed change and its own yes, in this order, with the
controls in `docs/hosting.md`, "Before real customer data":

1. WAF: `enable_waf = true`. It keeps metrics only, never a request log.
2. Public access: `public_access = true`, a DNS record for the domain, and
   claude.ai and ChatGPT tested.
3. Each page, with its callback added to Supabase's redirect URLs first.
4. A second task (`desired_count = 2`), after WAF is on.

## Undoing a step

- A failed pilot setup changed nothing; fix the config and run the dry run
  again.
- A key that leaked: `engramport admin key revoke <prefix>`, then mint a new
  one.
- The stack: `terraform destroy` removes it, but the load balancer has
  deletion protection and the secrets have a recovery window, both on purpose.
  The database is untouched.
- Migrations are forward-only. A mistake is fixed by a new migration.
