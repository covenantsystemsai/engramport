# EngramPort deploy files: Terraform

The infrastructure for founder decision D-06 (`docs/hosting.md`): Amazon ECS
on Fargate behind an Application Load Balancer in us-east-1, with the existing
Supabase project and AWS Secrets Manager.

These are files only. Nothing here has been applied. Every `terraform apply`
creates or changes billable AWS resources and is its own founder decision;
the order of steps and their checks is in `docs/install.md`.

## Layout

| Folder | What it makes |
|---|---|
| `bootstrap/` | The S3 bucket for Terraform state: versioned, KMS-encrypted, private, TLS only, protected from deletion. Applied once. |
| `pilot/` | The stack itself. |

`pilot/` holds:

| File | What it makes |
|---|---|
| `network.tf` | VPC over two zones; public subnets for the NAT gateway (and the load balancer once public); private subnets for the tasks; one NAT gateway; a closed default security group; security groups that let only the load balancer reach the tasks and let tasks out only on 443 and 5432; VPC flow logs |
| `alb.tf` | The load balancer: internal unless `public_access`, TLS 1.2/1.3 policy, HTTP to HTTPS redirect, HSTS and `nosniff` added, `Server` header removed, invalid headers dropped, idle timeout 300 s, deletion protection, access logs off; the target group with `/health` checks |
| `ecs.tf` | The cluster, task definition (Graviton, read-only root, user 1000, all capabilities dropped, `/tmp` scratch mount, init process, 30 s stop timeout) and service (private subnets, no public address, rolling deploy with circuit breaker and rollback, ECS Exec off) |
| `iam.tf` | The execution role (pull this image, write this log group, read these three secrets, decrypt only through Secrets Manager) and the task role (no permissions) |
| `secrets.tf` | The three secrets' names and access, never their values |
| `kms.tf` | One customer-managed key for secrets, logs and the alarm topic, rotated yearly |
| `ecr.tf` | The image repository: immutable tags, scan on push, KMS-encrypted, last 20 images kept |
| `monitoring.tf` | Alarm topic, alarms (no healthy task, server 5xx, load balancer 5xx), monthly budget alert |
| `waf.tf` | AWS WAF with AWS managed rules and a per-address rate rule, metrics only: no request log, which would copy keys, sign-in codes and memory text; off unless `enable_waf` |
| `outputs.tf` | The load balancer's address, the repository URL, the secret names, the NAT address |

## Guard rails in the files

- `allowed_account_ids`: a plan or apply against any other AWS account fails.
- `region` must be us-east-1, as D-06 decided.
- `image` must be an ECR image pinned by `@sha256:` digest; a tag is refused.
- `public_access` defaults to `false`; `internal_ingress_cidrs` can never be
  `0.0.0.0/0`.
- `desired_count` is 1 to 4.
- Secrets have names in Terraform and values only in Secrets Manager.
- `*.tfvars`, `backend.hcl` and state files are ignored by git.

## Checks

| Check | Where |
|---|---|
| `terraform fmt -check -recursive` | Locally and in CI (`.github/workflows/terraform.yml`) |
| `terraform init -backend=false` and `terraform validate`, each stack | CI only: the provider registry isn't reachable from the sandbox these files were written in |
| Checkov security scan, 0 failures | Locally and in CI. Each finding left as is is skipped in the file, next to the resource, with its reason |

The first `terraform init` against the real backend writes
`.terraform.lock.hcl`, which pins the AWS provider's exact version and hashes.
Commit it in that change.
