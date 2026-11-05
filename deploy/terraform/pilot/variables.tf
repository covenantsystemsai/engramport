variable "aws_account_id" {
  description = "The one AWS account this stack may change."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id is the 12-digit account id."
  }
}

variable "region" {
  description = "AWS region. D-06 puts the server next to the Supabase project, in us-east-1."
  type        = string
  default     = "us-east-1"
  validation {
    condition     = var.region == "us-east-1"
    error_message = "D-06 chose us-east-1, next to the Supabase project. Changing it is a new decision."
  }
}

variable "environment" {
  description = "Short environment name used in resource names, such as pilot."
  type        = string
  default     = "pilot"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,15}$", var.environment))
    error_message = "environment is 2 to 16 lowercase letters, digits or hyphens, starting with a letter."
  }
}

variable "image" {
  description = "The server image in this stack's ECR repository, pinned by digest: <account>.dkr.ecr.us-east-1.amazonaws.com/engramport-<env>@sha256:<64 hex>."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}\\.dkr\\.ecr\\.us-east-1\\.amazonaws\\.com/[a-z0-9-]+@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image must be an ECR image in us-east-1 pinned by digest (@sha256:...), never a tag."
  }
}

variable "certificate_arn" {
  description = "ACM certificate for the EngramPort domain, issued and validated in us-east-1 before apply."
  type        = string
  validation {
    condition     = can(regex("^arn:aws:acm:us-east-1:[0-9]{12}:certificate/[0-9a-f-]{36}$", var.certificate_arn))
    error_message = "certificate_arn is an ACM certificate ARN in us-east-1."
  }
}

variable "public_access" {
  description = "Whether the load balancer is reachable from the internet. Off until the founder decides to open it (docs/hosting.md, Before real customer data)."
  type        = bool
  default     = false
}

variable "internal_ingress_cidrs" {
  description = "While the load balancer is internal, the address ranges that may reach it. Defaults to the VPC itself."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for c in var.internal_ingress_cidrs : can(cidrhost(c, 0)) && c != "0.0.0.0/0"])
    error_message = "internal_ingress_cidrs are CIDR ranges, never 0.0.0.0/0; use public_access for that."
  }
}

variable "vpc_cidr" {
  description = "Address range of the stack's VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "desired_count" {
  description = "How many server tasks run. One for the pilot; two spread across both zones."
  type        = number
  default     = 1
  validation {
    condition     = var.desired_count >= 1 && var.desired_count <= 4
    error_message = "desired_count is between 1 and 4. More than one task should come with WAF (enable_waf), because rate limits are per task."
  }
}

variable "task_cpu" {
  description = "CPU units per task (512 = 0.5 vCPU)."
  type        = number
  default     = 512
}

variable "task_memory" {
  description = "Memory per task in MiB."
  type        = number
  default     = 1024
}

variable "enable_waf" {
  description = "Attach AWS WAF with managed rules and a per-address rate rule. Deferred for the pilot; required before public access, a second task or real customer data (docs/hosting.md)."
  type        = bool
  default     = false
}

variable "waf_rate_limit" {
  description = "Requests per 5 minutes from one address before WAF blocks it, when WAF is on."
  type        = number
  default     = 2000
}

variable "enable_flow_logs" {
  description = "Record VPC flow logs (addresses and ports only, no content) in CloudWatch."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "How long the server's and the flow logs are kept. The server logs no memory text."
  type        = number
  default     = 365
}

variable "alarm_email" {
  description = "Where alarms are sent. Empty means alarms are created but nobody is told, so set it before real customer data."
  type        = string
  default     = ""
}

variable "monthly_budget_usd" {
  description = "Monthly AWS cost that triggers a budget alert to alarm_email."
  type        = number
  default     = 150
}

# ── Server settings that are not secrets (deploy/engramport.env.example) ────

variable "public_url" {
  description = "ENGRAMPORT_PUBLIC_URL: https://<domain>, nothing after the host."
  type        = string
  validation {
    condition     = can(regex("^https://[a-z0-9.-]+$", var.public_url))
    error_message = "public_url is https:// and a host name, with no path or trailing slash."
  }
}

variable "supabase_url" {
  description = "ENGRAMPORT_SUPABASE_URL: https://<project ref>.supabase.co"
  type        = string
  validation {
    condition     = can(regex("^https://[a-z0-9]+\\.supabase\\.co$", var.supabase_url))
    error_message = "supabase_url is https://<project ref>.supabase.co"
  }
}

variable "supabase_publishable_key" {
  description = "ENGRAMPORT_SUPABASE_PUBLISHABLE_KEY: public by design, so configuration rather than a secret."
  type        = string
}

variable "embed_url" {
  description = "ENGRAMPORT_EMBED_URL: the embed Edge Function, https://<project ref>.supabase.co/functions/v1/embed"
  type        = string
  validation {
    condition     = can(regex("^https://[a-z0-9]+\\.supabase\\.co/functions/v1/embed$", var.embed_url))
    error_message = "embed_url is the project's embed function over https."
  }
}

variable "oauth_redirect_hosts" {
  description = "ENGRAMPORT_OAUTH_REDIRECT_HOSTS: MCP clients allowed to receive OAuth codes. Add a client only after its live test."
  type        = list(string)
  default     = ["claude.ai", "claude.com"]
}

variable "pages" {
  description = "Which pages are on. Each is off until its own decision."
  type = object({
    approval     = optional(bool, false)
    erasure      = optional(bool, false)
    export       = optional(bool, false)
    restore      = optional(bool, false)
    cell_erasure = optional(bool, false)
    accept       = optional(bool, false)
    grant        = optional(bool, false)
  })
  default = {}
}
