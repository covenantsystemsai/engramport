# EngramPort pilot stack (founder decision D-06, docs/hosting.md): ECS on
# Fargate behind an Application Load Balancer in us-east-1, with the existing
# Supabase project and AWS Secrets Manager.
#
# Files only. Applying this creates billable AWS resources, and each apply is
# its own founder decision (docs/install.md).

terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # State lives in the bucket made by ../bootstrap, with S3's own locking.
  # Bucket, key and region come from a backend file at init:
  #   terraform init -backend-config=backend.hcl
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  # Only the account named here can be changed, so a wrong profile can't
  # touch another account.
  allowed_account_ids = [var.aws_account_id]

  default_tags {
    tags = {
      Project     = "engramport"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
