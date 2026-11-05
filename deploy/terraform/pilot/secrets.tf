# The server's three secrets. Terraform makes each one's name and who may read
# it, never its value: a person sets each value once, outside Terraform
# (docs/install.md), so values never appear in this repository, in a plan or
# in Terraform state. The task fails to start until all three are set.

locals {
  secrets = {
    database_url = {
      env         = "ENGRAMPORT_DATABASE_URL"
      description = "EngramPort app role connection string, through Supabase's session-mode pooler"
    }
    key_pepper = {
      env         = "ENGRAMPORT_KEY_PEPPER"
      description = "EngramPort key pepper. Never rotate casually; an offline copy is kept by the founder"
    }
    embed_secret = {
      env         = "ENGRAMPORT_EMBED_SECRET"
      description = "Shared secret of the Supabase embed Edge Function"
    }
  }
}

resource "aws_secretsmanager_secret" "server" {
  # checkov:skip=CKV2_AWS_57:Rotation is a person's step. The key pepper must never rotate on a schedule (it would invalidate every API key), the database password is rotated by hand with a redeploy, and the embed secret changes together with the Edge Function's.
  for_each                = local.secrets
  name                    = "engramport/${var.environment}/${replace(each.key, "_", "-")}"
  kms_key_id              = aws_kms_key.stack.arn
  description             = each.value.description
  recovery_window_in_days = 30
}
