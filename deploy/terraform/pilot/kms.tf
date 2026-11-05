# One customer-managed key for the stack ($1 a month), rotated yearly. It
# encrypts the three secrets, the log groups and the alarm topic, with a key
# policy that names exactly which AWS services may use it, and for what.
# (CloudWatch alarms can't publish to a topic encrypted with AWS's own SNS
# key, so the topic needs this one.)

data "aws_iam_policy_document" "kms" {
  # checkov:skip=CKV_AWS_111:In a key policy, "*" means this key only. The account statement is AWS's default for every key, so IAM, not the key, decides who in the account may use it.
  # checkov:skip=CKV_AWS_356:Same: a key policy's resource is always "*", meaning this key.
  # checkov:skip=CKV_AWS_109:Same: without the account statement nobody could ever manage or delete the key.
  statement {
    sid       = "AccountAdministers"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }
  }

  statement {
    sid       = "CloudWatchLogsEncryptsThisStacksLogs"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values = [
        "arn:aws:logs:${var.region}:${var.aws_account_id}:log-group:/engramport/${var.environment}/*",
        "arn:aws:logs:${var.region}:${var.aws_account_id}:log-group:aws-waf-logs-${local.name}",
      ]
    }
  }

  statement {
    sid       = "CloudWatchAlarmsPublishToTheAlarmTopic"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
  }
}

resource "aws_kms_key" "stack" {
  description             = "EngramPort ${var.environment}: secrets, logs and alarms"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "stack" {
  name          = "alias/${local.name}"
  target_key_id = aws_kms_key.stack.key_id
}
