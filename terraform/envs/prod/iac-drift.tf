# ADR-0035 â€” read-only OIDC role for the iac-additive-guard.
#
# Plans terraform/envs/prod on PRs (and is available for a future drift
# detector) under a scoped plan policy + tfstate read. Trust gates assume-role
# on this repo's GitHub OIDC for the default branch (master) and the iac-plan
# GitHub Environment (human-gated — requires reviewer approval before the
# environment is entered, so fork PRs cannot auto-assume the role).
# Created out-of-band 2026-06-05 (platform #280) and imported here so it is
# Terraform-managed.

resource "aws_iam_role" "iac_drift" {
  name               = "carto-iac-drift"
  assume_role_policy = data.aws_iam_policy_document.iac_drift_trust.json
  description        = "Read-only OIDC role for the ADR-0035 iac-additive-guard (plan PR branches). Trusts master + iac-plan environment (human-gated)."
}

data "aws_iam_policy_document" "iac_drift_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:oidc-provider/token.actions.githubusercontent.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:jaetill/carto:ref:refs/heads/master",
        "repo:jaetill/carto:environment:iac-plan",
      ]
    }
  }
}

data "aws_iam_policy_document" "iac_drift_plan" {
  statement {
    sid    = "IAMRead"
    effect = "Allow"
    actions = [
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:ListRolePolicies",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "LambdaRead"
    effect = "Allow"
    actions = [
      "lambda:GetFunction",
      "lambda:GetPolicy",
    ]
    resources = [
      "arn:aws:lambda:${var.aws_region}:${var.aws_account_id}:function:cartoApi",
      "arn:aws:lambda:${var.aws_region}:${var.aws_account_id}:function:carto-feedback",
    ]
  }

  statement {
    sid     = "APIGatewayRead"
    effect  = "Allow"
    actions = ["apigateway:GET"]
    resources = [
      "arn:aws:apigateway:${var.aws_region}::/restapis/9o7c3668a4",
      "arn:aws:apigateway:${var.aws_region}::/restapis/9o7c3668a4/*",
    ]
  }

  statement {
    sid    = "S3Read"
    effect = "Allow"
    actions = [
      "s3:GetAccelerateConfiguration",
      "s3:GetBucketAcl",
      "s3:GetBucketCORS",
      "s3:GetBucketLogging",
      "s3:GetBucketObjectLockConfiguration",
      "s3:GetBucketOwnershipControls",
      "s3:GetBucketPolicy",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketRequestPayment",
      "s3:GetBucketTagging",
      "s3:GetBucketVersioning",
      "s3:GetBucketWebsite",
      "s3:GetEncryptionConfiguration",
      "s3:GetLifecycleConfiguration",
      "s3:GetReplicationConfiguration",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::jaetill-carto",
      "arn:aws:s3:::jaetill-carto/*",
    ]
  }

  statement {
    sid    = "CloudFrontRead"
    effect = "Allow"
    actions = [
      "cloudfront:GetDistribution",
      "cloudfront:GetDistributionConfig",
      "cloudfront:GetOriginAccessControl",
      "cloudfront:GetOriginAccessControlConfig",
      "cloudfront:ListTagsForResource",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "SecretsManagerRead"
    effect = "Allow"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetResourcePolicy",
    ]
    resources = [
      "arn:aws:secretsmanager:${var.aws_region}:${var.aws_account_id}:secret:carto/*",
    ]
  }

  statement {
    sid    = "CloudWatchLogsRead"
    effect = "Allow"
    actions = [
      "logs:DescribeLogGroups",
      "logs:ListTagsForResource",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "iac_drift_plan" {
  name   = "plan-read"
  role   = aws_iam_role.iac_drift.id
  policy = data.aws_iam_policy_document.iac_drift_plan.json
}

data "aws_iam_policy_document" "iac_drift_tfstate" {
  statement {
    sid       = "TFStateRead"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::jaetill-tfstate", "arn:aws:s3:::jaetill-tfstate/*"]
  }
  statement {
    sid       = "TFStateLockRead"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem"]
    resources = ["arn:aws:dynamodb:${var.aws_region}:${var.aws_account_id}:table/terraform-state-lock"]
  }
}

resource "aws_iam_role_policy" "iac_drift_tfstate" {
  name   = "tfstate-access"
  role   = aws_iam_role.iac_drift.id
  policy = data.aws_iam_policy_document.iac_drift_tfstate.json
}