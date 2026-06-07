# Slice 2: IAM
#
# 2 roles:
#   - cartoApi-role         (Lambda execution role)
#   - carto-github-deploy   (OIDC trust for GitHub Actions)

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ── cartoApi Lambda execution role ───────────────────────────────────────

resource "aws_iam_role" "cartoapi" {
  name               = "cartoApi-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "cartoapi_logs" {
  name = "cartoApi-logs"
  role = aws_iam_role.cartoapi.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "logs:CreateLogGroup"
        Resource = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/lambda/cartoApi:*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cartoapi_s3" {
  name = "cartoS3Access"
  role = aws_iam_role.cartoapi.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "arn:aws:s3:::jaetill-carto/*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cartoapi_secrets" {
  name = "carto-secrets-access"
  role = aws_iam_role.cartoapi.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = "arn:aws:secretsmanager:${var.aws_region}:${var.aws_account_id}:secret:carto/secrets-qgjImO"
      }
    ]
  })
}

# ── GitHub Actions OIDC deploy role ──────────────────────────────────────

resource "aws_iam_role" "github_deploy" {
  name        = "carto-github-deploy"
  description = "GitHub Actions OIDC role for carto CI/CD"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Federated = "arn:aws:iam::${var.aws_account_id}:oidc-provider/token.actions.githubusercontent.com" }
        Action    = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:sub" = ["repo:jaetill/carto:ref:refs/heads/master", "repo:jaetill/carto:environment:production"]
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "github_deploy" {
  name = "deploy"
  role = aws_iam_role.github_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject", "s3:ListBucket", "s3:DeleteObject"]
        Resource = [
          "arn:aws:s3:::jaetill-carto",
          "arn:aws:s3:::jaetill-carto/*",
        ]
      },
      {
        Effect   = "Allow"
        Action   = "cloudfront:CreateInvalidation"
        Resource = "arn:aws:cloudfront::${var.aws_account_id}:distribution/E36OPEPVLCLUYJ"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:UpdateFunctionCode",
          "lambda:GetFunction",
          "lambda:GetFunctionConfiguration",
          "lambda:UpdateFunctionConfiguration",
          "lambda:PublishVersion",
        ]
        Resource = [
          "arn:aws:lambda:${var.aws_region}:${var.aws_account_id}:function:cartoApi",
          "arn:aws:lambda:${var.aws_region}:${var.aws_account_id}:function:carto-feedback",
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:CreateAlias",
          "lambda:UpdateAlias",
          "lambda:GetAlias",
        ]
        Resource = [
          "arn:aws:lambda:${var.aws_region}:${var.aws_account_id}:function:cartoApi:*",
          "arn:aws:lambda:${var.aws_region}:${var.aws_account_id}:function:carto-feedback:*",
        ]
      }
    ]
  })
}

# ── feedback Lambda execution role ────────────────────────────────────────

resource "aws_iam_role" "feedback" {
  name               = "carto-feedback-role"
  description        = "Execution role for feedback Lambda (Standard 11)"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy_attachment" "feedback_basic_exec" {
  role       = aws_iam_role.feedback.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "feedback_secrets" {
  name = "github-token-access"
  role = aws_iam_role.feedback.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = aws_secretsmanager_secret.github_token.arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "feedback_dynamodb" {
  name = "rate-limit-dynamodb"
  role = aws_iam_role.feedback.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "dynamodb:UpdateItem"
        Resource = aws_dynamodb_table.rate_limits.arn
      }
    ]
  })
}
