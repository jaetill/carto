# cartoApi Lambda - all-in-one HTTP API behind API Gateway.
# Note: SENTRY_DSN env var not yet set on the function; Phase 5 SDK wired but DSN missing.

resource "aws_lambda_function" "cartoapi" {
  function_name = "cartoApi"
  role          = aws_iam_role.cartoapi.arn
  handler       = "index.handler"
  runtime       = "nodejs22.x"
  architectures = ["x86_64"]
  memory_size   = 128
  timeout       = 30

  filename = "${path.module}/placeholder.zip"

  environment {
    variables = {
      NEO4J_DATABASE = "ca5b33dc"
      NEO4J_URI      = "neo4j+s://ca5b33dc.databases.neo4j.io"
      NEO4J_USERNAME = "ca5b33dc"
    }
  }

  lifecycle {
    ignore_changes = [filename, source_code_hash]
  }
}

resource "aws_lambda_function" "feedback" {
  function_name = "carto-feedback"
  role          = aws_iam_role.feedback.arn
  handler       = "feedback.handler"
  runtime       = "nodejs22.x"
  architectures = ["x86_64"]
  memory_size   = 256
  timeout       = 10

  filename = "${path.module}/placeholder.zip"

  environment {
    variables = {
      GITHUB_REPO_OWNER = "jaetill"
      GITHUB_REPO_NAME  = "carto"
      GITHUB_SECRET_ID  = "carto/github-token"
      DEPLOY_ENV        = "production"
      LOG_LEVEL         = "INFO"
    }
  }

  lifecycle {
    ignore_changes = [filename, source_code_hash]
  }
}