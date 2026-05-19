# Slice 5: Secrets Manager + CloudWatch log group

resource "aws_secretsmanager_secret" "main" {
  name = "carto/secrets"
}

resource "aws_cloudwatch_log_group" "cartoapi" {
  name              = "/aws/lambda/cartoApi"
  retention_in_days = 0

  lifecycle {
    ignore_changes = [tags, tags_all]
  }
}

resource "aws_secretsmanager_secret" "github_token" {
  name        = "carto/github-token"
  description = "GitHub PAT for feedback Lambda to file user-feedback issues on jaetill/carto"
}