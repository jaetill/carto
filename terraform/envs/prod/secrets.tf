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