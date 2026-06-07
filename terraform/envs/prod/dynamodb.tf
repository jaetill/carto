# DynamoDB table for distributed rate limiting (feedback Lambda, issue #40).
# Fixed-window counters keyed by "feedback#<ip>#<windowEpoch>"; TTL cleans up stale rows.

resource "aws_dynamodb_table" "rate_limits" {
  name         = "carto-rate-limits"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
}
