# jaetill-carto S3 bucket - hosts the SPA at carto.jaetill.com.
# Origin for CloudFront distribution E36OPEPVLCLUYJ.

resource "aws_s3_bucket" "main" {
  bucket = "jaetill-carto"
}

resource "aws_s3_bucket_policy" "main" {
  bucket = aws_s3_bucket.main.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFrontOAC"
        Effect    = "Allow"
        Principal = { Service = "cloudfront.amazonaws.com" }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.main.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudfront::${var.aws_account_id}:distribution/E36OPEPVLCLUYJ"
          }
        }
      }
    ]
  })
}