# CloudFront distribution E36OPEPVLCLUYJ - carto.jaetill.com.
# OAC E1GXIADC14HCG5 restricts S3 access to this distribution.

resource "aws_cloudfront_origin_access_control" "main" {
  name                              = "carto-oac"
  description                       = "OAC for carto.jaetill.com"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  comment             = "Carto app"
  price_class         = "PriceClass_All"
  is_ipv6_enabled     = true
  aliases             = ["carto.jaetill.com"]
  default_root_object = "index.html"
  http_version        = "http2"

  origin {
    domain_name              = aws_s3_bucket.main.bucket_regional_domain_name
    origin_id                = "jaetill-carto-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.main.id

    s3_origin_config {
      origin_access_identity = ""
    }
  }

  default_cache_behavior {
    target_origin_id       = "jaetill-carto-s3"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true
    cache_policy_id        = "658327ea-f89d-4fab-a63d-7e88639e58f6"
  }

  custom_error_response {
    error_code            = 404
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 0
  }

  viewer_certificate {
    cloudfront_default_certificate = false
    acm_certificate_arn            = var.cloudfront_acm_cert_arn
    minimum_protocol_version       = "TLSv1.2_2021"
    ssl_support_method             = "sni-only"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  lifecycle {
    ignore_changes = [origin]
  }
}