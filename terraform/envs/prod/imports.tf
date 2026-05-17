# Phase 6 Slice 1 import blocks - S3 only.
# CloudFront imports deferred behind IAM gap.
# Fix:
#   aws iam put-user-policy --user-name jaetill-dev --policy-name TerraformCloudFront `
#     --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudfront:ListTagsForResource","cloudfront:GetOriginAccessControl","cloudfront:GetDistribution","cloudfront:GetDistributionConfig"],"Resource":"*"}]}'
# Then rename cloudfront.tf.pending to cloudfront.tf and uncomment below.

import {
  to = aws_s3_bucket.main
  id = "jaetill-carto"
}

import {
  to = aws_s3_bucket_policy.main
  id = "jaetill-carto"
}

import {
  to = aws_cloudfront_origin_access_control.main
  id = "E1GXIADC14HCG5"
}

import {
  to = aws_cloudfront_distribution.main
  id = "E36OPEPVLCLUYJ"
}
