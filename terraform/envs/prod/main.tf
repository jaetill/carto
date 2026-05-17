# Production environment for carto.
# Phase 6 retrofit per platform ADR-0007. Slice 1 (S3 + CloudFront) - S3 only for now.
# Subsequent slices (cartoApi Lambda, IAM, API Gateway, Neo4j secret) in terraform/README.md.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}