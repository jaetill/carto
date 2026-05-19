variable "project_name" {
  type        = string
  default     = "carto"
  description = "Project slug used in tags and resource names."
}

variable "env" {
  type        = string
  default     = "prod"
  description = "Deployment environment label."
}

variable "aws_region" {
  type        = string
  default     = "us-east-2"
  description = "AWS region for this environment."
}

variable "aws_account_id" {
  type        = string
  default     = "214599503944"
  description = "AWS account ID."
}

variable "cloudfront_acm_cert_arn" {
  type        = string
  default     = "arn:aws:acm:us-east-1:214599503944:certificate/36c7876f-a587-489d-a621-73e7cad8e2b9"
  description = "ACM certificate ARN for carto.jaetill.com (must be in us-east-1 for CloudFront)."
}