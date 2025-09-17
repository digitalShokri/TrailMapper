# main.tf - Complete Terraform configuration for Trail Mapper deployment
# Usage:
# 1. Save the HTML file as "index.html" in the same directory as this file
# 2. Run: terraform init
# 3. Run: terraform plan
# 4. Run: terraform apply

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region
}

# Variables
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "trail-mapper"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

# Create a unique bucket name using random suffix
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

locals {
  bucket_name = "${var.project_name}-${var.environment}-${random_id.bucket_suffix.hex}"
  s3_origin_id = "S3-${local.bucket_name}"
}

# S3 Bucket for hosting the static website
resource "aws_s3_bucket" "trail_mapper" {
  bucket = local.bucket_name

  tags = {
    Name        = "${var.project_name}-static-site"
    Environment = var.environment
    Project     = var.project_name
  }
}

# S3 Bucket Public Access Block (CloudFront only access)
resource "aws_s3_bucket_public_access_block" "trail_mapper" {
  bucket = aws_s3_bucket.trail_mapper.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket Website Configuration
resource "aws_s3_bucket_website_configuration" "trail_mapper" {
  bucket = aws_s3_bucket.trail_mapper.id

  index_document {
    suffix = "index.html"
  }

  error_document {
    key = "index.html"  # SPA fallback
  }
}

# S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "trail_mapper" {
  bucket = aws_s3_bucket.trail_mapper.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# CloudFront Origin Access Control
resource "aws_cloudfront_origin_access_control" "trail_mapper" {
  name                              = "${var.project_name}-oac"
  description                       = "OAC for ${var.project_name}"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# CloudFront Distribution
resource "aws_cloudfront_distribution" "trail_mapper" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  comment             = "${var.project_name} CloudFront Distribution"
  price_class         = "PriceClass_100"  # Use only North America and Europe edge locations to reduce costs

  origin {
    domain_name              = aws_s3_bucket.trail_mapper.bucket_regional_domain_name
    origin_id                = local.s3_origin_id
    origin_access_control_id = aws_cloudfront_origin_access_control.trail_mapper.id
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id
    compress         = true

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 86400    # 1 day
    max_ttl                = 31536000 # 1 year

    # Add response headers for security
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
  }

  custom_error_response {
    error_code         = 403
    response_code      = 200
    response_page_path = "/index.html"
  }

  tags = {
    Name        = "${var.project_name}-cdn"
    Environment = var.environment
    Project     = var.project_name
  }
}

# CloudFront Response Headers Policy for Security
resource "aws_cloudfront_response_headers_policy" "security_headers" {
  name = "${var.project_name}-security-headers"

  security_headers_config {
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
    strict_transport_security {
      access_control_max_age_sec = 63072000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    content_security_policy {
      content_security_policy = "default-src 'self' https://*.openstreetmap.org https://*.basemaps.cartocdn.com https://stamen-tiles-*.a.ssl.fastly.net https://cdnjs.cloudflare.com 'unsafe-inline' 'unsafe-eval' data: blob:; img-src 'self' https: data: blob:; connect-src 'self' https:;"
      override = true
    }
  }

  cors_config {
    access_control_allow_credentials = false
    access_control_allow_headers {
      items = ["*"]
    }
    access_control_allow_methods {
      items = ["GET", "HEAD", "OPTIONS"]
    }
    access_control_allow_origins {
      items = ["*"]
    }
    origin_override = true
  }
}

# S3 Bucket Policy to allow CloudFront access
resource "aws_s3_bucket_policy" "trail_mapper" {
  bucket = aws_s3_bucket.trail_mapper.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipal"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.trail_mapper.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.trail_mapper.arn
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.trail_mapper]
}

# Upload the HTML file to S3
resource "aws_s3_object" "index_html" {
  bucket       = aws_s3_bucket.trail_mapper.id
  key          = "index.html"
  source       = "${path.module}/index.html"
  content_type = "text/html"
  etag         = filemd5("${path.module}/index.html")

  # Cache control for better performance
  cache_control = "public, max-age=3600"
}

# CloudFront Invalidation (optional - runs on every apply)
resource "null_resource" "invalidate_cache" {
  triggers = {
    index_html_etag = aws_s3_object.index_html.etag
  }

  provisioner "local-exec" {
    command = "aws cloudfront create-invalidation --distribution-id ${aws_cloudfront_distribution.trail_mapper.id} --paths '/*' --region ${var.aws_region}"
  }

  depends_on = [aws_cloudfront_distribution.trail_mapper]
}

# Outputs
output "cloudfront_url" {
  description = "CloudFront distribution URL for the Trail Mapper application"
  value       = "https://${aws_cloudfront_distribution.trail_mapper.domain_name}"
}

output "cloudfront_distribution_id" {
  description = "CloudFront distribution ID"
  value       = aws_cloudfront_distribution.trail_mapper.id
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket"
  value       = aws_s3_bucket.trail_mapper.id
}

output "s3_bucket_website_endpoint" {
  description = "S3 website endpoint (not directly accessible)"
  value       = aws_s3_bucket_website_configuration.trail_mapper.website_endpoint
}

# Optional: Create a terraform.tfvars file with these values
# aws_region   = "us-west-2"
# project_name = "my-trail-mapper"
# environment  = "production"
