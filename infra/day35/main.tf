
# ==================================================
# Day 35: AI Security Incident Investigator
# AWS Infrastructure as Code
# LOCAL VALIDATION ONLY - DO NOT APPLY
# ==================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# ==================================================
# 1. AWS PROVIDER CONFIGURATION
# ==================================================

variable "aws_region" {
  description = "AWS Region for future authorized deployment"
  type        = string
  default     = "us-east-1"
}

variable "enable_events" {
  description = "Enable CloudTrail event routing"
  type        = bool
  default     = false
}

provider "aws" {
  region = var.aws_region
}

locals {
  name = "ai-security-investigator-lab"
}

# ==================================================
# 2. CLOUDWATCH LOGGING
# ==================================================

resource "aws_cloudwatch_log_group" "security" {
  name              = "/aws/lambda/${local.name}"
  retention_in_days = 7
}

# ==================================================
# 3. IAM EXECUTION ROLE
# ==================================================

resource "aws_iam_role" "lambda" {
  name = "${local.name}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"

      Principal = {
        Service = "lambda.amazonaws.com"
      }

      Action = "sts:AssumeRole"
    }]
  })
}

# ==================================================
# 4. LEAST-PRIVILEGE LAMBDA LOGGING POLICY
# ==================================================

resource "aws_iam_role_policy" "lambda_logs" {
  name = "${local.name}-logging"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"

    Statement = [{
      Effect = "Allow"

      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]

      Resource = [
        "${aws_cloudwatch_log_group.security.arn}:*"
      ]
    }]
  })
}

# ==================================================
# 5. AWS LAMBDA SECURITY DETECTOR
# ==================================================

resource "aws_lambda_function" "security" {
  function_name = local.name

  filename = "${path.module}/build/security-handler.zip"

  source_code_hash = filebase64sha256(
    "${path.module}/build/security-handler.zip"
  )

  handler = "lambda_security_handler.lambda_handler"
  runtime = "python3.13"

  role = aws_iam_role.lambda.arn

  memory_size = 128
  timeout     = 10

  architectures = ["x86_64"]

  reserved_concurrent_executions = 2

  depends_on = [
    aws_iam_role_policy.lambda_logs
  ]
}

# ==================================================
# 6. EVENTBRIDGE SECURITY EVENT ROUTING
# ==================================================

resource "aws_cloudwatch_event_rule" "signin" {
  name        = "${local.name}-signin"
  description = "Route CloudTrail console sign-in events"

  event_pattern = file(
    "${path.module}/../../event_patterns/signin.json"
  )

  state = var.enable_events ? (
    "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
  ) : "DISABLED"
}

# ==================================================
# 7. EVENTBRIDGE LAMBDA TARGET
# ==================================================

resource "aws_cloudwatch_event_target" "security" {
  rule = aws_cloudwatch_event_rule.signin.name
  arn  = aws_lambda_function.security.arn
}

# ==================================================
# 8. PERMISSION FOR EVENTBRIDGE TO INVOKE LAMBDA
# ==================================================

resource "aws_lambda_permission" "eventbridge" {
  statement_id = "AllowEventBridgeInvocation"
  action       = "lambda:InvokeFunction"

  function_name = aws_lambda_function.security.function_name
  principal     = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.signin.arn
}

# ==================================================
# 9. S3 SECURITY EVIDENCE BUCKET
# ==================================================

resource "aws_s3_bucket" "evidence" {
  bucket_prefix = "ai-security-evidence-lab-"
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }
}

# ==================================================
# 10. BLOCK ALL PUBLIC ACCESS TO S3
# ==================================================

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ==================================================
# 11. ENABLE S3 VERSIONING
# ==================================================

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ==================================================
# 12. ENABLE S3 ENCRYPTION
# ==================================================

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ==================================================
# END - LOCAL VALIDATION ONLY
# ==================================================
