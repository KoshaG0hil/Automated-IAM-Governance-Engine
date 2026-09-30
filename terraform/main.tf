terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "Automated-IAM-Governance-Engine"
      ManagedBy   = "Terraform"
      Environment = var.environment
    }
  }
}

data "aws_caller_identity" "current" {}

# ==============================================================================
# S3 BUCKET FOR AUDIT REPORTS & EVIDENCE
# ==============================================================================
resource "aws_s3_bucket" "audit_reports" {
  bucket        = "${var.project_name}-reports-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_reports" {
  bucket = aws_s3_bucket.audit_reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit_reports" {
  bucket = aws_s3_bucket.audit_reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ==============================================================================
# SNS ALERTING TOPIC
# ==============================================================================
resource "aws_sns_topic" "iam_alerts" {
  name = "${var.project_name}-alerts"
}

resource "aws_sns_topic_subscription" "email_sub" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.iam_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ==============================================================================
# LAMBDA EXECUTION ROLE & LEAST-PRIVILEGE POLICIES
# ==============================================================================
resource "aws_iam_role" "lambda_exec" {
  name = "${var.project_name}-lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_permissions" {
  name        = "${var.project_name}-lambda-policy"
  description = "Permissions for IAM Governance Lambda engine"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid    = "IAMReadOnlyAudit"
        Effect = "Allow"
        Action = [
          "iam:Get*",
          "iam:List*",
          "iam:GenerateCredentialReport"
        ]
        Resource = "*"
      },
      {
        Sid    = "SNSPublishAlerts"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.iam_alerts.arn
      },
      {
        Sid    = "S3ReportStorage"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.audit_reports.arn}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_attach" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.lambda_permissions.arn
}

# ==============================================================================
# LAMBDA FUNCTION PACKAGING & DEPLOYMENT
# ==============================================================================
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/lambda_bundle.zip"
}

resource "aws_lambda_function" "governance_engine" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-engine"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "lambda_handler.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.12"
  timeout          = 300
  memory_size      = 256

  environment {
    variables = {
      BASELINE_PATH      = "baseline/sample_baseline.yaml"
      PRIVESC_RULES_PATH = "baseline/privesc_rules.json"
      SNS_TOPIC_ARN      = aws_sns_topic.iam_alerts.arn
      REPORTS_BUCKET     = aws_s3_bucket.audit_reports.id
    }
  }
}

# ==============================================================================
# EVENTBRIDGE RULE: REAL-TIME CLOUDTRAIL IAM MUTATION DETECTION
# ==============================================================================
resource "aws_cloudwatch_event_rule" "iam_mutation_rule" {
  name        = "${var.project_name}-iam-mutations"
  description = "Captures CloudTrail IAM mutating API calls in real-time"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "CreatePolicy",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
        "DetachUserPolicy",
        "DetachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
        "CreateAccessKey",
        "UpdateAssumeRolePolicy"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_mutation_target" {
  rule      = aws_cloudwatch_event_rule.iam_mutation_rule.name
  target_id = "TriggerIAMGovernanceLambda"
  arn       = aws_lambda_function.governance_engine.arn
}

resource "aws_lambda_permission" "allow_eventbridge_mutations" {
  statement_id  = "AllowExecutionFromEventBridgeMutation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.governance_engine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_mutation_rule.arn
}

# ==============================================================================
# EVENTBRIDGE RULE: PERIODIC SCHEDULED AUDIT SWEEP
# ==============================================================================
resource "aws_cloudwatch_event_rule" "scheduled_audit_rule" {
  name                = "${var.project_name}-scheduled-audit"
  description         = "Periodic sweep trigger for full IAM compliance audit"
  schedule_expression = var.audit_schedule_expression
}

resource "aws_cloudwatch_event_target" "lambda_scheduled_target" {
  rule      = aws_cloudwatch_event_rule.scheduled_audit_rule.name
  target_id = "TriggerScheduledAudit"
  arn       = aws_lambda_function.governance_engine.arn
}

resource "aws_lambda_permission" "allow_eventbridge_schedule" {
  statement_id  = "AllowExecutionFromEventBridgeSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.governance_engine.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scheduled_audit_rule.arn
}
