variable "aws_region" {
  type        = string
  description = "AWS region to deploy resources"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment name"
  default     = "prod"
}

variable "project_name" {
  type        = string
  description = "Prefix for project resources"
  default     = "iam-governance-engine"
}

variable "alert_email" {
  type        = string
  description = "Email address for SNS security alert subscription"
  default     = "security-alerts@example.com"
}

variable "audit_schedule_expression" {
  type        = string
  description = "EventBridge cron or rate expression for periodic audits"
  default     = "cron(0 6 * * ? *)" # Daily at 06:00 UTC
}
