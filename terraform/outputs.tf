output "lambda_function_name" {
  description = "Name of the deployed IAM Governance Lambda function"
  value       = aws_lambda_function.governance_engine.function_name
}

output "lambda_function_arn" {
  description = "ARN of the IAM Governance Lambda function"
  value       = aws_lambda_function.governance_engine.arn
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for IAM security alerts"
  value       = aws_sns_topic.iam_alerts.arn
}

output "audit_reports_bucket_name" {
  description = "S3 bucket name where audit reports are archived"
  value       = aws_s3_bucket.audit_reports.id
}

output "cloudtrail_eventbridge_rule_arn" {
  description = "EventBridge rule ARN tracking CloudTrail IAM mutations"
  value       = aws_cloudwatch_event_rule.iam_mutation_rule.arn
}
