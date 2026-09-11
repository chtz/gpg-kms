output "api_base_url" {
  description = "HTTP API base URL"
  value       = local.api_base_url
}

output "lambda_function_name" {
  description = "Lambda function name"
  value       = aws_lambda_function.main.function_name
}

output "dynamodb_table_name" {
  description = "DynamoDB table name"
  value       = aws_dynamodb_table.requests.name
}

output "sns_topic_arn" {
  description = "SNS topic ARN for approvals"
  value       = aws_sns_topic.approvals.arn
}

output "kms_key_id" {
  description = "KMS signing key id"
  value       = aws_kms_key.signing.key_id
}

output "kms_key_arn" {
  description = "KMS signing key arn"
  value       = aws_kms_key.signing.arn
}

