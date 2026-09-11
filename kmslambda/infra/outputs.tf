output "api_base_url" {
  description = "HTTP API base URL"
  value       = local.api_base_url
}

output "lambda_function_name" {
  description = "Lambda function name (unqualified; signing pipeline invoke)"
  value       = aws_lambda_function.main.function_name
}

output "lambda_export_function_name" {
  description = "Function name qualified with the export alias (admin invoke)"
  value       = "${aws_lambda_function.main.function_name}:${aws_lambda_alias.export.name}"
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

output "openpgp_user_name" {
  description = "OpenPGP User ID name bound at deploy"
  value       = trimspace(var.openpgp_user_name)
}

output "openpgp_user_email" {
  description = "OpenPGP User ID email bound at deploy"
  value       = trimspace(var.openpgp_user_email)
}

