data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name_suffix = replace(var.project_name, "/[^a-zA-Z0-9-]/", "-")
  lambda_name = "${local.name_suffix}-lambda"
  table_name  = "${local.name_suffix}-requests"
  topic_name  = "${local.name_suffix}-approvals"

  param_full_name    = startswith(var.approval_hmac_param_name, "/") ? var.approval_hmac_param_name : "/${var.approval_hmac_param_name}"
  approval_param_arn = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter${local.param_full_name}"

  # API base URL = {api_endpoint}/{stage}
  api_base_url = "${aws_apigatewayv2_api.http.api_endpoint}/${aws_apigatewayv2_stage.stage.name}"
}

# ---------- KMS Signing Key ----------
resource "aws_kms_key" "signing" {
  description              = "Artifact Signing Key (KMS) for ${var.project_name}"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 7
  enable_key_rotation      = false
  multi_region             = false
  tags = {
    Project = var.project_name
  }
}

resource "aws_kms_alias" "signing" {
  name          = "alias/${local.name_suffix}-signing"
  target_key_id = aws_kms_key.signing.key_id
}

# ---------- DynamoDB ----------
resource "aws_dynamodb_table" "requests" {
  name         = local.table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "requestId"

  attribute {
    name = "requestId"
    type = "S"
  }

  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }

  tags = {
    Project = var.project_name
  }
}

# ---------- SNS ----------
resource "aws_sns_topic" "approvals" {
  name = local.topic_name
  tags = {
    Project = var.project_name
  }
}

# ---------- API Gateway v2 (HTTP API) ----------
resource "aws_apigatewayv2_api" "http" {
  name          = "${var.project_name}-http"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "stage" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = var.api_stage_name
  auto_deploy = true
}

# ---------- Lambda packaging ----------
# Built by ../04_build.sh (dist/index.js). Plan/apply fail if that file is missing.
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../dist/index.js"
  output_path = "${path.module}/../dist/lambda.zip"
}

# ---------- IAM Role & Policies ----------
data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.name_suffix}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
}

data "aws_iam_policy_document" "lambda_policy" {
  statement {
    sid = "AllowLogs"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
  }

  statement {
    sid = "AllowDynamoDB"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:UpdateItem"
    ]
    resources = [aws_dynamodb_table.requests.arn]
  }

  statement {
    sid = "AllowKmsSignGetPub"
    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
      "kms:DescribeKey"
    ]
    resources = [aws_kms_key.signing.arn]
  }

  statement {
    sid = "AllowSnsPublish"
    actions = [
      "sns:Publish"
    ]
    resources = [aws_sns_topic.approvals.arn]
  }

  statement {
    sid = "AllowSsmGetParam"
    actions = [
      "ssm:GetParameter"
    ]
    resources = [local.approval_param_arn]
  }

  # To retrieve SecureString with decryption, lambda also needs kms:Decrypt on the KMS key used by SSM (usually alias/aws/ssm)
  statement {
    sid = "AllowKmsDecryptForSsm"
    actions = [
      "kms:Decrypt"
    ]
    resources = ["arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/aws/ssm"]
  }
}

resource "aws_iam_role_policy" "lambda_inline" {
  name   = "${local.name_suffix}-lambda-policy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_policy.json
}

# ---------- Lambda ----------
resource "aws_lambda_function" "main" {
  function_name    = local.lambda_name
  role             = aws_iam_role.lambda.arn
  runtime          = "nodejs22.x"
  handler          = "index.handler"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      TABLE_NAME               = aws_dynamodb_table.requests.name
      KMS_KEY_ID               = aws_kms_key.signing.key_id
      SNS_TOPIC_ARN            = aws_sns_topic.approvals.arn
      API_BASE_URL             = local.api_base_url
      APPROVAL_HMAC_PARAM_NAME = local.param_full_name
      REQUEST_TTL_SECONDS      = tostring(var.request_ttl_seconds)
      APPROVAL_TTL_SECONDS     = tostring(var.approval_ttl_seconds)
      NODE_OPTIONS             = "--enable-source-maps"
    }
  }

  depends_on = [aws_iam_role_policy.lambda_inline]
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${aws_lambda_function.main.function_name}"
  retention_in_days = var.log_retention_days
}

# ---------- API Integration ----------
resource "aws_apigatewayv2_integration" "lambda_proxy" {
  api_id                 = aws_apigatewayv2_api.http.id
  integration_type       = "AWS_PROXY"
  integration_method     = "POST"
  payload_format_version = "2.0"
  integration_uri        = aws_lambda_function.main.invoke_arn
  timeout_milliseconds   = 30000
}

resource "aws_apigatewayv2_route" "get_approve" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "GET /approve"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_proxy.id}"
}

resource "aws_apigatewayv2_route" "post_approve" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "POST /approve"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_proxy.id}"
}

resource "aws_apigatewayv2_route" "get_request" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "GET /requests/{id}"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_proxy.id}"
}

resource "aws_apigatewayv2_route" "get_public_key" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "GET /public-key"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_proxy.id}"
}

resource "aws_apigatewayv2_route" "get_openpgp_public_key" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "GET /openpgp-public-key"
  target    = "integrations/${aws_apigatewayv2_integration.lambda_proxy.id}"
}

resource "aws_lambda_permission" "apigw_invoke" {
  statement_id  = "AllowAPIGwInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.main.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}

