variable "project_name" {
  description = "Project name prefix"
  type        = string
  default     = "artifact-signing-service"
}

variable "approval_hmac_param_name" {
  description = "SSM Parameter name containing the HMAC secret for approval/poll tokens (SecureString)."
  type        = string
  default     = "/artifact-signing/approval-hmac"
}

variable "api_stage_name" {
  description = "API Gateway stage name"
  type        = string
  default     = "prod"
}

variable "request_ttl_seconds" {
  description = "TTL for signing requests in seconds"
  type        = number
  default     = 3600
}

variable "approval_ttl_seconds" {
  description = "TTL for approval links in seconds"
  type        = number
  default     = 1800
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 14
}

