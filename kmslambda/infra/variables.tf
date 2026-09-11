variable "project_name" {
  description = "Project name prefix"
  type        = string
  default     = "artifact-signing-service"
}

variable "openpgp_user_name" {
  description = "OpenPGP User ID name, bound at deploy. Not a request parameter."
  type        = string

  validation {
    condition     = length(trimspace(var.openpgp_user_name)) > 0
    error_message = "openpgp_user_name must be non-empty."
  }
}

variable "openpgp_user_email" {
  description = "OpenPGP User ID email, bound at deploy. Not a request parameter."
  type        = string

  validation {
    condition     = can(regex("^[^[:space:]@]+@[^[:space:]@]+[.][^[:space:]@]+$", trimspace(var.openpgp_user_email)))
    error_message = "openpgp_user_email must be a simple email address."
  }
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

