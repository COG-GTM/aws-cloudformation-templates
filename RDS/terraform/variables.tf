variable "db_user" {
  description = "The database admin account username"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.db_user) >= 1 && length(var.db_user) <= 16 && can(regex("^[a-zA-Z][a-zA-Z0-9]*$", var.db_user))
    error_message = "Must begin with a letter and contain only alphanumeric characters (1-16 chars)."
  }
}

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}
