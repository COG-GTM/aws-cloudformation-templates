variable "db_user" {
  description = "The database admin account username"
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9]*$", var.db_user)) && length(var.db_user) >= 1 && length(var.db_user) <= 16
    error_message = "Must begin with a letter, contain only alphanumeric characters, and be 1-16 characters long."
  }
}
