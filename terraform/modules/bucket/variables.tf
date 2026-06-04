variable "app_name" {
  description = "Application name used as a prefix for all bucket names"
  type        = string
}

variable "empty_on_delete" {
  description = "If true, bucket contents will be permanently deleted when the stack is destroyed"
  type        = bool
  default     = false
  # TODO: Implement destroy-time provisioner to empty buckets before deletion
}
