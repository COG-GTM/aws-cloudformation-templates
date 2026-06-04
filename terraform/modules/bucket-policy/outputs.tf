output "policy_id" {
  description = "The ID of the bucket policy"
  value       = aws_s3_bucket_policy.this.id
}
