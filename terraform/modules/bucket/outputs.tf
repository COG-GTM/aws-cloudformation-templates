output "bucket_id" {
  description = "The name of the main bucket"
  value       = aws_s3_bucket.bucket.id
}

output "bucket_arn" {
  description = "The ARN of the main bucket"
  value       = aws_s3_bucket.bucket.arn
}

output "log_bucket_id" {
  description = "The name of the log bucket"
  value       = aws_s3_bucket.log_bucket.id
}

output "replica_bucket_id" {
  description = "The name of the replica bucket"
  value       = aws_s3_bucket.replica_bucket.id
}
