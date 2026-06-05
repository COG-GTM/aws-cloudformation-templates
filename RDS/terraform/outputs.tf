output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.my_db.endpoint
}

output "secret_arn" {
  description = "Secrets Manager secret ARN for the DB credential"
  value       = aws_secretsmanager_secret.db_credential.arn
}
