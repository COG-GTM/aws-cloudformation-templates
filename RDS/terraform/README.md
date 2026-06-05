# RDS Provisioned IOPS — Terraform

Terraform migration of the CloudFormation template at [`RDS/RDS_PIOPS.json`](../RDS_PIOPS.json).

Creates an Amazon RDS MySQL instance with provisioned IOPS and stores the generated database password in AWS Secrets Manager.

> **WARNING** This template creates an Amazon RDS database instance and a Secrets Manager secret. You will be billed for the AWS resources used if you apply this configuration.

## Usage

```bash
terraform init
terraform plan -var="db_user=admin"
terraform apply -var="db_user=admin"
```

## Migration Notes

| CloudFormation | Terraform |
|---|---|
| `AWS::SecretsManager::Secret` with `GenerateSecretString` | `random_password` + `aws_secretsmanager_secret` + `aws_secretsmanager_secret_version` |
| `{{resolve:secretsmanager:...}}` dynamic reference | Direct reference to `random_password.db_password.result` |
| Implicit `DependsOn` between secret and DB | Handled automatically by Terraform's reference graph |
| `storage_type` not specified (defaults in CFN) | Explicit `storage_type = "io1"` required for provisioned IOPS |
