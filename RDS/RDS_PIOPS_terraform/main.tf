# Migrated from RDS/RDS_PIOPS.yaml (CloudFormation)
#
# Creates an RDS MySQL instance with provisioned IOPS and stores
# the generated master password in AWS Secrets Manager.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

resource "random_password" "db_password" {
  length           = 16
  override_special = "!#$%&*()-_=+[]{}<>:?"
  # Exclude characters matching CFN ExcludeCharacters: "@ / \
}

resource "aws_secretsmanager_secret" "db_credential" {
  name_prefix = "DBCredential"
}

resource "aws_secretsmanager_secret_version" "db_credential" {
  secret_id     = aws_secretsmanager_secret.db_credential.id
  secret_string = random_password.db_password.result
}

resource "aws_db_instance" "this" {
  allocated_storage = 100
  instance_class    = "db.t3.small"

  backup_retention_period = 7
  engine                  = "mysql"
  iops                    = 1000
  storage_type            = "io1" # Required by Terraform for provisioned IOPS; CFN infers this.

  username = var.db_user
  password = random_password.db_password.result

  publicly_accessible = false
  storage_encrypted   = true

  # Terraform requires this to be set explicitly. Production usage should use
  # final_snapshot_identifier instead.
  skip_final_snapshot = true
}
