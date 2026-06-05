terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --- Secret (replaces CFN DBCredential) ---

resource "random_password" "db_password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}|:;',.<>?~`"
}

resource "aws_secretsmanager_secret" "db_credential" {
  name = "db_credential"
}

resource "aws_secretsmanager_secret_version" "db_credential" {
  secret_id     = aws_secretsmanager_secret.db_credential.id
  secret_string = random_password.db_password.result
}

# --- RDS Instance (replaces CFN myDB) ---

resource "aws_db_instance" "my_db" {
  allocated_storage       = 100
  instance_class          = "db.t3.small"
  backup_retention_period = 7
  engine                  = "mysql"
  iops                    = 1000
  storage_type            = "io1" # required for provisioned IOPS in Terraform
  username                = var.db_user
  password                = random_password.db_password.result
  publicly_accessible     = false
  storage_encrypted       = true
  skip_final_snapshot     = true # production should use false
}
