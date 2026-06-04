# -----------------------------------------------------------------------------
# S3 + DynamoDB Backend Configuration
# -----------------------------------------------------------------------------
# Uncomment the block below after bootstrapping the backend resources.
#
# Bootstrap instructions:
#   1. Create an S3 bucket for state storage:
#      aws s3api create-bucket \
#        --bucket <your-org>-terraform-state-<account-id> \
#        --region us-east-1
#
#   2. Enable versioning on the bucket:
#      aws s3api put-bucket-versioning \
#        --bucket <your-org>-terraform-state-<account-id> \
#        --versioning-configuration Status=Enabled
#
#   3. Enable server-side encryption:
#      aws s3api put-bucket-encryption \
#        --bucket <your-org>-terraform-state-<account-id> \
#        --server-side-encryption-configuration \
#          '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
#
#   4. Create a DynamoDB table for state locking:
#      aws dynamodb create-table \
#        --table-name terraform-state-lock \
#        --attribute-definitions AttributeName=LockID,AttributeType=S \
#        --key-schema AttributeName=LockID,KeyType=HASH \
#        --billing-mode PAY_PER_REQUEST \
#        --region us-east-1
#
#   5. Uncomment the backend block below and run:
#      terraform init -migrate-state
# -----------------------------------------------------------------------------

# terraform {
#   backend "s3" {
#     bucket         = "<your-org>-terraform-state-<account-id>"
#     key            = "cloudformation-migration/terraform.tfstate"
#     region         = "us-east-1"
#     dynamodb_table = "terraform-state-lock"
#     encrypt        = true
#   }
# }
