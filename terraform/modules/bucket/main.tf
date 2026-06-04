data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  bucket_name         = "${var.app_name}-${data.aws_region.current.name}-${data.aws_caller_identity.current.account_id}"
  log_bucket_name     = "${var.app_name}-logs-${data.aws_region.current.name}-${data.aws_caller_identity.current.account_id}"
  replica_bucket_name = "${var.app_name}-replicas-${data.aws_region.current.name}-${data.aws_caller_identity.current.account_id}"
}

# -----------------------------------------------------------------------------
# Log Bucket
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "log_bucket" {
  bucket              = local.log_bucket_name
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = 1
    }
  }
}

resource "aws_s3_bucket_public_access_block" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

module "log_bucket_policy" {
  source = "../bucket-policy"

  bucket_name = aws_s3_bucket.log_bucket.id
}

# -----------------------------------------------------------------------------
# Main Bucket
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "bucket" {
  bucket = local.bucket_name
}

resource "aws_s3_bucket_versioning" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_logging" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = ""
}

resource "aws_s3_bucket_replication_configuration" "bucket" {
  depends_on = [
    aws_s3_bucket_versioning.bucket,
    aws_s3_bucket_versioning.replica_bucket,
  ]

  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.bucket.id

  rule {
    id     = "replicate-all"
    status = "Enabled"

    destination {
      bucket = aws_s3_bucket.replica_bucket.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "bucket" {
  bucket = aws_s3_bucket.bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

module "bucket_policy" {
  source = "../bucket-policy"

  bucket_name = aws_s3_bucket.bucket.id
}

# -----------------------------------------------------------------------------
# Replica Bucket
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "replica_bucket" {
  bucket = local.replica_bucket_name
}

resource "aws_s3_bucket_versioning" "replica_bucket" {
  bucket = aws_s3_bucket.replica_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replica_bucket" {
  bucket = aws_s3_bucket.replica_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "replica_bucket" {
  bucket = aws_s3_bucket.replica_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

module "replica_bucket_policy" {
  source = "../bucket-policy"

  bucket_name = aws_s3_bucket.replica_bucket.id
}

# -----------------------------------------------------------------------------
# Replication IAM Role and Policy
# -----------------------------------------------------------------------------

resource "aws_iam_role" "replication" {
  name = "${var.app_name}-s3-replication-role"
  path = "/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      },
    ]
  })
}

resource "aws_iam_role_policy" "replication" {
  name = "bucket-replication-policy"
  role = aws_iam_role.replication.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name}"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicationTags",
        ]
        Resource = "arn:${data.aws_partition.current.partition}:s3:::${local.replica_bucket_name}/*"
      },
    ]
  })
}
