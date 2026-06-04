data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_s3_bucket_policy" "this" {
  bucket = var.bucket_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "s3:*"
        Resource = [
          "arn:${data.aws_partition.current.partition}:s3:::${var.bucket_name}",
          "arn:${data.aws_partition.current.partition}:s3:::${var.bucket_name}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "AllowS3LoggingPutObject"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource = [
          "arn:${data.aws_partition.current.partition}:s3:::${var.bucket_name}/*",
        ]
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:s3:::${var.bucket_name}"
          }
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
    ]
  })
}
