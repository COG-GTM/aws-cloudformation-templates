# bucket

Creates a compliance-ready S3 bucket with an associated log bucket and replica bucket.

Converted from `RainModules/bucket.yml`.

## Features

- **Log bucket** with AES-256 encryption, object lock (COMPLIANCE mode, 1-year retention), versioning, and public access blocked
- **Main bucket** with AES-256 encryption, access logging to the log bucket, versioning, replication to the replica bucket, and public access blocked
- **Replica bucket** with AES-256 encryption, versioning, and public access blocked
- **IAM replication role** with least-privilege policy for cross-bucket replication
- **Bucket policies** (via `bucket-policy` module) enforcing TLS and logging access on all three buckets

## Usage

```hcl
module "my_bucket" {
  source = "../bucket"

  app_name = "my-application"
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `app_name` | Application name used as a prefix for all bucket names | `string` | — | yes |
| `empty_on_delete` | If true, bucket contents will be permanently deleted on destroy | `bool` | `false` | no |

## Outputs

| Name | Description |
|------|-------------|
| `bucket_id` | The name of the main bucket |
| `bucket_arn` | The ARN of the main bucket |
| `log_bucket_id` | The name of the log bucket |
| `replica_bucket_id` | The name of the replica bucket |

## Module Composition

This module calls `../bucket-policy` for each of the three buckets it creates.
