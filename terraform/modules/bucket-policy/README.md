# bucket-policy

Attaches a security-hardened bucket policy to an S3 bucket.

## Policy Statements

1. **Deny insecure transport** — denies all `s3:*` actions when `aws:SecureTransport` is `false`
2. **Allow S3 logging** — allows `s3:PutObject` from `logging.s3.amazonaws.com`

## Usage

```hcl
module "bucket_policy" {
  source = "../bucket-policy"

  bucket_name = aws_s3_bucket.example.id
}
```

## Inputs

| Name | Description | Type | Required |
|------|-------------|------|----------|
| `bucket_name` | Name of the S3 bucket to attach the policy to | `string` | yes |

## Outputs

| Name | Description |
|------|-------------|
| `policy_id` | The ID of the bucket policy |
