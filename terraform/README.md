# CloudFormation-to-Terraform Migration

This directory contains Terraform equivalents of the AWS CloudFormation templates in this repository, organized as reusable modules.

## Project Structure

```
terraform/
├── versions.tf        # Terraform and provider version constraints
├── providers.tf       # AWS provider configuration with default tags
├── backend.tf         # S3 + DynamoDB remote state backend (commented out)
├── variables.tf       # Root-level input variables
├── outputs.tf         # Root-level outputs (placeholder)
├── modules/           # Reusable Terraform modules
│   ├── bucket-policy/ # S3 bucket policy (deny insecure transport + logging access)
│   ├── bucket/        # S3 bucket with logging, replication, and compliance defaults
│   └── vpc/           # VPC with 2-AZ public/private subnets and NAT gateways
└── stacks/            # Composed stacks for future deployment phases
```

## Prerequisites

- [Terraform](https://www.terraform.io/downloads) >= 1.5
- AWS credentials configured (`aws configure` or environment variables)

## Quick Start

```bash
cd terraform/

# Initialize (backend is commented out — uses local state by default)
terraform init

# Validate configuration
terraform validate

# Format check
terraform fmt -check -recursive

# Plan (requires AWS credentials)
terraform plan
```

## Using Modules

Each module under `modules/` is self-contained and can be called from any stack:

```hcl
module "my_vpc" {
  source = "./modules/vpc"

  vpc_cidr             = "10.0.0.0/16"
  public_subnet_1_cidr = "10.0.0.0/18"
}

module "my_bucket" {
  source = "./modules/bucket"

  app_name = "my-application"
}
```

## Module Composition

Modules compose with each other where appropriate:

- **bucket** calls **bucket-policy** internally for each bucket it creates
- Future modules may reference **vpc** outputs for subnet placement

## Migration Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 0     | Scaffolding + foundational modules (bucket-policy, bucket, vpc) | Current |
| 1+    | Additional modules and composed stacks | Planned |

## Backend Setup

The S3 + DynamoDB backend is commented out in `backend.tf`. Follow the bootstrap instructions in that file to enable remote state.
