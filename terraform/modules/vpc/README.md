# vpc

Creates a VPC with 2-AZ public/private subnet topology, NAT gateways, and route tables.

Converted from `RainModules/vpc.yml`.

## Architecture

- 1 VPC with DNS hostnames and DNS support enabled
- 1 Internet Gateway
- 2 Public subnets (one per AZ) with auto-assign public IP
- 2 Private subnets (one per AZ)
- 2 Elastic IPs (one per NAT gateway)
- 2 NAT Gateways (one per public subnet, serving the corresponding private subnet)
- 4 Route tables (one per subnet)
- Public subnets route `0.0.0.0/0` to the Internet Gateway
- Private subnets route `0.0.0.0/0` to the NAT Gateway in the same AZ

## Usage

```hcl
module "my_vpc" {
  source = "../vpc"

  vpc_cidr              = "10.0.0.0/16"
  public_subnet_1_cidr  = "10.0.0.0/18"
  public_subnet_2_cidr  = "10.0.64.0/18"
  private_subnet_1_cidr = "10.0.128.0/18"
  private_subnet_2_cidr = "10.0.192.0/18"
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|----------|
| `vpc_cidr` | CIDR block for the VPC | `string` | `10.0.0.0/16` | no |
| `public_subnet_1_cidr` | CIDR block for public subnet 1 | `string` | `10.0.0.0/18` | no |
| `public_subnet_2_cidr` | CIDR block for public subnet 2 | `string` | `10.0.64.0/18` | no |
| `private_subnet_1_cidr` | CIDR block for private subnet 1 | `string` | `10.0.128.0/18` | no |
| `private_subnet_2_cidr` | CIDR block for private subnet 2 | `string` | `10.0.192.0/18` | no |

## Outputs

| Name | Description |
|------|-------------|
| `vpc_id` | The ID of the VPC |
| `public_subnet_1_id` | The ID of public subnet 1 |
| `public_subnet_2_id` | The ID of public subnet 2 |
| `private_subnet_1_id` | The ID of private subnet 1 |
| `private_subnet_2_id` | The ID of private subnet 2 |
| `nat_gateway_1_id` | The ID of NAT gateway 1 |
| `nat_gateway_2_id` | The ID of NAT gateway 2 |
