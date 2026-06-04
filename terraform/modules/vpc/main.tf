data "aws_availability_zones" "available" {
  state = "available"
}

# -----------------------------------------------------------------------------
# VPC
# -----------------------------------------------------------------------------

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  instance_tenancy     = "default"
}

# -----------------------------------------------------------------------------
# Internet Gateway
# -----------------------------------------------------------------------------

resource "aws_internet_gateway" "this" {}

resource "aws_internet_gateway_attachment" "this" {
  internet_gateway_id = aws_internet_gateway.this.id
  vpc_id              = aws_vpc.this.id
}

# -----------------------------------------------------------------------------
# Public Subnet 1
# -----------------------------------------------------------------------------

resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_1_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
}

resource "aws_route_table" "public_1" {
  vpc_id = aws_vpc.this.id
}

resource "aws_route_table_association" "public_1" {
  subnet_id      = aws_subnet.public_1.id
  route_table_id = aws_route_table.public_1.id
}

resource "aws_route" "public_1_default" {
  route_table_id         = aws_route_table.public_1.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id

  depends_on = [aws_internet_gateway_attachment.this]
}

resource "aws_eip" "public_1" {
  domain = "vpc"
}

resource "aws_nat_gateway" "public_1" {
  allocation_id = aws_eip.public_1.id
  subnet_id     = aws_subnet.public_1.id

  depends_on = [
    aws_route.public_1_default,
    aws_route_table_association.public_1,
  ]
}

# -----------------------------------------------------------------------------
# Public Subnet 2
# -----------------------------------------------------------------------------

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_2_cidr
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true
}

resource "aws_route_table" "public_2" {
  vpc_id = aws_vpc.this.id
}

resource "aws_route_table_association" "public_2" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public_2.id
}

resource "aws_route" "public_2_default" {
  route_table_id         = aws_route_table.public_2.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id

  depends_on = [aws_internet_gateway_attachment.this]
}

resource "aws_eip" "public_2" {
  domain = "vpc"
}

resource "aws_nat_gateway" "public_2" {
  allocation_id = aws_eip.public_2.id
  subnet_id     = aws_subnet.public_2.id

  depends_on = [
    aws_route.public_2_default,
    aws_route_table_association.public_2,
  ]
}

# -----------------------------------------------------------------------------
# Private Subnet 1
# -----------------------------------------------------------------------------

resource "aws_subnet" "private_1" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.private_subnet_1_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false
}

resource "aws_route_table" "private_1" {
  vpc_id = aws_vpc.this.id
}

resource "aws_route_table_association" "private_1" {
  subnet_id      = aws_subnet.private_1.id
  route_table_id = aws_route_table.private_1.id
}

resource "aws_route" "private_1_default" {
  route_table_id         = aws_route_table.private_1.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.public_1.id
}

# -----------------------------------------------------------------------------
# Private Subnet 2
# -----------------------------------------------------------------------------

resource "aws_subnet" "private_2" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.private_subnet_2_cidr
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = false
}

resource "aws_route_table" "private_2" {
  vpc_id = aws_vpc.this.id
}

resource "aws_route_table_association" "private_2" {
  subnet_id      = aws_subnet.private_2.id
  route_table_id = aws_route_table.private_2.id
}

resource "aws_route" "private_2_default" {
  route_table_id         = aws_route_table.private_2.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.public_2.id
}
