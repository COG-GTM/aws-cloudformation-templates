output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.this.id
}

output "public_subnet_1_id" {
  description = "The ID of public subnet 1"
  value       = aws_subnet.public_1.id
}

output "public_subnet_2_id" {
  description = "The ID of public subnet 2"
  value       = aws_subnet.public_2.id
}

output "private_subnet_1_id" {
  description = "The ID of private subnet 1"
  value       = aws_subnet.private_1.id
}

output "private_subnet_2_id" {
  description = "The ID of private subnet 2"
  value       = aws_subnet.private_2.id
}

output "nat_gateway_1_id" {
  description = "The ID of NAT gateway 1"
  value       = aws_nat_gateway.public_1.id
}

output "nat_gateway_2_id" {
  description = "The ID of NAT gateway 2"
  value       = aws_nat_gateway.public_2.id
}
