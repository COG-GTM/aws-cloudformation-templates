output "instance_id" {
  description = "InstanceId of the newly created EC2 instance"
  value       = aws_instance.ec2_instance.id
}

output "availability_zone" {
  description = "Availability Zone of the newly created EC2 instance"
  value       = aws_instance.ec2_instance.availability_zone
}

output "public_dns" {
  description = "Public DNSName of the newly created EC2 instance"
  value       = aws_instance.ec2_instance.public_dns
}

output "public_ip" {
  description = "Public IP address of the newly created EC2 instance"
  value       = aws_instance.ec2_instance.public_ip
}
