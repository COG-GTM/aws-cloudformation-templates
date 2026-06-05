variable "key_name" {
  description = "Name of an existing EC2 KeyPair to enable SSH access to the instance"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.small"

  validation {
    condition = contains([
      "t2.nano", "t2.micro", "t2.small", "t2.medium", "t2.large",
      "t2.xlarge", "t2.2xlarge",
      "t3.nano", "t3.micro", "t3.small", "t3.medium", "t3.large",
      "t3.xlarge", "t3.2xlarge",
      "m4.large", "m4.xlarge", "m4.2xlarge", "m4.4xlarge", "m4.10xlarge",
      "m5.large", "m5.xlarge", "m5.2xlarge", "m5.4xlarge",
      "c5.large", "c5.xlarge", "c5.2xlarge", "c5.4xlarge", "c5.9xlarge",
      "g3.8xlarge",
      "r5.large", "r5.xlarge", "r5.2xlarge", "r5.4xlarge",
      "i3.xlarge", "i3.2xlarge", "i3.4xlarge", "i3.8xlarge",
      "d2.xlarge", "d2.2xlarge", "d2.4xlarge", "d2.8xlarge",
    ], var.instance_type)
    error_message = "Must be a valid EC2 instance type."
  }
}

variable "ssh_location" {
  description = "The IP address range that can be used to SSH to the EC2 instances"
  type        = string
  default     = "192.168.1.0/0"

  validation {
    condition     = can(cidrhost(var.ssh_location, 0))
    error_message = "Must be a valid IP CIDR range of the form x.x.x.x/x."
  }
}

variable "ami_ssm_parameter" {
  description = "SSM parameter name for the latest AMI ID"
  type        = string
  default     = "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
}

variable "subnet_ids" {
  description = "List of subnet IDs"
  type        = list(string)
}
