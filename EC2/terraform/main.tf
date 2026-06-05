terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {}

data "aws_ssm_parameter" "latest_ami" {
  name = var.ami_ssm_parameter
}

data "aws_subnet" "selected" {
  id = var.subnet_ids[0]
}

resource "aws_security_group" "instance_sg" {
  description = "Enable SSH access via port 22"
  vpc_id      = data.aws_subnet.selected.vpc_id

  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = [var.ssh_location]
  }
}

resource "aws_instance" "ec2_instance" {
  ami                    = data.aws_ssm_parameter.latest_ami.value
  instance_type          = var.instance_type
  subnet_id              = var.subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.instance_sg.id]
  key_name               = var.key_name
}
