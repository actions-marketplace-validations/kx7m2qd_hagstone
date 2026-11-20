terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

# Remote modules must never be fetched by a scan (third-party code, network access).
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"
  name    = "main"
  cidr    = "10.0.0.0/16"
}

# --- exposed: anyone on the internet can list and read the bucket
resource "aws_s3_bucket" "uploads" {
  bucket = "acme-user-uploads"
}

resource "aws_s3_bucket_acl" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  # expect: aws-0092
  acl = "public-read"
}

# --- safe: private bucket with every public access block on
resource "aws_s3_bucket" "reports" {
  bucket = "acme-reports"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# --- exposed: SSH open to the world. The inline ignore must not hide it (the repo is untrusted).
resource "aws_security_group" "bastion" {
  name        = "bastion"
  description = "Bastion host"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    #trivy:ignore:AVD-AWS-0107
    # expect: aws-0107
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- safe: SSH only from the office range
resource "aws_security_group" "admin" {
  name        = "admin"
  description = "Admin access"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "SSH from the office"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }
}

# --- exposed: database reachable from the internet, storage unencrypted
resource "aws_db_instance" "orders" {
  identifier          = "orders"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "orders"
  manage_master_user_password = true
  # expect: aws-0180
  publicly_accessible = true
  # expect: aws-0080
  storage_encrypted   = false
}

# --- safe: private, encrypted database
resource "aws_db_instance" "billing" {
  identifier                  = "billing"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "billing"
  manage_master_user_password = true
  publicly_accessible         = false
  storage_encrypted           = true
  backup_retention_period     = 7
  iam_database_authentication_enabled = true
  performance_insights_enabled = true
  deletion_protection         = true
}

# --- exposed: an admin policy (any action on any resource)
resource "aws_iam_policy" "deploy" {
  name = "deploy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      # expect: aws-0057
      Action   = "*"
      Resource = "*"
    }]
  })
}
