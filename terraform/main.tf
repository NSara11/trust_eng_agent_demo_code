# main.tf — Intentionally vulnerable Terraform IaC for IaC scanner testing
# ==========================================================================
#
# IaC-1 (Checkov CKV_AWS_18 / CKV_AWS_21):
#   S3 bucket has no server-side encryption, no versioning,
#   no public-access block — world-readable.
#
# IaC-2 (Checkov CKV_AWS_25 / CKV_AWS_23):
#   Security group allows ALL inbound traffic from 0.0.0.0/0 on port 22 (SSH)
#   and port 3306 (MySQL) — fully open to the internet.
#
# IaC-3 (Checkov CKV_AWS_17 / CKV_AWS_157):
#   RDS instance has no storage encryption, no deletion protection,
#   publicly_accessible = true, and no automated backups.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region     = "us-east-1"
  # IaC: credentials hardcoded (should use IAM role or env vars)
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# ── IaC-1: S3 bucket — no encryption, public access allowed ──────────────────
resource "aws_s3_bucket" "user_data" {
  bucket = "vulnapp-user-pii-data"
  # CKV_AWS_21: no versioning
  # CKV_AWS_18: no access logging
  # CKV_AWS_145: no SSE-KMS encryption

  tags = {
    Environment = "production"
    DataClass   = "PII"
  }
}

# IaC-1: No aws_s3_bucket_server_side_encryption_configuration defined
# IaC-1: No aws_s3_bucket_public_access_block defined → bucket is public

resource "aws_s3_bucket_acl" "user_data_acl" {
  bucket = aws_s3_bucket.user_data.id
  # CKV_AWS_57: public-read ACL — anyone can list and download PII objects
  acl    = "public-read"
}

# ── IaC-2: Security group — SSH and DB open to the world ─────────────────────
resource "aws_security_group" "open_sg" {
  name        = "vulnapp-open-sg"
  description = "Unrestricted inbound access"

  # CKV_AWS_25: SSH (22) open to 0.0.0.0/0
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # CKV_AWS_23: MySQL (3306) open to 0.0.0.0/0
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # All outbound allowed — CKV_AWS_382 (unrestricted egress)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ── IaC-3: RDS — no encryption, publicly accessible, no backups ──────────────
resource "aws_db_instance" "user_db" {
  identifier        = "vulnapp-userdb"
  engine            = "mysql"
  engine_version    = "5.7"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "users"
  username = "admin"
  # IaC-3: plaintext password in Terraform (should use aws_secretsmanager_secret)
  password = "Sup3rS3cr3tP@ssw0rd!"

  # CKV_AWS_17: storage_encrypted = false (default) — PII data unencrypted at rest
  storage_encrypted = false

  # CKV_AWS_157: deletion_protection = false — DB can be deleted accidentally
  deletion_protection = false

  # CKV_AWS_133: backup_retention_period = 0 — no automated backups
  backup_retention_period = 0

  # CKV_AWS_17: publicly_accessible = true — DB reachable from internet
  publicly_accessible = true

  vpc_security_group_ids = [aws_security_group.open_sg.id]

  skip_final_snapshot = true

  tags = {
    Environment = "production"
    DataClass   = "PII"
  }
}

# ── Missing controls (additional Checkov findings expected) ───────────────────
# No aws_cloudtrail resource → no audit logging (CKV_AWS_67)
# No aws_kms_key for RDS/S3 encryption
# No MFA delete on S3 bucket (CKV_AWS_21)
