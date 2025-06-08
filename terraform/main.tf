# ============================================================================
# DATA SOURCES
# ============================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# ============================================================================
# LOCALS
# ============================================================================

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name

  # Network configuration
  public_subnets = [
    "10.0.1.0/24",
    "10.0.2.0/24",
    "10.0.3.0/24"
  ]

  private_subnets = [
    "10.0.10.0/24",
    "10.0.20.0/24",
    "10.0.30.0/24"
  ]

  database_subnets = [
    "10.0.80.0/24",
    "10.0.100.0/24",
    "10.0.120.0/24"
  ]

  # Common tags merged with resource-specific tags
  common_tags = merge(var.common_tags, {
    AccountId = local.account_id
    Region    = local.region
  })
}

# ============================================================================
# AWS ORGANIZATIONS (Master Account Only)
# ============================================================================

# Organizations setup (only run in master account)
resource "aws_organizations_organization" "main" {
  count = var.environment == "master" ? 1 : 0

  aws_service_access_principals = [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "sso.amazonaws.com",
    "account.amazonaws.com"
  ]

  feature_set = "ALL"
}

# Organizational Units
resource "aws_organizations_organizational_unit" "security" {
  count     = var.environment == "master" ? 1 : 0
  name      = "Security"
  parent_id = aws_organizations_organization.main[0].roots[0].id

  tags = local.common_tags
}

resource "aws_organizations_organizational_unit" "shared_services" {
  count     = var.environment == "master" ? 1 : 0
  name      = "SharedServices"
  parent_id = aws_organizations_organization.main[0].roots[0].id

  tags = local.common_tags
}

resource "aws_organizations_organizational_unit" "log_archive" {
  count     = var.environment == "master" ? 1 : 0
  name      = "LogArchive"
  parent_id = aws_organizations_organization.main[0].roots[0].id

  tags = local.common_tags
}

resource "aws_organizations_organizational_unit" "workloads" {
  count     = var.environment == "master" ? 1 : 0
  name      = "Workloads"
  parent_id = aws_organizations_organization.main[0].roots[0].id

  tags = local.common_tags
}

# ============================================================================
# Service Control Policies
# ============================================================================

resource "aws_organizations_policy" "deny_root_access" {
  count = var.environment == "master" ? 1 : 0

  name        = "DenyRootAccess"
  description = "Deny root user access"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Deny"
        Principal = {
          AWS = "*"
        }
        Action   = "*"
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:PrincipalType" = "Root"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_organizations_policy" "prevent_leaving_org" {
  count = var.environment == "master" ? 1 : 0

  name        = "PreventLeavingOrganization"
  description = "Prevent member accounts from leaving the organization"

  content = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "DenyLeaveOrganization",
        Effect = "Deny",
        Action = [
          "organizations:LeaveOrganization"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_organizations_policy" "region_restriction" {
  count = var.environment == "master" ? 1 : 0

  name        = "RegionRestriction"
  description = "Limit AWS regions to approved locations"

  content = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "DenyUnapprovedRegions",
        Effect = "Deny",
        NotAction = [
          "a4b:*",
          "acm:*",
          "aws-marketplace:*",
          "aws-portal:*",
          "budgets:*",
          "ce:*",
          "chime:*",
          "cloudfront:*",
          "config:*",
          "cur:*",
          "directconnect:*",
          "ec2:Describe*",
          "fms:*",
          "globalaccelerator:*",
          "health:*",
          "iam:*",
          "importexport:*",
          "kms:*",
          "mobileanalytics:*",
          "networkmanager:*",
          "organizations:*",
          "pricing:*",
          "route53:*",
          "s3:Get*",
          "s3:List*",
          "s3:Describe*",
          "shield:*",
          "sts:*",
          "support:*",
          "trustedadvisor:*",
          "waf-regional:*",
          "waf:*",
          "wafv2:*"
        ],
        Resource = "*",
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = [
              "us-east-1", # Primary region
              "us-west-2", # DR region
              "eu-west-1"  # Compliance region
            ]
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy" "s3_encryption" {
  count = var.environment == "master" ? 1 : 0

  name        = "S3EncryptionRequirement"
  description = "Enforce S3 bucket encryption"

  content = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "DenyUnencryptedS3",
        Effect = "Deny",
        Action = [
          "s3:PutObject",
          "s3:CreateBucket"
        ],
        Resource = "*",
        Condition = {
          Null = {
            "s3:x-amz-server-side-encryption" = "true"
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy" "prevent_critical_deletion" {
  count = var.environment == "master" ? 1 : 0

  name        = "PreventCriticalDeletion"
  description = "Block deletion of key resources"

  content = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "DenyDeletingVPCs",
        Effect = "Deny",
        Action = [
          "ec2:DeleteVpc",
          "ec2:DeleteVpcEndpoints"
        ],
        Resource = "*"
      },
      {
        Sid    = "DenyDeletingLogs",
        Effect = "Deny",
        Action = [
          "logs:DeleteLogGroup",
          "logs:DeleteLogStream"
        ],
        Resource = "*"
      },
      {
        Sid    = "DenyDeletingIAM",
        Effect = "Deny",
        Action = [
          "iam:DeleteUser",
          "iam:DeleteRole",
          "iam:DeletePolicy"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_organizations_policy" "require_mfa" {
  count = var.environment == "master" ? 1 : 0

  name        = "RequireMFAForPrivilegedActions"
  description = "Enforce MFA for sensitive operations"

  content = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "DenyNoMFA",
        Effect = "Deny",
        Action = [
          "iam:*",
          "ec2:*",
          "rds:*",
          "s3:*",
          "kms:*"
        ],
        Resource = "*",
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_organizations_policy" "block_public_s3" {
  count = var.environment == "master" ? 1 : 0

  name        = "BlockPublicS3Access"
  description = "Prevent S3 buckets from being made public"

  content = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "DenyPublicS3",
        Effect = "Deny",
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketPolicy"
        ],
        Resource = "*",
        Condition = {
          StringNotEquals = {
            "s3:x-amz-acl" = "private"
          }
        }
      }
    ]
  })
}

# ============================================================================
# IAM ROLES AND POLICIES
# ============================================================================

# Cross-account assume role for organization access
resource "aws_iam_role" "organization_access_role" {
  name = "${var.organization_name}-organization-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = [for account_id in var.allowed_account_ids : "arn:aws:iam::${account_id}:root"]
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "${var.organization_name}-external-id"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

# CloudTrail service role
resource "aws_iam_role" "cloudtrail_role" {
  name = "${var.organization_name}-cloudtrail-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "cloudtrail_policy" {
  name = "${var.organization_name}-cloudtrail-policy"
  role = aws_iam_role.cloudtrail_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# ============================================================================
# VPC AND NETWORKING
# ============================================================================

# Main VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "${var.organization_name}-vpc"
  })
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${var.organization_name}-igw"
  })
}

# Public Subnets
resource "aws_subnet" "public" {
  count = length(local.public_subnets)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_subnets[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = merge(local.common_tags, {
    Name = "${var.organization_name}-public-subnet-${count.index + 1}"
    Tier = "Public"
  })
}

# Private Subnets
resource "aws_subnet" "private" {
  count = length(local.private_subnets)

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_subnets[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(local.common_tags, {
    Name = "${var.organization_name}-private-subnet-${count.index + 1}"
    Tier = "Private"
  })
}

# Database Subnets
resource "aws_subnet" "database" {
  count = length(local.database_subnets)

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.database_subnets[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(local.common_tags, {
    Name = "${var.organization_name}-database-subnet-${count.index + 1}"
    Tier = "Database"
  })
}

# NAT Gateways
resource "aws_eip" "nat" {
  count  = length(aws_subnet.public)
  domain = "vpc"

  depends_on = [aws_internet_gateway.main]

  tags = merge(local.common_tags, {
    Name = "${var.organization_name}-nat-eip-${count.index + 1}"
  })
}

resource "aws_nat_gateway" "main" {
  count = length(aws_subnet.public)

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  depends_on = [aws_internet_gateway.main]

  tags = merge(local.common_tags, {
    Name = "${var.organization_name}-nat-gw-${count.index + 1}"
  })
}

# Route Tables
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = merge(local.common_tags, {
    Name = "${var.organization_name}-public-rt"
  })
}

resource "aws_route_table" "private" {
  count  = length(aws_nat_gateway.main)
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }

  tags = merge(local.common_tags, {
    Name = "${var.organization_name}-private-rt-${count.index + 1}"
  })
}

# Route Table Associations
resource "aws_route_table_association" "public" {
  count = length(aws_subnet.public)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# VPC Flow Logs
resource "aws_flow_log" "vpc_flow_log" {
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_log.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "vpc_flow_log" {
  name              = "/aws/vpc/flowlogs"
  retention_in_days = 30

  tags = local.common_tags
}

resource "aws_iam_role" "flow_log_role" {
  name = "${var.organization_name}-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "flow_log_policy" {
  name = "${var.organization_name}-flow-log-policy"
  role = aws_iam_role.flow_log_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# ============================================================================
# SECURITY GROUPS
# ============================================================================

# Web tier security group
resource "aws_security_group" "web_tier" {
  name_prefix = "${var.organization_name}-web-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for web tier"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(local.common_tags, {
    Name = "${var.organization_name}-web-sg"
    Tier = "Web"
  })
}

# Application tier security group
resource "aws_security_group" "app_tier" {
  name_prefix = "${var.organization_name}-app-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for application tier"

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web_tier.id]
    description     = "Application port from web tier"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(local.common_tags, {
    Name = "${var.organization_name}-app-sg"
    Tier = "Application"
  })
}

# Database tier security group
resource "aws_security_group" "db_tier" {
  name_prefix = "${var.organization_name}-db-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for database tier"

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_tier.id]
    description     = "MySQL from application tier"
  }

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_tier.id]
    description     = "PostgreSQL from application tier"
  }

  tags = merge(local.common_tags, {
    Name = "${var.organization_name}-db-sg"
    Tier = "Database"
  })
}

# ============================================================================
# LOGGING AND MONITORING
# ============================================================================

# S3 bucket for CloudTrail logs
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "${var.organization_name}-cloudtrail-logs-${random_id.bucket_suffix.hex}"
  force_destroy = false

  tags = local.common_tags
}

resource "random_id" "bucket_suffix" {
  byte_length = 8
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# resource "aws_s3_bucket_encryption" "cloudtrail_logs" {
#   bucket = aws_s3_bucket.cloudtrail_logs.id

#   server_side_encryption_configuration {
#     rule {
#       apply_server_side_encryption_by_default {
#         sse_algorithm = "AES256"
#       }
#     }
#   }
# }

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# CloudTrail
resource "aws_cloudtrail" "main" {
  name           = "${var.organization_name}-cloudtrail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.bucket

  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  event_selector {
    read_write_type                  = "All"
    include_management_events        = true
    exclude_management_event_sources = []

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/*"]
    }
  }

  tags = local.common_tags
}

# Config Service
resource "aws_config_configuration_recorder" "main" {
  name     = "${var.organization_name}-config-recorder"
  role_arn = aws_iam_role.config_role.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.organization_name}-config-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config_logs.bucket
}

resource "aws_s3_bucket" "config_logs" {
  bucket        = "${var.organization_name}-config-logs-${random_id.config_bucket_suffix.hex}"
  force_destroy = false

  tags = local.common_tags
}

resource "random_id" "config_bucket_suffix" {
  byte_length = 8
}

resource "aws_s3_bucket_versioning" "config_logs" {
  bucket = aws_s3_bucket.config_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# resource "aws_s3_bucket_encryption" "config_logs" {
#   bucket = aws_s3_bucket.config_logs.id

#   server_side_encryption_configuration {
#     rule {
#       apply_server_side_encryption_by_default {
#         sse_algorithm = "AES256"
#       }
#     }
#   }
# }

resource "aws_iam_role" "config_role" {
  name = "${var.organization_name}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "config_role_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

# GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = local.common_tags
}

# ============================================================================
# BACKUP AND DISASTER RECOVERY
# ============================================================================

# Backup vault
resource "aws_backup_vault" "main" {
  name        = "${var.organization_name}-backup-vault"
  kms_key_arn = aws_kms_key.backup.arn

  tags = local.common_tags
}

# Backup KMS key
resource "aws_kms_key" "backup" {
  description             = "KMS key for backup encryption"
  deletion_window_in_days = 7

  tags = local.common_tags
}

resource "aws_kms_alias" "backup" {
  name          = "alias/${var.organization_name}-backup"
  target_key_id = aws_kms_key.backup.key_id
}

# Backup plan
resource "aws_backup_plan" "main" {
  name = "${var.organization_name}-backup-plan"

  rule {
    rule_name         = "daily_backup"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 5 ? * * *)"

    recovery_point_tags = local.common_tags

    lifecycle {
      cold_storage_after = 30
      delete_after       = 120
    }
  }

  tags = local.common_tags
}

# Backup IAM role
resource "aws_iam_role" "backup_role" {
  name = "${var.organization_name}-backup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "backup_policy" {
  role       = aws_iam_role.backup_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}