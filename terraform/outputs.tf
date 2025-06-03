# ============================================================================
# OUTPUTS
# ============================================================================

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "database_subnet_ids" {
  description = "IDs of the database subnets"
  value       = aws_subnet.database[*].id
}

output "security_group_web_id" {
  description = "ID of the web tier security group"
  value       = aws_security_group.web_tier.id
}

output "security_group_app_id" {
  description = "ID of the application tier security group"
  value       = aws_security_group.app_tier.id
}

output "security_group_db_id" {
  description = "ID of the database tier security group"
  value       = aws_security_group.db_tier.id
}

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail"
  value       = aws_cloudtrail.main.arn
}

output "backup_vault_arn" {
  description = "ARN of the backup vault"
  value       = aws_backup_vault.main.arn
}

output "organization_id" {
  description = "ID of the AWS Organization"
  value       = var.environment == "master" ? aws_organizations_organization.main[0].id : null
}