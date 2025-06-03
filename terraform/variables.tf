# ============================================================================
# VARIABLES
# ============================================================================

variable "organization_name" {
  description = "Name of the organization"
  type        = string
  default     = "acme-corp"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "primary_region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
}

variable "secondary_region" {
  description = "Secondary AWS region for DR"
  type        = string
  default     = "us-west-2"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones to use"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "allowed_account_ids" {
  description = "List of allowed AWS account IDs"
  type        = list(string)
  default     = []
}

variable "common_tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Project     = "landing-zone"
    Environment = "production"
    Owner       = "platform-team"
    ManagedBy   = "terraform"
  }
}