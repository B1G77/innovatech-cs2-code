# The SOAR is its own Terraform root with its own pipeline (.github/workflows/soar.yml):
# it can be tested and redeployed without touching the network underneath.
terraform {
  required_version = ">= 1.10"

  backend "s3" {
    bucket       = "innovatech-tfstate-286439316079"
    key          = "cs2/soar.tfstate"
    region       = "eu-central-1"
    profile      = "Goncalo"
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.6"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.profile

  default_tags {
    tags = {
      Project   = var.project
      Case      = "cs2"
      Component = "soar"
      ManagedBy = "terraform"
    }
  }
}

variable "project" {
  type    = string
  default = "innovatech"
}

variable "region" {
  type    = string
  default = "eu-central-1"
}

variable "profile" {
  description = "Local AWS CLI profile (empty in the pipeline)"
  type        = string
  default     = "Goncalo"
}

variable "block_ttl" {
  description = "How long a tier-2 block of an internet address lasts"
  type        = string
  default     = "1h"
}

variable "never_block" {
  description = "Extra addresses tier 2 never blocks: the netlab gateway in front of the office firewall"
  type        = list(string)
  default     = ["192.168.121.1"]
}

variable "max_isolations_per_hour" {
  description = "Circuit breaker: more automatic isolations than this per hour are downgraded to notify"
  type        = number
  default     = 5
}

data "aws_caller_identity" "current" {}

data "terraform_remote_state" "platform" {
  backend = "s3"
  config = {
    bucket  = "innovatech-tfstate-286439316079"
    key     = "cs2/platform.tfstate"
    region  = "eu-central-1"
    profile = var.profile
  }
}

locals {
  platform = data.terraform_remote_state.platform.outputs
  prefix   = "${var.project}-soar"
  account  = data.aws_caller_identity.current.account_id
}
