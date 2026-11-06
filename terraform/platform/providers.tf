terraform {
  required_version = ">= 1.10"

  # Same state bucket as Case Study 1 (created by its bootstrap stack), separate key.
  backend "s3" {
    bucket       = "innovatech-tfstate-286439316079"
    key          = "cs2/platform.tfstate"
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
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}
