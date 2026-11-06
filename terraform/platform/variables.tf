variable "project" {
  description = "Name prefix used on every resource"
  type        = string
  default     = "innovatech"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-central-1"
}

variable "profile" {
  description = "Local AWS CLI profile (empty in the pipeline, which uses the ops host role)"
  type        = string
  default     = "Goncalo"
}

variable "alert_email" {
  description = "Where alarm and SOAR notifications are sent. Set in terraform.tfvars (not in git)."
  type        = string
}

variable "onprem_bgp_asn" {
  description = "BGP AS number of the office firewall on vSphere (private range)"
  type        = number
  default     = 65010
}

variable "onprem_public_ip" {
  description = "Public address fw01 on vSphere leaves through (the netlab NAT). Empty = no VPN (cloud only)."
  type        = string
  default     = "145.220.75.5"
}

variable "opensearch_instance_type" {
  description = "Data node size of the log database (two nodes, one per AZ)"
  type        = string
  default     = "t3.medium.search"
}

variable "onprem_outside_cidrs" {
  description = "Private ranges outside the office firewall that count as 'internet' (the netlab WAN segment)"
  type        = list(string)
  default     = ["192.168.121.0/24"]
}
