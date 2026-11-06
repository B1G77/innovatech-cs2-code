# Two cloud networks; the office runs on vSphere and joins through the Site-to-Site VPN (transit.tf):
#   shared   - cloud hub: monitoring, ops host, DNS resolver endpoints, private API endpoint, central NAT.
#   workload - new cloud applications.
locals {
  az_a = "${var.region}a"
  az_b = "${var.region}b"

  vpcs = {
    shared   = "10.30.0.0/16"
    workload = "10.40.0.0/16"
  }

  # The office network on vSphere and its DNS server (the office firewall).
  onprem_cidr   = "10.10.0.0/16"
  onprem_dns_ip = "10.10.0.10"

  subnets = {
    shared-public-a  = { vpc = "shared", cidr = "10.30.0.0/24", az = local.az_a, tier = "public" }
    shared-private-a = { vpc = "shared", cidr = "10.30.10.0/24", az = local.az_a, tier = "private" }
    shared-private-b = { vpc = "shared", cidr = "10.30.11.0/24", az = local.az_b, tier = "private" }
    shared-tgw-a     = { vpc = "shared", cidr = "10.30.255.0/28", az = local.az_a, tier = "tgw" }
    shared-tgw-b     = { vpc = "shared", cidr = "10.30.255.16/28", az = local.az_b, tier = "tgw" }

    workload-app-a = { vpc = "workload", cidr = "10.40.10.0/24", az = local.az_a, tier = "app" }
    workload-app-b = { vpc = "workload", cidr = "10.40.11.0/24", az = local.az_b, tier = "app" }
    workload-tgw-a = { vpc = "workload", cidr = "10.40.255.0/28", az = local.az_a, tier = "tgw" }
    workload-tgw-b = { vpc = "workload", cidr = "10.40.255.16/28", az = local.az_b, tier = "tgw" }
  }
}

resource "aws_vpc" "this" {
  for_each = local.vpcs

  cidr_block           = each.value
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.project}-${each.key}" }
}

resource "aws_subnet" "this" {
  for_each = local.subnets

  vpc_id                  = aws_vpc.this[each.value.vpc].id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project}-${each.key}"
    Tier = each.value.tier
  }
}

resource "aws_internet_gateway" "this" {
  for_each = toset(["shared"])

  vpc_id = aws_vpc.this[each.key].id

  tags = { Name = "${var.project}-${each.key}-igw" }
}

# ---------------- Shared services (hub) routing ----------------
resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${var.project}-nat-eip" }
}

# One NAT gateway for the whole cloud side (central egress through the hub).
resource "aws_nat_gateway" "shared" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.this["shared-public-a"].id

  tags = { Name = "${var.project}-nat" }

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "shared_public" {
  vpc_id = aws_vpc.this["shared"].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this["shared"].id
  }

  route {
    cidr_block         = local.vpcs.workload
    transit_gateway_id = aws_ec2_transit_gateway.hub.id
  }

  route {
    cidr_block         = local.onprem_cidr
    transit_gateway_id = aws_ec2_transit_gateway.hub.id
  }

  tags = { Name = "${var.project}-shared-rt-public" }

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.this]
}

resource "aws_route_table" "shared_private" {
  vpc_id = aws_vpc.this["shared"].id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.shared.id
  }

  route {
    cidr_block         = local.vpcs.workload
    transit_gateway_id = aws_ec2_transit_gateway.hub.id
  }

  route {
    cidr_block         = local.onprem_cidr
    transit_gateway_id = aws_ec2_transit_gateway.hub.id
  }

  tags = { Name = "${var.project}-shared-rt-private" }

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.this]
}

# Traffic arriving from the TGW (workloads going to the internet) leaves through the NAT.
# Its own table on purpose: S3 gateway endpoints do not accept traffic that comes in through
# a Transit Gateway, so the S3 endpoint route must not be in this table (found in testing:
# app servers could not reach the Amazon Linux repositories, which live on S3).
resource "aws_route_table" "shared_tgw" {
  vpc_id = aws_vpc.this["shared"].id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.shared.id
  }

  tags = { Name = "${var.project}-shared-rt-tgw" }
}

resource "aws_route_table_association" "shared" {
  for_each = {
    shared-public-a  = aws_route_table.shared_public.id
    shared-private-a = aws_route_table.shared_private.id
    shared-private-b = aws_route_table.shared_private.id
    shared-tgw-a     = aws_route_table.shared_tgw.id
    shared-tgw-b     = aws_route_table.shared_tgw.id
  }

  subnet_id      = aws_subnet.this[each.key].id
  route_table_id = each.value
}

# ---------------- Workload routing: no own internet exit, everything via the hub ----------------
resource "aws_route_table" "workload" {
  vpc_id = aws_vpc.this["workload"].id

  route {
    cidr_block         = "0.0.0.0/0"
    transit_gateway_id = aws_ec2_transit_gateway.hub.id
  }

  tags = { Name = "${var.project}-workload-rt" }

  depends_on = [aws_ec2_transit_gateway_vpc_attachment.this]
}

resource "aws_route_table_association" "workload" {
  for_each = toset(["workload-app-a", "workload-app-b", "workload-tgw-a", "workload-tgw-b"])

  subnet_id      = aws_subnet.this[each.key].id
  route_table_id = aws_route_table.workload.id
}
