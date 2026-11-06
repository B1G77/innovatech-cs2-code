# Hub-and-spoke: the Transit Gateway is the hub. Each spoke gets its own TGW route table,
# so who-can-reach-whom is decided in one place:
#   onprem   -> shared, workload
#   shared   -> onprem, workload        (monitoring and ops must reach everything)
#   workload -> shared, onprem, internet via the hub NAT
# The TGW only routes; it keeps no connection state. "Cloud may answer workstations but
# never open a connection to them" is therefore enforced by the stateful office firewall.
resource "aws_ec2_transit_gateway" "hub" {
  description                     = "Innovatech hub"
  amazon_side_asn                 = 64512
  default_route_table_association = "disable"
  default_route_table_propagation = "disable"
  dns_support                     = "enable"
  vpn_ecmp_support                = "enable"

  tags = { Name = "${var.project}-tgw" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "this" {
  for_each = {
    shared   = ["shared-tgw-a", "shared-tgw-b"]
    workload = ["workload-tgw-a", "workload-tgw-b"]
  }

  transit_gateway_id                              = aws_ec2_transit_gateway.hub.id
  vpc_id                                          = aws_vpc.this[each.key].id
  subnet_ids                                      = [for s in each.value : aws_subnet.this[s].id]
  transit_gateway_default_route_table_association = false
  transit_gateway_default_route_table_propagation = false

  tags = { Name = "${var.project}-tgw-${each.key}" }
}

resource "aws_ec2_transit_gateway_route_table" "this" {
  for_each = toset(["onprem", "shared", "workload"])

  transit_gateway_id = aws_ec2_transit_gateway.hub.id

  tags = { Name = "${var.project}-tgw-rt-${each.key}" }
}

locals {
  vpn_enabled = var.onprem_public_ip != ""

  tgw_attachment = merge({
    shared   = aws_ec2_transit_gateway_vpc_attachment.this["shared"].id
    workload = aws_ec2_transit_gateway_vpc_attachment.this["workload"].id
  }, local.vpn_enabled ? { onprem = aws_vpn_connection.onprem[0].transit_gateway_attachment_id } : {})

  # route table => attachments whose routes it learns (office entries only once the VPN exists)
  tgw_propagation = { for k, v in {
    "onprem/shared"   = { table = "onprem", from = "shared" }
    "onprem/workload" = { table = "onprem", from = "workload" }
    "shared/onprem"   = { table = "shared", from = "onprem" }
    "shared/workload" = { table = "shared", from = "workload" }
    "workload/shared" = { table = "workload", from = "shared" }
    "workload/onprem" = { table = "workload", from = "onprem" }
  } : k => v if contains(keys(local.tgw_attachment), v.table) && contains(keys(local.tgw_attachment), v.from) }
}

resource "aws_ec2_transit_gateway_route_table_association" "this" {
  for_each = local.tgw_attachment

  transit_gateway_attachment_id  = each.value
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.key].id
}

resource "aws_ec2_transit_gateway_route_table_propagation" "this" {
  for_each = local.tgw_propagation

  transit_gateway_attachment_id  = local.tgw_attachment[each.value.from]
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this[each.value.table].id
}

# Central internet exit for workloads through the NAT gateway in the hub.
resource "aws_ec2_transit_gateway_route" "workload_default" {
  destination_cidr_block         = "0.0.0.0/0"
  transit_gateway_attachment_id  = local.tgw_attachment.shared
  transit_gateway_route_table_id = aws_ec2_transit_gateway_route_table.this["workload"].id
}

# ---------------- Site-to-Site VPN to the office (vSphere) ----------------
# Created once var.onprem_public_ip holds the office firewall's public address.
resource "aws_customer_gateway" "onprem" {
  count = local.vpn_enabled ? 1 : 0

  bgp_asn    = var.onprem_bgp_asn
  ip_address = var.onprem_public_ip
  type       = "ipsec.1"

  tags = { Name = "${var.project}-onprem-cgw" }
}

# AWS pre-shared keys: 8-64 characters, letters/digits only here, must not start with 0.
resource "random_password" "vpn_psk" {
  count   = 2
  length  = 40
  special = false
}

locals {
  vpn_psk = [for p in random_password.vpn_psk : "k${p.result}"]
}

resource "aws_vpn_connection" "onprem" {
  count = local.vpn_enabled ? 1 : 0

  customer_gateway_id = aws_customer_gateway.onprem[0].id
  transit_gateway_id  = aws_ec2_transit_gateway.hub.id
  type                = "ipsec.1"
  static_routes_only  = false # BGP: routes are exchanged dynamically and a dead tunnel is routed around

  tunnel1_inside_cidr                  = "169.254.10.0/30"
  tunnel1_preshared_key                = local.vpn_psk[0]
  tunnel1_ike_versions                 = ["ikev2"]
  tunnel1_phase1_encryption_algorithms = ["AES256"]
  tunnel1_phase1_integrity_algorithms  = ["SHA2-256"]
  tunnel1_phase1_dh_group_numbers      = [14]
  tunnel1_phase2_encryption_algorithms = ["AES256"]
  tunnel1_phase2_integrity_algorithms  = ["SHA2-256"]
  tunnel1_phase2_dh_group_numbers      = [14]

  tunnel2_inside_cidr                  = "169.254.11.0/30"
  tunnel2_preshared_key                = local.vpn_psk[1]
  tunnel2_ike_versions                 = ["ikev2"]
  tunnel2_phase1_encryption_algorithms = ["AES256"]
  tunnel2_phase1_integrity_algorithms  = ["SHA2-256"]
  tunnel2_phase1_dh_group_numbers      = [14]
  tunnel2_phase2_encryption_algorithms = ["AES256"]
  tunnel2_phase2_integrity_algorithms  = ["SHA2-256"]
  tunnel2_phase2_dh_group_numbers      = [14]

  tags = { Name = "${var.project}-onprem-vpn" }
}

# The office firewall is configured with these keys; they never go into git.
resource "aws_ssm_parameter" "vpn_psk" {
  count = 2

  name  = "/${var.project}/onprem/vpn-psk-${count.index + 1}"
  type  = "SecureString"
  value = local.vpn_psk[count.index]
}
