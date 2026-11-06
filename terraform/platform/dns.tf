# Two private zones, one on each side, resolvable from both:
#   cloud.innovatech.internal  - Route 53 private hosted zone (cloud services)
#   corp.innovatech.lan        - served by the office firewall on vSphere
# The cloud side forwards corp.* to the office (outbound endpoint + rule); the office
# forwards cloud.* to Route 53 (inbound endpoint). Same split as a real hybrid network.
resource "aws_route53_zone" "cloud" {
  name    = "cloud.innovatech.internal"
  comment = "Private names for cloud services"

  vpc {
    vpc_id = aws_vpc.this["shared"].id
  }

  vpc {
    vpc_id = aws_vpc.this["workload"].id
  }
}

resource "aws_route53_record" "app" {
  zone_id = aws_route53_zone.cloud.zone_id
  name    = "app.cloud.innovatech.internal"
  type    = "A"

  alias {
    name                   = aws_lb.app.dns_name
    zone_id                = aws_lb.app.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "ops" {
  zone_id = aws_route53_zone.cloud.zone_id
  name    = "ops.cloud.innovatech.internal"
  type    = "A"
  ttl     = 60
  records = [aws_instance.ops.private_ip]
}

resource "aws_route53_record" "search" {
  zone_id = aws_route53_zone.cloud.zone_id
  name    = "search.cloud.innovatech.internal"
  type    = "CNAME"
  ttl     = 300
  records = [aws_opensearch_domain.logs.endpoint]
}

resource "aws_security_group" "resolver" {
  name        = "${var.project}-resolver"
  description = "Route 53 Resolver endpoints: DNS to and from the office"
  vpc_id      = aws_vpc.this["shared"].id

  tags = { Name = "${var.project}-resolver" }
}

resource "aws_vpc_security_group_ingress_rule" "resolver" {
  for_each = toset(["udp", "tcp"])

  security_group_id = aws_security_group.resolver.id
  description       = "DNS queries from the office"
  ip_protocol       = each.key
  from_port         = 53
  to_port           = 53
  cidr_ipv4         = local.onprem_cidr
}

resource "aws_vpc_security_group_egress_rule" "resolver" {
  for_each = toset(["udp", "tcp"])

  security_group_id = aws_security_group.resolver.id
  description       = "Forwarded queries to the office DNS"
  ip_protocol       = each.key
  from_port         = 53
  to_port           = 53
  cidr_ipv4         = local.onprem_cidr
}

resource "aws_route53_resolver_endpoint" "inbound" {
  name               = "${var.project}-inbound"
  direction          = "INBOUND"
  security_group_ids = [aws_security_group.resolver.id]

  ip_address {
    subnet_id = aws_subnet.this["shared-private-a"].id
    ip        = "10.30.10.53"
  }

  ip_address {
    subnet_id = aws_subnet.this["shared-private-b"].id
    ip        = "10.30.11.53"
  }
}

resource "aws_route53_resolver_endpoint" "outbound" {
  name               = "${var.project}-outbound"
  direction          = "OUTBOUND"
  security_group_ids = [aws_security_group.resolver.id]

  ip_address {
    subnet_id = aws_subnet.this["shared-private-a"].id
  }

  ip_address {
    subnet_id = aws_subnet.this["shared-private-b"].id
  }
}

resource "aws_route53_resolver_rule" "corp" {
  name                 = "${var.project}-corp"
  domain_name          = "corp.innovatech.lan"
  rule_type            = "FORWARD"
  resolver_endpoint_id = aws_route53_resolver_endpoint.outbound.id

  target_ip {
    ip = local.onprem_dns_ip
  }
}

resource "aws_route53_resolver_rule_association" "corp" {
  for_each = toset(["shared", "workload"])

  resolver_rule_id = aws_route53_resolver_rule.corp.id
  vpc_id           = aws_vpc.this[each.key].id
}

# Carried over from Case Study 1: validate DNSSEC signatures on public names.
resource "aws_route53_resolver_dnssec_config" "this" {
  for_each = toset(["shared", "workload"])

  resource_id = aws_vpc.this[each.key].id
}
