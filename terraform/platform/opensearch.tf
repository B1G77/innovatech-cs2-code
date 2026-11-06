# Central log and security-event database: Amazon OpenSearch Service.
# Two data nodes in two AZs with one replica per shard, so losing a node or an AZ loses no data.
# Logs arrive through CloudWatch Logs subscriptions (the indexer Lambda, terraform/soar).
resource "aws_security_group" "opensearch" {
  name        = "${var.project}-opensearch"
  description = "Log database: HTTPS from the hub only (ops host, indexer)"
  vpc_id      = aws_vpc.this["shared"].id

  ingress {
    description = "HTTPS from the hub"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = [local.vpcs.shared]
  }

  tags = { Name = "${var.project}-opensearch" }
}

# admin: break-glass and Dashboards login; ingest: write-only for the indexer; grafana: read-only.
resource "random_password" "opensearch" {
  for_each = toset(["admin", "ingest", "grafana"])

  length           = 24
  special          = true
  override_special = "_-"
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 1
}

resource "aws_ssm_parameter" "opensearch" {
  for_each = random_password.opensearch

  name  = "/${var.project}/opensearch/${each.key}-password"
  type  = "SecureString"
  value = each.value.result
}

resource "aws_opensearch_domain" "logs" {
  domain_name    = "${var.project}-logs"
  engine_version = "OpenSearch_2.19"

  cluster_config {
    instance_type          = var.opensearch_instance_type
    instance_count         = 2
    zone_awareness_enabled = true

    zone_awareness_config {
      availability_zone_count = 2
    }
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = 10
  }

  vpc_options {
    subnet_ids         = [aws_subnet.this["shared-private-a"].id, aws_subnet.this["shared-private-b"].id]
    security_group_ids = [aws_security_group.opensearch.id]
  }

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  # Fine-grained access control decides who may do what; the network (VPC + SG) decides who may connect.
  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true

    master_user_options {
      master_user_name     = "admin"
      master_user_password = random_password.opensearch["admin"].result
    }
  }

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "es:ESHttp*"
      Resource  = "arn:aws:es:${var.region}:${data.aws_caller_identity.current.account_id}:domain/${var.project}-logs/*"
    }]
  })

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch_errors.arn
    log_type                 = "ES_APPLICATION_LOGS"
  }

  tags = { Name = "${var.project}-logs" }

  depends_on = [aws_cloudwatch_log_resource_policy.opensearch]
}

resource "aws_cloudwatch_log_group" "opensearch_errors" {
  name              = "/${var.project}/opensearch/errors"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_resource_policy" "opensearch" {
  policy_name = "${var.project}-opensearch-logs"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "es.amazonaws.com" }
      Action    = ["logs:PutLogEvents", "logs:CreateLogStream"]
      Resource  = "${aws_cloudwatch_log_group.opensearch_errors.arn}:*"
    }]
  })
}
