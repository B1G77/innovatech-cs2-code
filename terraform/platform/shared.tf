# Shared services in the hub: config bundle bucket, private AWS endpoints, ops host.

# ---------------- Artifact bucket (Ansible + detector bundle, SSM command output) ----------------
resource "aws_s3_bucket" "artifacts" {
  bucket        = "${var.project}-cs2-artifacts-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-command-output"
    status = "Enabled"
    filter {
      prefix = "ssm-output/"
    }
    expiration {
      days = 30
    }
  }
}

# Ansible playbooks and the detectors travel together as one versioned bundle.
data "archive_file" "bundle" {
  type        = "zip"
  output_path = "${path.module}/.build/bundle.zip"

  source {
    content  = "see ansible/ and detectors/ in the repository"
    filename = "README.txt"
  }

  dynamic "source" {
    for_each = fileset("${path.module}/../../ansible", "**")
    content {
      content  = file("${path.module}/../../ansible/${source.value}")
      filename = "ansible/${source.value}"
    }
  }

  dynamic "source" {
    for_each = fileset("${path.module}/../../detectors", "*.py")
    content {
      content  = file("${path.module}/../../detectors/${source.value}")
      filename = "detectors/${source.value}"
    }
  }
}

resource "aws_s3_object" "bundle" {
  bucket = aws_s3_bucket.artifacts.id
  key    = "bundle/bundle-${data.archive_file.bundle.output_md5}.zip"
  source = data.archive_file.bundle.output_path
  etag   = data.archive_file.bundle.output_md5
}

# ---------------- Private endpoints in the hub ----------------
resource "aws_security_group" "endpoints" {
  name        = "${var.project}-endpoints"
  description = "Interface endpoints: HTTPS from the office and the cloud"
  vpc_id      = aws_vpc.this["shared"].id

  ingress {
    description = "HTTPS from private ranges"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = { Name = "${var.project}-endpoints" }
}

# logs:        the office ships its logs over the VPN, never over the internet
# execute-api: the private SOAR webhook (API Gateway) the detectors call
resource "aws_vpc_endpoint" "interface" {
  for_each = toset(["logs", "execute-api"])

  vpc_id              = aws_vpc.this["shared"].id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.this["shared-private-a"].id, aws_subnet.this["shared-private-b"].id]
  security_group_ids  = [aws_security_group.endpoints.id]

  tags = { Name = "${var.project}-${each.key}-endpoint" }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this["shared"].id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.shared_private.id, aws_route_table.shared_public.id]

  tags = { Name = "${var.project}-s3-endpoint" }
}

# ---------------- Ops host: pipeline runner, Grafana, OpenSearch admin ----------------
resource "aws_iam_role" "ops" {
  name               = "${var.project}-ops-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

# Admin rights because the pipeline applies the whole stack; accepted risk carried over from
# Case Study 1 (the sandbox has no IAM Identity Center for GitHub OIDC roles per repo).
resource "aws_iam_role_policy_attachment" "ops_admin" {
  role       = aws_iam_role.ops.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "ops" {
  name = "${var.project}-ops-profile"
  role = aws_iam_role.ops.name
}

resource "aws_security_group" "ops" {
  name        = "${var.project}-ops"
  description = "Ops host: no inbound, admin access only through SSM"
  vpc_id      = aws_vpc.this["shared"].id

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project}-ops" }
}

resource "random_password" "grafana" {
  length  = 24
  special = false
}

resource "aws_ssm_parameter" "grafana_password" {
  name  = "/${var.project}/grafana/admin-password"
  type  = "SecureString"
  value = random_password.grafana.result
}

resource "aws_s3_object" "grafana_dashboard" {
  bucket = aws_s3_bucket.artifacts.id
  key    = "grafana/innovatech-cs2.json"
  source = "${path.module}/files/grafana_dashboard.json"
  etag   = filemd5("${path.module}/files/grafana_dashboard.json")
}

resource "aws_instance" "ops" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = "t3.small"
  subnet_id              = aws_subnet.this["shared-private-a"].id
  vpc_security_group_ids = [aws_security_group.ops.id]
  iam_instance_profile   = aws_iam_instance_profile.ops.name

  user_data = templatefile("${path.module}/files/ops_user_data.sh.tftpl", {
    region            = var.region
    artifact_bucket   = aws_s3_bucket.artifacts.id
    dashboard_key     = aws_s3_object.grafana_dashboard.key
    grafana_pw_param  = aws_ssm_parameter.grafana_password.name
    os_endpoint       = aws_opensearch_domain.logs.endpoint
    os_master_param   = aws_ssm_parameter.opensearch["admin"].name
    os_ingest_param   = aws_ssm_parameter.opensearch["ingest"].name
    os_grafana_param  = aws_ssm_parameter.opensearch["grafana"].name
    os_retention_days = 30
  })

  root_block_device {
    volume_size = 20
    encrypted   = true
  }

  metadata_options {
    http_tokens = "required"
  }

  # The pipeline runs here: a new AMI or script must not replace it mid-run.
  lifecycle {
    ignore_changes = [ami, user_data]
  }

  tags = {
    Name          = "${var.project}-ops"
    Role          = "ops"
    PatchGroup    = var.project
    SoarProtected = "true"
  }

  depends_on = [aws_nat_gateway.shared, aws_route_table_association.shared]
}
