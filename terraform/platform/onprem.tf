# What AWS needs to manage the office on Fontys vSphere (REQ-NCA-P2-08: not on the SOAR's platform).
# The VMs and their SSM registration live in terraform/office; this file holds:
#   * the IAM roles an office VM gets when it registers as an SSM managed node (mi-...);
#   * the VPN settings fw01's Ansible role reads, so a rebuilt VPN reconfigures the office.

# ---------------- IAM: what an office node may do ----------------
data "aws_iam_policy_document" "ssm_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "onprem" {
  for_each = toset(["firewall", "host"])

  name               = "${var.project}-onprem-${each.key}-role"
  assume_role_policy = data.aws_iam_policy_document.ssm_assume.json
}

resource "aws_iam_role_policy_attachment" "onprem_ssm" {
  for_each = aws_iam_role.onprem

  role       = each.value.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "onprem" {
  for_each = aws_iam_role.onprem

  name = "${var.project}-onprem-${each.key}"
  role = each.value.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "ShipLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
        Resource = "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/${var.project}/onprem/*"
      },
      {
        Sid      = "ReadWebhookSettings"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${var.project}/soar/*"
      },
      {
        Sid      = "ReadConfigBundle"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
      },
      {
        # Run Command output, including the SOAR's forensic capture (no EBS snapshot on vSphere).
        Sid      = "WriteCommandOutput"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = ["${aws_s3_bucket.artifacts.arn}/ssm-output/*", "${aws_s3_bucket.artifacts.arn}/soar-forensics/*"]
      },
      ], each.key == "firewall" ? [{
        Sid      = "ReadVpnSettings"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${var.project}/onprem/*"
    }] : [])
  })
}

# ---------------- VPN settings for the office firewall ----------------
resource "aws_ssm_parameter" "vpn_config" {
  count = local.vpn_enabled ? 1 : 0

  name = "/${var.project}/onprem/vpn-config"
  type = "String"
  value = jsonencode({
    public_ip     = var.onprem_public_ip
    onprem_asn    = var.onprem_bgp_asn
    aws_asn       = aws_ec2_transit_gateway.hub.amazon_side_asn
    t1_outside    = aws_vpn_connection.onprem[0].tunnel1_address
    t2_outside    = aws_vpn_connection.onprem[0].tunnel2_address
    t1_cgw_inside = aws_vpn_connection.onprem[0].tunnel1_cgw_inside_address
    t2_cgw_inside = aws_vpn_connection.onprem[0].tunnel2_cgw_inside_address
    t1_aws_inside = aws_vpn_connection.onprem[0].tunnel1_vgw_inside_address
    t2_aws_inside = aws_vpn_connection.onprem[0].tunnel2_vgw_inside_address
    psk_params    = [for p in aws_ssm_parameter.vpn_psk : p.name]
  })
}
