# Log groups the agents ship to. Office hosts use Fluent Bit (vendor-neutral, buffers to disk
# while the VPN is down); cloud servers use the CloudWatch agent.
locals {
  log_groups = {
    "onprem/syslog"    = 30 # system logs of every office host
    "onprem/auth"      = 90 # logins and SSH: security-relevant, kept longer
    "onprem/suricata"  = 30 # IDS alerts (eve.json) from the firewall
    "onprem/firewall"  = 30 # nftables drops and SOAR blocks
    "onprem/detectors" = 30 # traffic analyzer and process watcher output
    "cloud/app"        = 14
    "vpc-flow-logs"    = 14
  }
}

resource "aws_cloudwatch_log_group" "this" {
  for_each = local.log_groups

  name              = "/${var.project}/${each.key}"
  retention_in_days = each.value
}

# ---------------- VPC Flow Logs for every network ----------------
resource "aws_iam_role" "flow_logs" {
  name = "${var.project}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.project}-flow-logs-write"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.this["vpc-flow-logs"].arn}:*"
    }]
  })
}

resource "aws_flow_log" "this" {
  for_each = aws_vpc.this

  vpc_id                   = each.value.id
  traffic_type             = "REJECT" # rejected traffic is the security signal; ACCEPT would only add volume
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.this["vpc-flow-logs"].arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60

  tags = { Name = "${var.project}-${each.key}-flow-logs" }
}
