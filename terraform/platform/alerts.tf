# One alert topic for alarms and SOAR notifications.
# Subscribers: the e-mail address (needs a one-time confirmation click) and a test queue
# that the automated tests read to prove a notification went out.
resource "aws_sns_topic" "alerts" {
  name = "${var.project}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sqs_queue" "alert_test" {
  name                      = "${var.project}-alerts-test"
  message_retention_seconds = 86400
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue_policy" "alert_test" {
  queue_url = aws_sqs_queue.alert_test.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "sns.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.alert_test.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_sns_topic.alerts.arn } }
    }]
  })
}

resource "aws_sns_topic_subscription" "test_queue" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.alert_test.arn
}

# Managed threat detection for the cloud side; findings reach the SOAR through EventBridge.
resource "aws_guardduty_detector" "this" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# ---------------- Security alerts from logs ----------------
# A metric filter turns matching log lines into a count; an entry with "alarm" also e-mails when
# the count reaches the threshold within the period (seconds). To add an alert, add one entry.
locals {
  metric_filters = {
    SshFailures = { group = "onprem/auth", pattern = "?\"Failed password\" ?\"Invalid user\"",
    alarm = { name = "ssh-bruteforce", threshold = 10, period = 300, text = "10+ failed SSH logins in 5 minutes on office hosts" } }
    IdsHighAlerts = { group = "onprem/suricata", pattern = "{ $.event_type = \"alert\" && $.alert.severity = 1 }",
    alarm = { name = "ids-high", threshold = 1, period = 60, text = "Suricata raised a high-severity alert" } }
    FirewallDrops = { group = "onprem/firewall", pattern = "\"FW-DROP\"",
    alarm = { name = "firewall-drops", threshold = 100, period = 300, text = "Office firewall dropped 100+ packets in 5 minutes" } }
    IdsAlerts        = { group = "onprem/suricata", pattern = "{ $.event_type = \"alert\" }" }
    SoarBlockedPkts  = { group = "onprem/firewall", pattern = "?\"SOAR-BLOCK\" ?\"SOAR-QUARANTINE\"" }
    FlowLogRejects   = { group = "vpc-flow-logs", pattern = "REJECT" }
    DetectorFindings = { group = "onprem/detectors", pattern = "{ $.kind = \"finding\" }" }
  }
  security_alarms = { for m, f in local.metric_filters : f.alarm.name => merge(f.alarm, { metric = m }) if can(f.alarm) }
}

resource "aws_cloudwatch_log_metric_filter" "this" {
  for_each = local.metric_filters

  name           = "${var.project}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.this[each.value.group].name
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.key
    namespace     = "Innovatech/Security"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "security" {
  for_each = local.security_alarms

  alarm_name          = "${var.project}-sec-${each.key}"
  alarm_description   = each.value.text
  namespace           = "Innovatech/Security"
  metric_name         = each.value.metric
  statistic           = "Sum"
  period              = each.value.period
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "vpn_tunnel" {
  for_each = local.vpn_enabled ? {
    tunnel1 = aws_vpn_connection.onprem[0].tunnel1_address
    tunnel2 = aws_vpn_connection.onprem[0].tunnel2_address
  } : {}

  alarm_name          = "${var.project}-vpn-${each.key}-down"
  alarm_description   = "Office VPN ${each.key} is down (the other tunnel takes over through BGP)"
  namespace           = "AWS/VPN"
  metric_name         = "TunnelState"
  dimensions          = { TunnelIpAddress = each.value }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "app_unhealthy" {
  alarm_name          = "${var.project}-app-unhealthy"
  alarm_description   = "Fewer than 2 healthy app servers behind the load balancer"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HealthyHostCount"
  dimensions          = { LoadBalancer = aws_lb.app.arn_suffix, TargetGroup = aws_lb_target_group.app.arn_suffix }
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 2
  comparison_operator = "LessThanThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "opensearch_red" {
  alarm_name          = "${var.project}-opensearch-red"
  alarm_description   = "Log database has unassigned primary shards"
  namespace           = "AWS/ES"
  metric_name         = "ClusterStatus.red"
  dimensions          = { DomainName = aws_opensearch_domain.logs.domain_name, ClientId = data.aws_caller_identity.current.account_id }
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# Soft signal for the SOAR: unusual outbound volume through the cloud's central exit (the NAT
# gateway). The model learns the normal pattern; alarms named "*-anomaly-*" are picked up by
# the SOAR and only notify.
resource "aws_cloudwatch_metric_alarm" "egress_anomaly" {
  alarm_name          = "${var.project}-anomaly-cloud-egress"
  alarm_description   = "Cloud outbound traffic through the NAT gateway is far above its learned normal band"
  comparison_operator = "GreaterThanUpperThreshold"
  evaluation_periods  = 2
  threshold_metric_id = "band"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  metric_query {
    id          = "out"
    return_data = true
    metric {
      namespace   = "AWS/NATGateway"
      metric_name = "BytesOutToDestination"
      dimensions  = { NatGatewayId = aws_nat_gateway.shared.id }
      period      = 300
      stat        = "Sum"
    }
  }

  metric_query {
    id          = "band"
    expression  = "ANOMALY_DETECTION_BAND(out, 3)"
    label       = "Normal band"
    return_data = true
  }
}
