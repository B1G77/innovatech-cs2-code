# REQ-NCA-P2-09: the SOAR watches itself. Alarms go to the same alert topic as everything else;
# the panels are on the central Grafana dashboard (and this CloudWatch dashboard as a fallback).
locals {
  soar_alarms = {
    actions-failed = {
      text = "An automated SOAR action failed", namespace = "Innovatech/SOAR", metric = "ActionsFailed",
      dims = {}, stat = "Sum", op = "GreaterThanOrEqualToThreshold", threshold = 1, missing = "notBreaching"
    }
    playbook-failed = {
      text      = "A SOAR playbook run ended in failure", namespace = "AWS/States", metric = "ExecutionsFailed",
      dims      = { StateMachineArn = aws_sfn_state_machine.playbook.arn }, stat = "Sum", op = "GreaterThanOrEqualToThreshold",
      threshold = 1, missing = "notBreaching"
    }
    heartbeat-missing = {
      text   = "No SOAR heartbeat for 15 minutes: the response chain is broken", namespace = "Innovatech/SOAR",
      metric = "Heartbeat", dims = {}, stat = "Sum", op = "LessThanThreshold", threshold = 1, missing = "breaching", period = 900
    }
    dlq-not-empty = {
      text   = "Events are waiting in the SOAR dead-letter queue", namespace = "AWS/SQS",
      metric = "ApproximateNumberOfMessagesVisible", dims = { QueueName = aws_sqs_queue.dlq.name }, stat = "Maximum",
      op     = "GreaterThanOrEqualToThreshold", threshold = 1, missing = "notBreaching"
    }
    collector-errors = {
      text = "The SOAR collector is throwing errors", namespace = "AWS/Lambda", metric = "Errors",
      dims = { FunctionName = aws_lambda_function.fn["ingest"].function_name }, stat = "Sum",
      op   = "GreaterThanOrEqualToThreshold", threshold = 3, missing = "notBreaching"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "soar" {
  for_each = local.soar_alarms

  alarm_name          = "${local.prefix}-${each.key}"
  alarm_description   = each.value.text
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  dimensions          = each.value.dims
  statistic           = each.value.stat
  period              = lookup(each.value, "period", 300)
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = each.value.op
  treat_missing_data  = each.value.missing
  alarm_actions       = [local.platform.alerts_topic_arn]
  ok_actions          = [local.platform.alerts_topic_arn]
}

resource "aws_cloudwatch_dashboard" "soar" {
  dashboard_name = local.prefix

  dashboard_body = jsonencode({
    widgets = [
      { type = "metric", x = 0, y = 0, width = 8, height = 6, properties = {
        title = "Events by tier", region = var.region, stat = "Sum", period = 300, view = "timeSeries", stacked = true,
      metrics = [for t in ["0", "1", "2", "3"] : ["Innovatech/SOAR", "EventsProcessed", "Tier", t]] } },
      { type = "metric", x = 8, y = 0, width = 8, height = 6, properties = {
        title = "Actions", region = var.region, stat = "Sum", period = 300, view = "timeSeries",
      metrics = [["Innovatech/SOAR", "ActionsSucceeded"], ["Innovatech/SOAR", "ActionsFailed"], ["Innovatech/SOAR", "PlaybookFailures"]] } },
      { type = "metric", x = 16, y = 0, width = 8, height = 6, properties = {
        title = "Latency (ms) and heartbeat", region = var.region, period = 300, view = "timeSeries",
      metrics = [["Innovatech/SOAR", "ProcessingLatency", { stat = "p95" }], ["Innovatech/SOAR", "Heartbeat", { stat = "Sum", yAxis = "right" }]] } },
      { type = "alarm", x = 0, y = 6, width = 24, height = 3, properties = {
      title = "SOAR health", alarms = [for a in aws_cloudwatch_metric_alarm.soar : a.arn] } },
    ]
  })
}

output "playbook_arn" {
  value = aws_sfn_state_machine.playbook.arn
}

output "webhook_url" {
  value = "https://${local.platform.execute_api_endpoint_dns}/v1/events"
}

output "cases_table" {
  value = aws_dynamodb_table.cases.name
}
