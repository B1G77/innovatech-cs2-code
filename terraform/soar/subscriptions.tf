# CloudWatch Logs -> SOAR collector (security signals) and -> indexer (everything searchable).
locals {
  groups = local.platform.log_group_names

  to_collector = {
    suricata = { group = local.groups["onprem/suricata"], pattern = "{ $.event_type = \"alert\" && $.alert.severity <= 2 }" } # informational (3) alerts only go to OpenSearch
    auth     = { group = local.groups["onprem/auth"], pattern = "?\"Invalid user\" ?\"Failed password\" ?\"Connection closed by authenticating user\" ?\"Accepted publickey\" ?\"Accepted password\"" }
  }

  to_indexer = merge(
    { for k, g in local.groups : k => { group = g, pattern = "" } if k != "vpc-flow-logs" },
    {
      "soar-ingest"  = { group = aws_cloudwatch_log_group.fn["ingest"].name, pattern = "{ $.log_type = \"event\" }" }
      "soar-decide"  = { group = aws_cloudwatch_log_group.fn["decide"].name, pattern = "{ $.log_type = \"decision\" }" }
      "soar-act"     = { group = aws_cloudwatch_log_group.fn["act"].name, pattern = "{ $.log_type = * }" }
      "soar-release" = { group = aws_cloudwatch_log_group.fn["release"].name, pattern = "{ $.log_type = * }" }
    }
  )
}

resource "aws_lambda_permission" "logs" {
  for_each = { ingest = "ingest", indexer = "indexer" }

  statement_id  = "cloudwatch-logs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn[each.key].function_name
  principal     = "logs.amazonaws.com"
  source_arn    = "arn:aws:logs:${var.region}:${local.account}:log-group:*"
}

resource "aws_cloudwatch_log_subscription_filter" "collector" {
  for_each = local.to_collector

  name            = "${local.prefix}-collector"
  log_group_name  = each.value.group
  filter_pattern  = each.value.pattern
  destination_arn = aws_lambda_function.fn["ingest"].arn

  depends_on = [aws_lambda_permission.logs]
}

resource "aws_cloudwatch_log_subscription_filter" "indexer" {
  for_each = local.to_indexer

  name            = "${local.prefix}-indexer"
  log_group_name  = each.value.group
  filter_pattern  = each.value.pattern
  destination_arn = aws_lambda_function.fn["indexer"].arn

  depends_on = [aws_lambda_permission.logs]
}
