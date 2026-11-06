# SOAR data and functions.
resource "aws_dynamodb_table" "state" {
  name         = "${local.prefix}-state" # counters, de-duplication, circuit breaker (all expire)
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  ttl {
    attribute_name = "expires"
    enabled        = true
  }
}

resource "aws_dynamodb_table" "cases" {
  name         = "${local.prefix}-cases" # one item per incident the SOAR acted on
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "case_id"

  attribute {
    name = "case_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}

# Failure injection switch for the design-for-failure tests (value "none" = no failures).
resource "aws_ssm_parameter" "chaos" {
  name  = "/${var.project}/soar/chaos/fail-actions"
  type  = "String"
  value = "none"

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${local.prefix}-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

data "archive_file" "soar" {
  type        = "zip"
  source_dir  = "${path.module}/../../functions/soar"
  output_path = "${path.module}/.build/soar.zip"
  excludes    = ["__pycache__"]
}

data "archive_file" "indexer" {
  type        = "zip"
  source_dir  = "${path.module}/../../functions/indexer"
  output_path = "${path.module}/.build/indexer.zip"
  excludes    = ["__pycache__"]
}

locals {
  functions = {
    ingest  = { handler = "ingest.handler", timeout = 30, zip = "soar" }
    decide  = { handler = "decide.handler", timeout = 30, zip = "soar" }
    act     = { handler = "actions.handler", timeout = 90, zip = "soar" }
    release = { handler = "release.handler", timeout = 90, zip = "soar" }
    indexer = { handler = "indexer.handler", timeout = 90, zip = "indexer" }
  }
  zips = {
    soar    = data.archive_file.soar
    indexer = data.archive_file.indexer
  }
}

resource "aws_cloudwatch_log_group" "fn" {
  for_each = local.functions

  name              = "/aws/lambda/${local.prefix}-${each.key}"
  retention_in_days = 30
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "fn" {
  for_each = local.functions

  name               = "${local.prefix}-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "fn_logs" {
  for_each = local.functions

  role       = aws_iam_role.fn[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "indexer_vpc" {
  role       = aws_iam_role.fn["indexer"].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Least privilege: each function may only do its own job.
locals {
  fn_policies = {
    ingest = [
      { Action = ["events:PutEvents"], Resource = [aws_cloudwatch_event_bus.soar.arn] },
    ]
    decide = [
      { Action = ["dynamodb:UpdateItem", "dynamodb:GetItem", "dynamodb:PutItem"], Resource = [aws_dynamodb_table.state.arn] },
      { Action = ["ec2:DescribeInstances"], Resource = ["*"] },
      { Action = ["ssm:DescribeInstanceInformation", "ssm:ListTagsForResource"], Resource = ["*"] },
    ]
    act = [
      { Action = ["dynamodb:PutItem"], Resource = [aws_dynamodb_table.cases.arn] },
      { Action = ["sns:Publish"], Resource = [local.platform.alerts_topic_arn] },
      { Action = ["ssm:GetParameter"], Resource = [aws_ssm_parameter.chaos.arn] },
      # Any instance tagged Role=firewall (the firewall can be rebuilt with a new id).
      { Action = ["ssm:SendCommand"], Resource = ["arn:aws:ec2:${var.region}:${local.account}:instance/*"], Condition = { StringEquals = { "ssm:resourceTag/Role" = "firewall" } } },
      { Action = ["ssm:SendCommand"], Resource = ["arn:aws:ssm:${var.region}::document/AWS-RunShellScript"] },
      { Action = ["ssm:GetCommandInvocation"], Resource = ["*"] },
      { Action = ["ec2:DescribeInstances", "ec2:DescribeVolumes", "ec2:DescribeSnapshots"], Resource = ["*"] },
      { Action = ["ec2:ModifyNetworkInterfaceAttribute", "ec2:CreateTags", "ec2:CreateSnapshot"], Resource = ["*"] },
      # Keep an isolated app server for forensics instead of letting its group replace it.
      { Action = ["autoscaling:DescribeAutoScalingInstances", "autoscaling:DetachInstances"], Resource = ["*"] },
      # Office VMs on vSphere (SSM managed nodes): the firewall, and the hosts it may isolate.
      { Action = ["ssm:SendCommand"], Resource = ["arn:aws:ssm:${var.region}:${local.account}:managed-instance/*"], Condition = { StringEquals = { "ssm:resourceTag/Role" = ["firewall", "workstation", "server"] } } },
      { Action = ["ssm:DescribeInstanceInformation", "ssm:ListTagsForResource", "ssm:AddTagsToResource"], Resource = ["*"] },
    ]
    release = [
      { Action = ["dynamodb:PutItem"], Resource = [aws_dynamodb_table.state.arn] },
      { Action = ["ssm:SendCommand"], Resource = ["arn:aws:ec2:${var.region}:${local.account}:instance/*"], Condition = { StringEquals = { "ssm:resourceTag/Role" = "firewall" } } },
      { Action = ["ssm:SendCommand"], Resource = ["arn:aws:ssm:${var.region}::document/AWS-RunShellScript"] },
      { Action = ["ssm:GetCommandInvocation"], Resource = ["*"] },
      { Action = ["ec2:DescribeInstances", "ec2:ModifyNetworkInterfaceAttribute", "ec2:DeleteTags"], Resource = ["*"] },
      { Action = ["ssm:SendCommand"], Resource = ["arn:aws:ssm:${var.region}:${local.account}:managed-instance/*"], Condition = { StringEquals = { "ssm:resourceTag/Role" = ["firewall", "workstation", "server"] } } },
      { Action = ["ssm:DescribeInstanceInformation", "ssm:ListTagsForResource", "ssm:RemoveTagsFromResource"], Resource = ["*"] },
    ]
    indexer = [
      { Action = ["ssm:GetParameter"], Resource = ["arn:aws:ssm:${var.region}:${local.account}:parameter${local.platform.opensearch_ingest_password_param}"] },
    ]
  }
}

resource "aws_iam_role_policy" "fn" {
  for_each = local.fn_policies

  name = "${local.prefix}-${each.key}"
  role = aws_iam_role.fn[each.key].id

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [for s in each.value : merge({ Effect = "Allow" }, s)]
  })
}

resource "aws_iam_role_policy" "fn_dlq" {
  for_each = toset(["ingest", "indexer"])

  name = "${local.prefix}-${each.key}-dlq"
  role = aws_iam_role.fn[each.key].id

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["sqs:SendMessage"], Resource = [aws_sqs_queue.dlq.arn] }]
  })
}

resource "aws_security_group" "indexer" {
  name        = "${local.prefix}-indexer"
  description = "Indexer Lambda: HTTPS out to OpenSearch and AWS APIs"
  vpc_id      = local.platform.shared_vpc_id

  egress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_lambda_function" "fn" {
  for_each = local.functions

  function_name    = "${local.prefix}-${each.key}"
  role             = aws_iam_role.fn[each.key].arn
  runtime          = "python3.13"
  handler          = each.value.handler
  filename         = local.zips[each.value.zip].output_path
  source_code_hash = local.zips[each.value.zip].output_base64sha256
  timeout          = each.value.timeout
  memory_size      = 256

  # Smooth log bursts: at most 4 indexer runs hit OpenSearch at once (found in testing: many
  # parallel bulk requests during attack bursts timed out on the small 2 GB data nodes).
  reserved_concurrent_executions = each.key == "indexer" ? 4 : null

  environment {
    variables = {
      EVENT_BUS                 = aws_cloudwatch_event_bus.soar.name
      STATE_TABLE               = aws_dynamodb_table.state.name
      CASES_TABLE               = aws_dynamodb_table.cases.name
      TOPIC_ARN                 = local.platform.alerts_topic_arn
      QUARANTINE_SGS            = jsonencode(local.platform.quarantine_security_groups)
      NEVER_BLOCK               = jsonencode(compact(concat(local.platform.vpn_tunnel_addresses, [local.platform.onprem_public_ip], var.never_block)))
      OUTSIDE_CIDRS             = jsonencode(local.platform.onprem_outside_cidrs)
      OFFICE_DNS                = local.platform.onprem_dns_ip
      FORENSICS_BUCKET          = local.platform.artifacts_bucket
      BLOCK_TTL                 = var.block_ttl
      MAX_ISOLATIONS_PER_HOUR   = tostring(var.max_isolations_per_hour)
      CHAOS_PARAM               = aws_ssm_parameter.chaos.name
      OPENSEARCH_ENDPOINT       = local.platform.opensearch_endpoint
      OPENSEARCH_PASSWORD_PARAM = local.platform.opensearch_ingest_password_param
    }
  }

  dynamic "vpc_config" {
    for_each = each.key == "indexer" ? [1] : []
    content {
      subnet_ids         = local.platform.shared_private_subnet_ids
      security_group_ids = [aws_security_group.indexer.id]
    }
  }

  depends_on = [aws_cloudwatch_log_group.fn, aws_iam_role_policy_attachment.fn_logs]
}

# Asynchronous callers (EventBridge, CloudWatch Logs): retry twice, then park the event in the DLQ.
resource "aws_lambda_function_event_invoke_config" "async" {
  for_each = toset(["ingest", "indexer"])

  function_name                = aws_lambda_function.fn[each.key].function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 3600

  destination_config {
    on_failure {
      destination = aws_sqs_queue.dlq.arn
    }
  }
}
