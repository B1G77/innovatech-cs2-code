# The event flow: collector -> SOAR event bus -> playbook (Step Functions) -> decide -> actions.

resource "aws_cloudwatch_event_bus" "soar" {
  name = "${var.project}-soar"
}

# ---------------- Playbook runner ----------------
resource "aws_iam_role" "playbook" {
  name = "${local.prefix}-playbook"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "states.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "playbook" {
  name = "${local.prefix}-playbook"
  role = aws_iam_role.playbook.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["lambda:InvokeFunction"], Resource = [aws_lambda_function.fn["decide"].arn, aws_lambda_function.fn["act"].arn] },
      { Effect = "Allow", Action = ["logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy", "logs:DescribeResourcePolicies", "logs:DescribeLogGroups"], Resource = ["*"] },
    ]
  })
}

resource "aws_cloudwatch_log_group" "playbook" {
  name              = "/aws/vendedlogs/states/${local.prefix}-playbook"
  retention_in_days = 30
}

locals {
  lambda_retry = [
    { ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"],
    IntervalSeconds = 2, MaxAttempts = 3, BackoffRate = 2 },
  ]

  playbook = {
    Comment = "Innovatech SOAR: decide the response tier, then run that tier's actions in order"
    StartAt = "Decide"
    States = {
      Decide = {
        Type       = "Task"
        Resource   = "arn:aws:states:::lambda:invoke"
        Parameters = { FunctionName = aws_lambda_function.fn["decide"].arn, Payload = { "event.$" = "$.detail", "execution.$" = "$$.Execution.Id" } }
        OutputPath = "$.Payload"
        Retry      = local.lambda_retry
        Next       = "AnythingToDo"
      }
      AnythingToDo = {
        Type    = "Choice"
        Choices = [{ Variable = "$.actions[0]", IsPresent = true, Next = "RunActions" }]
        Default = "Done"
      }
      RunActions = {
        Type           = "Map"
        ItemsPath      = "$.actions"
        MaxConcurrency = 1 # in order: contain first, then snapshot, then notify
        ItemSelector   = { "action.$" = "$$.Map.Item.Value", "case.$" = "$.case", "event.$" = "$.event" }
        ItemProcessor = {
          ProcessorConfig = { Mode = "INLINE" }
          StartAt         = "Act"
          States = {
            Act = {
              Type       = "Task"
              Resource   = "arn:aws:states:::lambda:invoke"
              Parameters = { FunctionName = aws_lambda_function.fn["act"].arn, "Payload.$" = "$" }
              OutputPath = "$.Payload"
              Retry = concat(local.lambda_retry, [
                { ErrorEquals = ["States.TaskFailed"], IntervalSeconds = 3, MaxAttempts = 2, BackoffRate = 2, JitterStrategy = "FULL" },
              ])
              End = true
            }
          }
        }
        ResultPath = "$.results"
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "ReportFailure" }]
        Next       = "Done"
      }
      ReportFailure = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.fn["act"].arn
          Payload      = { action = "report_failure", "case.$" = "$.case", "event.$" = "$.event", "error.$" = "$.error" }
        }
        Retry = local.lambda_retry
        Next  = "Failed"
      }
      Failed = { Type = "Fail", Error = "ActionFailed", Cause = "An automated action failed after retries; a person was notified" }
      Done   = { Type = "Succeed" }
    }
  }
}

resource "aws_sfn_state_machine" "playbook" {
  name       = "${local.prefix}-playbook"
  role_arn   = aws_iam_role.playbook.arn
  type       = "STANDARD" # keeps a full, auditable history of every response
  definition = jsonencode(local.playbook)

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.playbook.arn}:*"
    include_execution_data = true
    level                  = "ERROR"
  }
}

# ---------------- Routing ----------------
resource "aws_iam_role" "events" {
  name = "${local.prefix}-events"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = ["events.amazonaws.com", "scheduler.amazonaws.com"] }
    }]
  })
}

resource "aws_iam_role_policy" "events" {
  name = "${local.prefix}-events"
  role = aws_iam_role.events.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["states:StartExecution"], Resource = [aws_sfn_state_machine.playbook.arn] },
      { Effect = "Allow", Action = ["lambda:InvokeFunction"], Resource = [aws_lambda_function.fn["ingest"].arn] },
    ]
  })
}

resource "aws_cloudwatch_event_rule" "security_events" {
  name           = "${local.prefix}-security-events"
  description    = "Every normalised security event starts a playbook run"
  event_bus_name = aws_cloudwatch_event_bus.soar.name

  event_pattern = jsonencode({
    source        = ["innovatech.soar.ingest"]
    "detail-type" = ["SecurityEvent"]
  })
}

resource "aws_cloudwatch_event_target" "playbook" {
  rule           = aws_cloudwatch_event_rule.security_events.name
  event_bus_name = aws_cloudwatch_event_bus.soar.name
  arn            = aws_sfn_state_machine.playbook.arn
  role_arn       = aws_iam_role.events.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 10
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.dlq.arn
      Condition = { ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.security_events.arn } }
    }]
  })
}

# AWS-native sources on the default bus go through the collector, so they are normalised too.
resource "aws_cloudwatch_event_rule" "aws_sources" {
  for_each = {
    guardduty = { source = ["aws.guardduty"], "detail-type" = ["GuardDuty Finding"] }
    anomaly = {
      source        = ["aws.cloudwatch"]
      "detail-type" = ["CloudWatch Alarm State Change"]
      detail        = { alarmName = [{ prefix = "${var.project}-anomaly-" }], state = { value = ["ALARM"] } }
    }
  }

  name          = "${local.prefix}-${each.key}"
  event_pattern = jsonencode(each.value)
}

resource "aws_cloudwatch_event_target" "aws_sources" {
  for_each = aws_cloudwatch_event_rule.aws_sources

  rule = each.value.name
  arn  = aws_lambda_function.fn["ingest"].arn
}

resource "aws_lambda_permission" "events" {
  for_each = aws_cloudwatch_event_rule.aws_sources

  statement_id  = "events-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn["ingest"].function_name
  principal     = "events.amazonaws.com"
  source_arn    = each.value.arn
}

# Heartbeat: a synthetic event every 5 minutes proves the whole chain still works.
resource "aws_scheduler_schedule" "heartbeat" {
  name                = "${local.prefix}-heartbeat"
  schedule_expression = "rate(5 minutes)"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.fn["ingest"].arn
    role_arn = aws_iam_role.events.arn
    input    = jsonencode({ heartbeat = true })
  }
}
