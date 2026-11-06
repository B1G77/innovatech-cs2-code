# Private webhook for detectors: POST /v1/events. Reachable only through the execute-api
# endpoint in the hub (so only over the VPN or from inside AWS), and only with the API key.
resource "aws_api_gateway_rest_api" "webhook" {
  name        = "${local.prefix}-webhook"
  description = "SOAR intake for detector alerts"

  endpoint_configuration {
    types            = ["PRIVATE"]
    vpc_endpoint_ids = [local.platform.execute_api_endpoint_id]
  }
}

resource "aws_api_gateway_rest_api_policy" "webhook" {
  rest_api_id = aws_api_gateway_rest_api.webhook.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "${aws_api_gateway_rest_api.webhook.execution_arn}/*"
      },
      {
        Effect    = "Deny"
        Principal = "*"
        Action    = "execute-api:Invoke"
        Resource  = "${aws_api_gateway_rest_api.webhook.execution_arn}/*"
        Condition = { StringNotEquals = { "aws:SourceVpce" = local.platform.execute_api_endpoint_id } }
      },
    ]
  })
}

resource "aws_api_gateway_resource" "events" {
  rest_api_id = aws_api_gateway_rest_api.webhook.id
  parent_id   = aws_api_gateway_rest_api.webhook.root_resource_id
  path_part   = "events"
}

resource "aws_api_gateway_method" "post" {
  rest_api_id      = aws_api_gateway_rest_api.webhook.id
  resource_id      = aws_api_gateway_resource.events.id
  http_method      = "POST"
  authorization    = "NONE"
  api_key_required = true
}

resource "aws_api_gateway_integration" "ingest" {
  rest_api_id             = aws_api_gateway_rest_api.webhook.id
  resource_id             = aws_api_gateway_resource.events.id
  http_method             = aws_api_gateway_method.post.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.fn["ingest"].invoke_arn
}

resource "aws_lambda_permission" "api" {
  statement_id  = "api-gateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn["ingest"].function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.webhook.execution_arn}/*/POST/events"
}

resource "aws_api_gateway_deployment" "webhook" {
  rest_api_id = aws_api_gateway_rest_api.webhook.id

  triggers = {
    redeploy = sha1(jsonencode([aws_api_gateway_method.post, aws_api_gateway_integration.ingest, aws_api_gateway_rest_api_policy.webhook.policy]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [aws_api_gateway_integration.ingest, aws_api_gateway_rest_api_policy.webhook]
}

resource "aws_api_gateway_stage" "v1" {
  rest_api_id   = aws_api_gateway_rest_api.webhook.id
  deployment_id = aws_api_gateway_deployment.webhook.id
  stage_name    = "v1"
}

resource "aws_api_gateway_method_settings" "v1" {
  rest_api_id = aws_api_gateway_rest_api.webhook.id
  stage_name  = aws_api_gateway_stage.v1.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled        = true
    throttling_rate_limit  = 50 # a misbehaving detector cannot flood the SOAR
    throttling_burst_limit = 100
  }
}

resource "aws_api_gateway_api_key" "detectors" {
  name = "${local.prefix}-detectors"
}

resource "aws_api_gateway_usage_plan" "detectors" {
  name = "${local.prefix}-detectors"

  api_stages {
    api_id = aws_api_gateway_rest_api.webhook.id
    stage  = aws_api_gateway_stage.v1.stage_name
  }
}

resource "aws_api_gateway_usage_plan_key" "detectors" {
  key_id        = aws_api_gateway_api_key.detectors.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.detectors.id
}

# The contract with the detectors: they read these at start-up.
resource "aws_ssm_parameter" "webhook" {
  for_each = {
    "webhook-url" = { type = "String", value = "https://${local.platform.execute_api_endpoint_dns}/v1/events" }
    "api-id"      = { type = "String", value = aws_api_gateway_rest_api.webhook.id }
    "api-key"     = { type = "SecureString", value = aws_api_gateway_api_key.detectors.value }
  }

  name  = "/${var.project}/soar/${each.key}"
  type  = each.value.type
  value = each.value.value
}
