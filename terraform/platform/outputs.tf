# Read by terraform/soar (remote state) and by the scripts in scripts/.
output "region" {
  value = var.region
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "alert_test_queue_url" {
  value = aws_sqs_queue.alert_test.url
}

output "shared_vpc_id" {
  value = aws_vpc.this["shared"].id
}

output "shared_private_subnet_ids" {
  value = [aws_subnet.this["shared-private-a"].id, aws_subnet.this["shared-private-b"].id]
}

output "execute_api_endpoint_id" {
  value = aws_vpc_endpoint.interface["execute-api"].id
}

output "execute_api_endpoint_dns" {
  description = "Endpoint-specific name of the private API endpoint (resolves to private IPs)"
  value       = aws_vpc_endpoint.interface["execute-api"].dns_entry[0].dns_name
}

output "quarantine_security_groups" {
  description = "VPC id => security group the SOAR swaps in to isolate a host"
  value = {
    (aws_vpc.this["workload"].id) = aws_security_group.quarantine["workload"].id
  }
}

output "onprem_public_ip" {
  value = var.onprem_public_ip
}

output "vpn_tunnel_addresses" {
  value = local.vpn_enabled ? [aws_vpn_connection.onprem[0].tunnel1_address, aws_vpn_connection.onprem[0].tunnel2_address] : []
}

output "log_group_names" {
  value = { for k, g in aws_cloudwatch_log_group.this : k => g.name }
}

output "opensearch_endpoint" {
  value = aws_opensearch_domain.logs.endpoint
}

output "opensearch_ingest_password_param" {
  value = aws_ssm_parameter.opensearch["ingest"].name
}

output "opensearch_security_group_id" {
  value = aws_security_group.opensearch.id
}

output "app_url" {
  value = "http://app.cloud.innovatech.internal/items"
}

output "grafana_tunnel" {
  description = "Open Grafana on http://localhost:3000 after running this"
  value       = "aws ssm start-session --target ${aws_instance.ops.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=3000,localPortNumber=3000"
}

output "onprem_outside_cidrs" {
  description = "The netlab segment in front of fw01; it stands in for the internet"
  value       = var.onprem_outside_cidrs
}

output "onprem_dns_ip" {
  value = local.onprem_dns_ip
}

output "artifacts_bucket" {
  value = aws_s3_bucket.artifacts.id
}
