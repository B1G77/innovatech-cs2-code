#!/usr/bin/env bash
# Runs the Ansible update/config associations now and prints fleet patch compliance.
#   run-updates.sh [all|firewall|workstation|server|app|ops]
set -euo pipefail
export AWS_PAGER="" AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1}
role=${1:-all}
ids=$(aws ssm list-associations --query "Associations[?starts_with(AssociationName,'innovatech-ansible-')].[AssociationId,AssociationName]" --output text |
  awk -v r="$role" '$2 ~ (r=="all" ? "" : "-" r "$") {print $1}')
[ -n "$ids" ] || { echo "no associations for $role"; exit 1; }
aws ssm start-associations-once --association-ids $ids
echo "started: $ids"
sleep 30
for _ in $(seq 1 60); do
  pending=$(for id in $ids; do aws ssm describe-association-executions --association-id "$id" --max-results 1 \
    --query 'AssociationExecutions[0].Status' --output text; done | grep -c -E 'Pending|InProgress' || true)
  [ "$pending" = 0 ] && break
  sleep 20
done
for id in $ids; do
  aws ssm describe-association-executions --association-id "$id" --max-results 1 \
    --query 'AssociationExecutions[0].[AssociationId,Status,DetailedStatus,ResourceCountByStatus]' --output text
done
echo; echo "Patch compliance per node:"
aws ssm list-resource-compliance-summaries --filters Key=ComplianceType,Values=Patch,Type=EQUAL \
  --query 'ResourceComplianceSummaryItems[].[ResourceId,Status,OverallSeverity]' --output table
