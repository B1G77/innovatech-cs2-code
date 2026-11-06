#!/usr/bin/env bash
# Removes the whole deployment: SOAR first (it depends on the platform), then the forensic
# snapshots the SOAR created (Terraform does not own them), then the platform.
set -euo pipefail
cd "$(dirname "$0")/.."
export AWS_PROFILE=${AWS_PROFILE:-Goncalo} AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1} AWS_PAGER=""

terraform -chdir=terraform/soar destroy -input=false -auto-approve

for snap in $(aws ec2 describe-snapshots --owner-ids self --filters Name=tag-key,Values=SoarCase \
    --query 'Snapshots[].SnapshotId' --output text); do
  echo "deleting forensic snapshot $snap"
  aws ec2 delete-snapshot --snapshot-id "$snap"
done

# App servers the SOAR isolated are detached from their Auto Scaling group to keep the evidence,
# so Terraform no longer owns them; their security group would block the platform teardown.
ids=$(aws ec2 describe-instances --filters Name=tag-key,Values=SoarCase Name=instance-state-name,Values=pending,running,stopping,stopped \
  --query 'Reservations[].Instances[].InstanceId' --output text)
if [ -n "$ids" ]; then
  echo "terminating isolated instances $ids"
  aws ec2 terminate-instances --instance-ids $ids >/dev/null
  aws ec2 wait instance-terminated --instance-ids $ids
fi

terraform -chdir=terraform/platform destroy -input=false -auto-approve

echo "Left behind on purpose: the Terraform state bucket (shared with Case Study 1)."
echo "Check: docs/evidence/raw/Z-after-destroy.txt lists the counts to verify (the sandbox blocks the tagging API)."
