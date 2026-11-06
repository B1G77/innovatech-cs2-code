#!/usr/bin/env bash
# Registers the ops host as the GitHub Actions runner; run after each apply that creates it.
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-Goncalo} AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1} AWS_PAGER=""
unset GITHUB_TOKEN   # gh uses its keyring login; the old token in claude.env is dead

repo=B1G77/innovatech-cs2
name=innovatech-cs2-ops

ops=$(aws ec2 describe-instances --filters Name=tag:Name,Values=innovatech-ops Name=instance-state-name,Values=running \
  --query 'Reservations[0].Instances[0].InstanceId' --output text)
[ "$ops" != None ] || { echo "No running ops host; run terraform apply first"; exit 1; }

# Remove the offline runner a destroyed ops host leaves behind.
for id in $(gh api "repos/$repo/actions/runners" --jq ".runners[] | select(.name==\"$name\") | .id"); do
  gh api -X DELETE "repos/$repo/actions/runners/$id"
done

token=$(gh api -X POST "repos/$repo/actions/runners/registration-token" --jq .token)
params=$(python3 -c 'import json,sys; print(json.dumps({"commands": sys.argv[1:]}))' \
  "cloud-init status --wait >/dev/null || true" \
  "cd /opt/actions-runner" \
  "sudo -u runner ./config.sh --unattended --replace --url https://github.com/$repo --token $token --name $name --labels innovatech-cs2" \
  "./svc.sh install runner" \
  "./svc.sh start")

cmd=$(aws ssm send-command --instance-ids "$ops" --document-name AWS-RunShellScript \
  --parameters "$params" --comment "register GitHub runner" --query Command.CommandId --output text)
for _ in $(seq 1 60); do
  status=$(aws ssm get-command-invocation --command-id "$cmd" --instance-id "$ops" --query Status --output text 2>/dev/null || true)
  case $status in Success|Failed|Cancelled|TimedOut) break ;; esac
  sleep 10
done
echo "Registration on $ops: $status"
[ "$status" = Success ] && gh api "repos/$repo/actions/runners" --jq '.runners[] | "\(.name): \(.status)"'
