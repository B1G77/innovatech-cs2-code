#!/usr/bin/env bash
# Runs a shell command on a host through SSM and prints its output. The exit code follows the
# remote command.
#   onhost.sh <host> '<command>'
# host: an office VM by name (fw01, ws01, srv01, ...), "ops" (the ops host in the hub) or "app"
# (the first running app server). The attacker VM has no SSM agent: ssh student@<attacker_ip>.
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-Goncalo} AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1} AWS_PAGER=""

host=$1; shift
case $host in
  app) filter=Key=tag:Role,Values=app ;;
  ops) filter=Key=tag:Name,Values=innovatech-ops ;;
  *)   filter=Key=tag:Name,Values=$host ;;
esac
# SSM cannot combine a tag filter with a status filter, so "Online" is picked in the query.
id=$(aws ssm describe-instance-information --filters "$filter" \
  --query 'InstanceInformationList[?PingStatus==`Online`] | [0].InstanceId' --output text)
[ -n "$id" ] && [ "$id" != None ] || { echo "no online SSM node called $host" >&2; exit 1; }

params=$(python3 -c 'import json,sys; print(json.dumps({"commands": [sys.argv[1]], "executionTimeout": ["600"]}))' "$*")
cmd=$(aws ssm send-command --instance-ids "$id" --document-name AWS-RunShellScript --comment "onhost $host" \
  --parameters "$params" --query Command.CommandId --output text)
for _ in $(seq 1 150); do
  status=$(aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query Status --output text 2>/dev/null || true)
  case $status in Success|Failed|Cancelled|TimedOut) break ;; esac
  sleep 2
done
aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" \
  --query '[StandardOutputContent,StandardErrorContent]' --output text
[ "$status" = Success ]
