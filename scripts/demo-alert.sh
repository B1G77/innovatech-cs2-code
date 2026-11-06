#!/usr/bin/env bash
# Demo: sends one test alert to the private SOAR webhook (from the ops host, because the webhook
# is private) and prints what the SOAR did with it. One scenario per response tier:
#   demo-alert.sh observe     config change on an app server       -> tier 0: record only
#   demo-alert.sh notify      suspicious CPU on an app server     -> tier 1: record + e-mail
#   demo-alert.sh scan        port scan from the internet          -> tier 2: block at the office firewall
#   demo-alert.sh miner       cryptominer on an app server         -> tier 3: isolate, detach, snapshot, e-mail
#   demo-alert.sh protected   cryptominer on the ops host          -> guard rail: protected, downgraded to tier 1
#   demo-alert.sh failure     CPU anomaly while 'notify' is set to fail -> retries, then a "SOAR FAILED" e-mail
set -euo pipefail
cd "$(dirname "$0")/.."
export AWS_PAGER="" AWS_PROFILE=${AWS_PROFILE:-Goncalo} AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1}

app_ip() {
  aws ec2 describe-instances --filters Name=tag:Role,Values=app Name=instance-state-name,Values=running \
    --query 'Reservations[].Instances[?!(Tags[?Key==`SoarCase`])][].PrivateIpAddress' --output text | awk '{print $1}'
}
ops_ip() {
  aws ec2 describe-instances --filters Name=tag:Name,Values=innovatech-ops Name=instance-state-name,Values=running \
    --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text
}

wait=20
case ${1:-} in
  observe)   event='{"type":"app.config_change","severity":2,"host":"app-server","summary":"demo: configuration reloaded on an app server"}' ;;
  notify)    ip=$(app_ip); event="{\"type\":\"process.suspicious_cpu\",\"severity\":5,\"host\":\"app-server\",\"host_ip\":\"$ip\",\"summary\":\"demo: unknown process at 97% CPU on app server $ip\"}" ;;
  scan)      event='{"type":"network.portscan","severity":6,"host":"office-firewall","src_ip":"93.184.215.77","summary":"demo: internet port scan of the office","details":{"ports":[22,23,80,443,3389]}}' ;;
  miner)     ip=$(app_ip); event="{\"type\":\"process.cryptominer\",\"severity\":9,\"host\":\"app-server\",\"host_ip\":\"$ip\",\"dst_ip\":\"93.184.215.77\",\"summary\":\"demo: xmrig on app server $ip talking to a mining pool\",\"details\":{\"process\":\"xmrig\",\"ports\":[3333]}}" ;;
  protected) ip=$(ops_ip); event="{\"type\":\"process.cryptominer\",\"severity\":9,\"host\":\"ops\",\"host_ip\":\"$ip\",\"summary\":\"demo: miner reported on the protected ops host $ip\"}" ;;
  failure)   chaos=notify; wait=60; event='{"type":"metric.cpu_anomaly","severity":4,"host":"app-server","summary":"demo: CPU far above its learned band (notify is set to fail)"}' ;;
  *) sed -n '2,9p' "$0"; exit 1 ;;
esac

# Failure injection (design for failure): the act function fails the named action until the switch is reset.
if [ -n "${chaos:-}" ]; then
  param=/innovatech/soar/chaos/fail-actions
  trap 'aws ssm put-parameter --name $param --value none --overwrite >/dev/null && echo "Failure switch reset to none (wait 30 s before the next alert)."' EXIT
  aws ssm put-parameter --name $param --value "$chaos" --overwrite >/dev/null
  echo "Failure switch: action '$chaos' is set to fail. Waiting 35 s until the SOAR picks it up..."; sleep 35
fi
event="{\"source\":\"mockgen\",${event#\{}"

since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "Sending: $event"
scripts/onhost.sh ops "export AWS_DEFAULT_REGION=$AWS_DEFAULT_REGION
p() { aws ssm get-parameter --name /innovatech/soar/\$1 --with-decryption --query Parameter.Value --output text; }
curl -s -X POST \"\$(p webhook-url)\" -H \"x-api-key: \$(p api-key)\" -H \"x-apigw-api-id: \$(p api-id)\" -H 'Content-Type: application/json' -d '$event'"
echo; echo "Waiting $wait s for the playbook..."; sleep $wait
.venv/bin/python scripts/soar_check.py --since "$since"
