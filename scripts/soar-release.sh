#!/usr/bin/env bash
# Analyst action: release a host the SOAR isolated, after checking the forensic snapshot.
#   soar-release.sh <instance-id> [analyst-name]
set -euo pipefail
export AWS_PAGER="" AWS_PROFILE=${AWS_PROFILE:-Goncalo} AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1}
[ $# -ge 1 ] || { echo "usage: $0 <instance-id> [analyst]"; exit 1; }
payload=$(printf '{"instance_id":"%s","analyst":"%s"}' "$1" "${2:-$USER}")
aws lambda invoke --function-name innovatech-soar-release --cli-binary-format raw-in-base64-out \
  --payload "$payload" /tmp/release.json >/dev/null
cat /tmp/release.json; echo
