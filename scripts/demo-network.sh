#!/usr/bin/env bash
# Demo: proves two network paths live, from inside the servers (through SSM):
#   1. an app server (no public IP, no internet gateway) reaches the internet as the hub NAT's address;
#   2. the ops host in the hub finds the app by its private name and reaches it through the Transit Gateway.
set -euo pipefail
cd "$(dirname "$0")/.."
export AWS_PROFILE=${AWS_PROFILE:-Goncalo} AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1} AWS_PAGER=""

nat=$(aws ec2 describe-addresses --filters Name=tag:Name,Values=innovatech-nat-eip --query 'Addresses[0].PublicIp' --output text)
seen=$(scripts/onhost.sh app 'curl -s -m 5 https://checkip.amazonaws.com' | tr -d '[:space:]')
echo "1. One exit to the internet"
echo "   NAT gateway Elastic IP:               $nat"
echo "   app server, as the internet sees it:  $seen"
if [ "$seen" = "$nat" ]; then echo "   -> same address: the app server leaves through the hub's NAT"; else echo "   -> DIFFERENT: check the routes"; fi
echo
echo "2. Private DNS and the Transit Gateway (from the ops host in the hub)"
scripts/onhost.sh ops 'getent hosts app.cloud.innovatech.internal | sed "s/^/   /"; curl -s -o /dev/null -m 5 -w "   GET http://app.cloud.innovatech.internal/items -> HTTP %{http_code}\n" http://app.cloud.innovatech.internal/items' | grep -v '^[[:space:]]*$'
