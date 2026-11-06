#!/usr/bin/env bash
# Registers an office VM with AWS Systems Manager and tags the new managed node (mi-...).
# From then on State Manager runs the Ansible playbook on it (REQ-NCA-P1-05), and the SOAR
# reaches it through Run Command. Terraform runs it once per new VM (terraform/office/main.tf).
#
#   ACTIVATION_ID=... ACTIVATION_CODE=... register.sh <vm> <role> <address> <fw01 WAN address>
#   register.sh --remove <vm>        deregisters the VM's managed node (Terraform runs it on destroy)
#
# The activation comes from the environment and travels to the VM over SSH stdin, so it never
# shows up on a command line. Idempotent: a VM that is already registered only gets re-tagged.
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-Goncalo} AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1}

if [ "$1" = --remove ]; then
  for id in $(aws ssm describe-instance-information --filters Key=tag:Name,Values="$2" \
      --query 'InstanceInformationList[].InstanceId' --output text); do
    aws ssm deregister-managed-instance --instance-id "$id" && echo "[$2] $id deregistered"
  done
  exit 0
fi

name=$1 role=$2 addr=$3 fw=$4
jump=(); [ "$addr" = "$fw" ] || jump=(-J "student@$fw")   # LAN hosts: through fw01
ssh=(ssh -o StrictHostKeyChecking=accept-new "${jump[@]}" "student@$addr")

registration() {
  "${ssh[@]}" "sudo cat /var/lib/amazon/ssm/registration 2>/dev/null" |
    python3 -c "import json,sys; print(json.load(sys.stdin)['ManagedInstanceID'])" 2>/dev/null || true
}

id=$(registration)
if [ -z "$id" ]; then
  echo "[$name] registering as $role"
  echo "$ACTIVATION_ID $ACTIVATION_CODE" | "${ssh[@]}" 'read -r aid code; set -e
    snap list amazon-ssm-agent >/dev/null 2>&1 || sudo snap install amazon-ssm-agent --classic
    sudo snap stop amazon-ssm-agent
    sudo /snap/amazon-ssm-agent/current/amazon-ssm-agent -register -y -code "$code" -id "$aid" -region '"$AWS_DEFAULT_REGION"' >/dev/null
    sudo snap start amazon-ssm-agent'
  id=$(registration)
fi

# Role picks the State Manager association; the firewall is never isolated automatically.
tags=(Key=Role,Value="$role" Key=Name,Value="$name" Key=PatchGroup,Value=innovatech Key=Site,Value=office)
[ "$role" = firewall ] && tags+=(Key=SoarProtected,Value=true)
aws ssm add-tags-to-resource --resource-type ManagedInstance --resource-id "$id" --tags "${tags[@]}"
echo "[$name] $id tagged Role=$role"
