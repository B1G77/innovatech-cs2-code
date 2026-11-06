#!/usr/bin/env bash
# First deployment from a laptop (afterwards the pipelines on the ops host take over).
# Order matters: the SOAR reads the platform's outputs.
set -euo pipefail
cd "$(dirname "$0")/.."
export AWS_PROFILE=${AWS_PROFILE:-Goncalo} AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1} AWS_PAGER=""

.venv/bin/python -m pytest -q tests -p no:cacheprovider
terraform -chdir=terraform/platform init -input=false
terraform -chdir=terraform/platform apply -input=false -auto-approve
terraform -chdir=terraform/soar init -input=false
terraform -chdir=terraform/soar apply -input=false -auto-approve
# The office on vSphere needs the platform's IAM roles and Ansible associations, so it comes last.
if [ -f ~/.config/claude-secrets/vsphere.env ]; then
  source ~/.config/claude-secrets/vsphere.env
  terraform -chdir=terraform/office init -input=false
  terraform -chdir=terraform/office apply -input=false -auto-approve
fi
scripts/register-runner.sh || echo "runner registration failed: run scripts/register-runner.sh again later"
echo "Deployed. Grafana: $(terraform -chdir=terraform/platform output -raw grafana_tunnel)"
