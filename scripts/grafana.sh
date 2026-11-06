#!/usr/bin/env bash
# Opens Grafana for the demo: copies the admin password to the clipboard, then holds the SSM tunnel
# to the ops host open. Browser: http://localhost:3000, user admin, paste the password. Ctrl+C closes it.
set -euo pipefail
cd "$(dirname "$0")/.."
export AWS_PROFILE=${AWS_PROFILE:-Goncalo} AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1} AWS_PAGER=""

aws ssm get-parameter --name /innovatech/grafana/admin-password --with-decryption \
  --query Parameter.Value --output text | tr -d '\n' | pbcopy
echo "Password copied. Open http://localhost:3000, user admin, paste with Cmd+V."

if lsof -nP -iTCP:3000 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "The tunnel is already open (port 3000 in use); nothing else to do."
  exit 0
fi
echo "Opening the tunnel. Leave this window open."
$(terraform -chdir=terraform/platform output -raw grafana_tunnel)
