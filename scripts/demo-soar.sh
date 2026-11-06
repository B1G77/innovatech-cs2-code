#!/usr/bin/env bash
# Demo: every SOAR response in one run, in order. Before each step it says what the step shows and
# waits: Enter = run, s = skip, q = stop. About 6 minutes. Step 7 releases and removes the isolated
# server, so the next run starts clean. Alerts repeated within 15 minutes count as duplicates (a guard
# rail) and do nothing, so leave 15 minutes between two full runs.
#   demo-soar.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export AWS_PAGER="" AWS_PROFILE=${AWS_PROFILE:-Goncalo} AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1}

last="${TMPDIR:-/tmp}/innovatech-demo-soar.last"
if [ -f "$last" ] && [ $(( $(date +%s) - $(cat "$last") )) -lt 900 ]; then
  left=$(( (900 - $(date +%s) + $(cat "$last")) / 60 + 1 ))
  echo "Note: the last run was less than 15 minutes ago, so its alerts would be duplicates and do nothing."
  echo "      Wait $left more minutes, or carry on and skip the steps you already showed."
fi

step() {  # step <number> <what it is> <what to show>; fails when skipped
  echo; echo "=== Step $1 of 8: $2"; echo "    Show: $3"
  read -r -p "    Enter = run, s = skip, q = stop: " answer
  case $answer in q|Q) exit 0 ;; s|S) return 1 ;; esac
}
run() {
  scripts/demo-alert.sh "$1" || echo "    This step did not finish. Carry on, or show the evidence files instead."
}

step 1 "Tier 0, observe: an event no rule acts on is only recorded" "the DECIDE and ACT lines" && run observe
step 2 "Tier 1, notify: a soft signal (high CPU) is recorded and someone is told" "the e-mail" && run notify && date +%s > "$last"
step 3 "Guard rail, duplicate: the same alert within 15 minutes is the same case" "'duplicate' and no actions" && run notify
step 4 "Tier 2, contain the network: an internet scan, block the address for 1 hour" "block_ip, skipped until the office firewall exists" && run scan
step 5 "Tier 3, isolate the host: a cryptominer on an app server" "EC2 Security tab, Auto Scaling Activity, Snapshots, Step Functions graph, e-mail" && run miner
step 6 "Guard rail, protected host: the same miner on the ops host only alerts a person" "DECIDE tier 1" && run protected
if step 7 "Analyst: a person releases the isolated server, then it is removed (a clean one already replaced it)" "\"released\": true, EC2 Instances"; then
  ids=$(aws ec2 describe-instances --filters Name=tag-key,Values=SoarCase Name=instance-state-name,Values=running \
    --query 'Reservations[].Instances[].InstanceId' --output text)
  [ -n "$ids" ] || echo "    No isolated server found."
  for id in $ids; do
    scripts/soar-release.sh "$id" goncalo
    aws ec2 terminate-instances --instance-ids "$id" --query 'TerminatingInstances[].[InstanceId,CurrentState.Name]' --output text
  done
fi
step 8 "Failure path: an action fails, the SOAR retries, then tells a person (two alarms turn red for a few minutes)" "the [SOAR FAILED] e-mail, the red Step Functions run" && run failure
echo; echo "Done. The heartbeat (tier 0) runs by itself every 5 minutes: Grafana, top row."
