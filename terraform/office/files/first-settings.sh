#!/usr/bin/env bash
# First settings of a freshly cloned office VM, through VMware Tools (the VM has no SSH yet):
# your SSH key, passwordless sudo, keys-only SSH, hostname and, for office hosts, a fixed
# address behind fw01. Terraform runs it once per new VM (terraform/office/main.tf).
#
#   first-settings.sh <vm> <ip/prefix | dhcp> <gateway | ->
#
# Needs govc and ~/.config/claude-secrets/vsphere.env (GOVC_URL, GOVC_USERNAME, GOVC_PASSWORD).
set -euo pipefail
source ~/.config/claude-secrets/vsphere.env

name=$1 ip=$2 gw=$3
VM=/Netlab-DC/vm/_Courses/MA-NCA1/I544337/$name
GUEST=student:student   # the templates' default login; SSH becomes keys only below
KEY=$(cat ~/.ssh/id_ed25519.pub)

guest() {  # guest < script: runs the script as root inside the VM
  # VMware Tools passes the command line to /bin/sh unquoted, so "bash -c '...|...'" breaks
  # (found in testing: sudo got an empty password). Uploading a small runner avoids quoting.
  local tmp; tmp=$(mktemp)
  cat >"$tmp"
  govc guest.upload -l "$GUEST" -vm "$VM" -f "$tmp" /tmp/onprem-setup.sh >/dev/null
  printf '#!/bin/sh\necho student | sudo -S -p "" bash /tmp/onprem-setup.sh\nrc=$?\nrm -f /tmp/onprem-setup.sh /tmp/onprem-run.sh\nexit $rc\n' >"$tmp"
  govc guest.upload -l "$GUEST" -vm "$VM" -f "$tmp" /tmp/onprem-run.sh >/dev/null
  rm -f "$tmp"
  govc guest.run -l "$GUEST" -vm "$VM" /bin/sh /tmp/onprem-run.sh
}

echo "[$name] waiting for VMware Tools"
until govc guest.run -l "$GUEST" -vm "$VM" /bin/true 2>/dev/null; do sleep 10; done

guest <<SETUP
set -e
install -d -m 700 -o student -g student /home/student/.ssh
grep -qF '$KEY' /home/student/.ssh/authorized_keys 2>/dev/null || echo '$KEY' >> /home/student/.ssh/authorized_keys
chown student:student /home/student/.ssh/authorized_keys; chmod 600 /home/student/.ssh/authorized_keys
echo 'student ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-student; chmod 440 /etc/sudoers.d/90-student
hostnamectl set-hostname $name
grep -q " $name\$" /etc/hosts || echo "127.0.1.1 $name" >> /etc/hosts
if [ "$ip" != dhcp ]; then
  # Office host: fixed address behind fw01, which is also its DNS server.
  nic=\$(ip -o link | awk -F': ' '\$2 ~ /^en/ {print \$2; exit}')
  rm -f /etc/netplan/*.yaml
  cat > /etc/netplan/60-office.yaml <<NETPLAN
network:
  version: 2
  ethernets:
    \$nic:
      addresses: [$ip]
      routes: [{to: default, via: $gw}]
      nameservers: {addresses: [10.10.0.10], search: [corp.innovatech.lan]}
NETPLAN
  chmod 600 /etc/netplan/60-office.yaml
  netplan apply
fi
# The desktop template has no SSH server; install it once fw01 gives the host internet.
for i in \$(seq 1 30); do command -v sshd >/dev/null && break; apt-get update -q && apt-get install -y -q openssh-server && break; sleep 20; done
printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' > /etc/ssh/sshd_config.d/10-keys-only.conf
systemctl enable --now ssh
systemctl reload ssh
SETUP
echo "[$name] ready"
