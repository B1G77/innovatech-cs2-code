# Innovatech Case Study 2: hybrid cloud, monitoring and an event-driven SOAR

Fontys ICT MA-NCA, Case Study 2. Flavor A: process detection & response, traffic pattern analysis.

The office runs on Fontys vSphere: firewall `fw01`, workstation `ws01`, server `srv01` and a Kali attacker.
`fw01` connects the office to AWS through an IPsec VPN with BGP. AWS hosts the new app, the central
logging (CloudWatch → OpenSearch → Grafana) and the serverless SOAR. Every machine, office or cloud,
is an SSM managed node. That lets one Ansible playbook update them all, and lets the SOAR act on them.

## Where things are

| Folder | What it holds | Start reading at |
|---|---|---|
| `terraform/platform` | AWS network (hub, workload VPC, Transit Gateway, VPN), DNS, logging, OpenSearch, alerts, updates | `network.tf`, `transit.tf` |
| `terraform/soar` | SOAR: webhook, EventBridge, Step Functions playbook, Lambdas, case table | `playbook.tf` |
| `terraform/office` | The office VMs on vSphere and their SSM registration | `main.tf` (host lists at the top) |
| `functions/soar` | SOAR code: normalise → decide (rules) → act | `rules.json`, `decide.py`, `actions.py` |
| `functions/indexer` | Copies CloudWatch logs into OpenSearch | `indexer.py` |
| `ansible` | Configuration and updates of every node, run by SSM State Manager | `site.yml` |
| `detectors` | Office detectors: traffic analyzer, process watcher | `traffic_analyzer.py` |
| `simulations` | Attack scenarios for the demo and tests | `scenarios.sh` |
| `scripts` | Deploy, destroy, demo and operator tools | see below |
| `tests` | Unit tests: `.venv/bin/python -m pytest -q tests` | |
| `.github/workflows` | CI (tests, validate), infra, SOAR and update pipelines on a self-hosted runner | `ci.yml` |

## Setup

You need Terraform 1.10 or newer, the AWS CLI with an SSO profile, Python 3 and, for the office on
vSphere, `govc` and a vCenter login.

```
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q tests          # 92 unit tests, no AWS access needed
```

Two values stay outside Git:

* `terraform/platform/terraform.tfvars` with `alert_email = "you@example.com"` (the address that receives
  alarms and SOAR e-mails; AWS sends a confirmation link first);
* the vCenter login as `VSPHERE_USER`, `VSPHERE_PASSWORD` and `VSPHERE_SERVER`. The scripts read them from
  `~/.config/claude-secrets/vsphere.env`; change that path in `scripts/deploy.sh` if yours differs.

## Everyday commands

```
scripts/deploy.sh                       # tests → platform → SOAR → office → CI runner   (~40 min)
scripts/destroy.sh                      # SOAR → forensic snapshots → platform           (~40 min)
scripts/onhost.sh fw01 'swanctl --list-sas'   # run a command on any host (fw01, ws01, srv01, ops, app)
scripts/run-updates.sh firewall         # run Ansible now instead of Sunday 03:00
simulations/scenarios.sh cryptominer    # run an attack; the SOAR answers
scripts/demo-soar.sh                    # every SOAR tier, step by step
scripts/grafana.sh                      # open Grafana on http://localhost:3000
```

AWS commands use profile `Goncalo` (`aws sso login --profile Goncalo` when it expires). The office
stack also needs the vCenter login: `source ~/.config/claude-secrets/vsphere.env`.

## Change recipes

Each change has one place to edit and one command to apply it. A push to `main` runs the same
apply through the pipelines.

**Add a workstation or server.** In `terraform/office/main.tf`, add a line to `workstations`
(PVlanA, 10.10.10.0/24) or `servers` (PVlanB, 10.10.20.0/24):
```hcl
ws03 = "10.10.10.13"
```
Apply with `terraform -chdir=terraform/office apply`. Terraform clones the VM, sets its address,
registers it with SSM (tag `Role=workstation`) and adds `ws03.corp.innovatech.lan` to the office DNS.
State Manager then runs Ansible on it. Remove the line to delete the VM and its SSM record.

**Add or change a firewall rule on fw01.** Edit `ansible/roles/office_firewall/templates/nftables.conf.j2`:
chain `input` for traffic to fw01, chain `forward` for traffic through it. Apply with
`terraform -chdir=terraform/platform apply` (uploads the new Ansible bundle), then `scripts/run-updates.sh firewall`.
Ansible checks the file with `nft -c` before loading it. The SOAR's active blocks survive the reload.

**Change a SOAR threshold or tier.** Edit `functions/soar/rules.json`. Each rule has a `match`
(`min_severity`, `min_count`, `scope`) and a `tier` (0 observe, 1 notify, 2 block at the firewall,
3 isolate the host). The first matching rule wins, so order matters. The time windows (5-minute count,
15-minute duplicate) sit at the top of `functions/soar/decide.py`. Run the tests, then
`terraform -chdir=terraform/soar apply`.

**Add an alert from logs.** Add an entry to `metric_filters` in `terraform/platform/alerts.tf`:
the log group, a CloudWatch filter pattern and, for an e-mail, an `alarm` with threshold and period.
Apply with `terraform -chdir=terraform/platform apply`.

**Add a log source on the office hosts.** Add the file to `inputs` in
`ansible/roles/fluentbit/templates/fluent-bit.conf.j2` and its log group to `log_groups` in
`terraform/platform/logging.tf`. The indexer copies every log group into OpenSearch, so Grafana
can query it without further changes.

**Change the update schedule.** `schedule_expression` in `terraform/platform/updates.tf` (now Sunday 03:00 UTC).

**Add a SOAR action.** Write the function in `functions/soar/actions.py` and add it to `ACTIONS`.
Put its name in a tier in `rules.json`, and give the Lambda the AWS permissions it needs in
`terraform/soar/functions.tf`. Add a test in `tests/test_actions_indexer.py`.

## Checks before you apply

```
.venv/bin/python -m pytest -q tests
terraform fmt -check -recursive terraform
terraform -chdir=terraform/<platform|soar|office> validate
ansible-playbook --syntax-check -i localhost, -c local ansible/site.yml -e node_role=server -e bundle_dir=/tmp
```
