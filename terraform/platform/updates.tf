# REQ-NCA-P1-05: central, automated updates and configuration for every node.
#   * Ansible does the work (patch, baseline, agents) - one playbook for all nodes.
#   * SSM State Manager runs it on every node with tag PatchGroup, at creation and weekly,
#     a few nodes at a time; new or replaced nodes get it automatically.
#   * Patch Manager scans daily, so "is every node patched?" is a compliance report, not a guess.
resource "aws_ssm_document" "ansible" {
  name            = "${var.project}-ApplyAnsible"
  document_type   = "Command"
  document_format = "YAML"

  content = yamlencode({
    schemaVersion = "2.2"
    description   = "Download the Innovatech bundle and run its Ansible playbook locally."
    parameters = {
      NodeRole = { type = "String", description = "firewall | workstation | server | app | ops" }
      Bucket   = { type = "String", default = aws_s3_bucket.artifacts.id }
      Key      = { type = "String", description = "Bundle object; its name contains its hash" }
      Playbook = { type = "String", default = "site.yml", allowedPattern = "^[a-z_]+\\.yml$" }
    }
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "ansible"
      inputs = {
        timeoutSeconds = "1800"
        runCommand = [
          "set -eu # runs under /bin/sh (dash on Ubuntu): no pipefail",
          "if command -v apt-get >/dev/null; then export DEBIAN_FRONTEND=noninteractive; command -v ansible-playbook >/dev/null || { apt-get -o DPkg::Lock::Timeout=600 update -q; apt-get -o DPkg::Lock::Timeout=600 install -y -q ansible-core python3-boto3 unzip; }; fi",
          "if command -v dnf >/dev/null; then command -v ansible-playbook >/dev/null || dnf install -y -q ansible-core || { dnf install -y -q python3-pip && pip3 install -q ansible-core; }; dnf install -y -q python3-boto3 unzip || true; fi",
          "work=$(mktemp -d) && cd \"$work\"",
          # Retry: office nodes have no network while their firewall is being replaced (found in testing).
          "for i in 1 2 3 4 5 6 7 8 9 10; do python3 -c \"import boto3,sys; boto3.client('s3').download_file(sys.argv[1], sys.argv[2], 'bundle.zip')\" '{{ Bucket }}' '{{ Key }}' && break; sleep 30; done; test -s bundle.zip",
          "python3 -m zipfile -e bundle.zip .",
          "ansible-playbook -c local -i localhost, ansible/{{ Playbook }} -e node_role={{ NodeRole }} -e bundle_dir=$work -e aws_region=${var.region}",
          "cd / && rm -rf \"$work\"",
        ]
      }
    }]
  })
}

locals {
  ansible_roles = ["firewall", "workstation", "server", "app", "ops"]
}

resource "aws_ssm_association" "ansible" {
  for_each = toset(local.ansible_roles)

  name                = aws_ssm_document.ansible.name
  association_name    = "${var.project}-ansible-${each.key}"
  schedule_expression = "cron(0 3 ? * SUN *)" # weekly, Sunday 03:00 UTC; also runs at creation
  max_concurrency     = "50%"                 # never all nodes of a role at once
  max_errors          = "1"
  compliance_severity = "HIGH"

  parameters = {
    NodeRole = each.key
    # A new bundle has a new name (hash), which re-runs the association on every node.
    Key = aws_s3_object.bundle.key
  }

  targets {
    key    = "tag:Role"
    values = [each.key]
  }

  output_location {
    s3_bucket_name = aws_s3_bucket.artifacts.id
    s3_key_prefix  = "ssm-output/ansible-${each.key}"
  }
}

resource "aws_ssm_association" "patch_scan" {
  name                = "AWS-RunPatchBaseline"
  association_name    = "${var.project}-patch-scan"
  schedule_expression = "rate(1 day)"

  parameters = {
    Operation = "Scan"
  }

  targets {
    key    = "tag:PatchGroup"
    values = [var.project]
  }
}
