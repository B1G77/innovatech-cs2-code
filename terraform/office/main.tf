# The office on Fontys vSphere: firewall, workstations, servers and the lab attacker.
#
# To add a workstation or server, add one line to the lists below and run:
#   source ~/.config/claude-secrets/vsphere.env
#   terraform -chdir=terraform/office apply
# Terraform clones the VM, gives it its first settings, registers it with SSM and adds it to
# the office DNS. State Manager then runs Ansible on it like on every other node. Removing a
# line destroys the VM and deregisters it.
#
# Runs from your Mac only: the CI runner in AWS cannot reach the netlab vCenter.

locals {
  # name = fixed address. Workstations sit on PVlanA (10.10.10.0/24), servers on PVlanB.
  workstations = {
    ws01 = "10.10.10.11"
    ws02 = "10.10.10.12"
  }
  servers = {
    srv01 = "10.10.20.10"
  }
}

# ---------------- Everything below follows from the lists above ----------------
terraform {
  required_version = ">= 1.10"

  backend "s3" {
    bucket       = "innovatech-tfstate-286439316079"
    key          = "cs2/office.tfstate"
    region       = "eu-central-1"
    profile      = "Goncalo"
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    vsphere = {
      source  = "hashicorp/vsphere"
      version = "~> 2.12"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "vsphere" {
  # VSPHERE_SERVER, VSPHERE_USER and VSPHERE_PASSWORD come from vsphere.env (never in git).
  allow_unverified_ssl = false
}

provider "aws" {
  region  = "eu-central-1"
  profile = "Goncalo"
}

locals {
  wan     = "0121_Internet-DHCP-192.168.121.0_24" # netlab segment, stands in for the internet
  ws_net  = "1196_I544337_PVlanA"
  srv_net = "1197_I544337_PVlanB"

  templates = {
    server  = "/Netlab-DC/vm/_Templates/All Courses/Templ_Ubuntu-Linux_Server_24.04.3"
    desktop = "/Netlab-DC/vm/_Templates/All Courses/Templ_Ubuntu-Linux_Desktop_24.04.3"
    kali    = "/Netlab-DC/vm/_Templates/Courses/ICS/Templ_Kali_2024.1"
  }

  # role = Role tag (selects the Ansible association); null = not a company machine.
  vms = merge(
    { fw01 = { template = "server", cpu = 2, memory = 2048, networks = [local.wan, local.ws_net, local.srv_net], ip = "dhcp", gateway = "-", role = "firewall" } },
    { for n, ip in local.workstations : n => { template = "desktop", cpu = 2, memory = 4096, networks = [local.ws_net], ip = "${ip}/24", gateway = "10.10.10.1", role = "workstation" } },
    { for n, ip in local.servers : n => { template = "server", cpu = 1, memory = 2048, networks = [local.srv_net], ip = "${ip}/24", gateway = "10.10.20.1", role = "server" } },
    { attacker = { template = "kali", cpu = 2, memory = 2048, networks = [local.wan], ip = "dhcp", gateway = "-", role = null } },
  )
  company = { for n, vm in local.vms : n => vm if vm.role != null }

  fw01_wan_ip = one([for a in vsphere_virtual_machine.vm["fw01"].guest_ip_addresses : a if startswith(a, "192.168.121.")])
}

# ---------------- vSphere inventory (names as in the vSphere client) ----------------
data "vsphere_datacenter" "dc" {
  name = "Netlab-DC"
}

data "vsphere_resource_pool" "pool" {
  name          = "/Netlab-DC/host/Netlab-Cluster-B/Resources/_Courses-RP-B/MA-NCA1-RP/I544337"
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_datastore_cluster" "students" {
  name          = "DataCluster-Students"
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_network" "net" {
  for_each      = toset([local.wan, local.ws_net, local.srv_net])
  name          = each.key
  datacenter_id = data.vsphere_datacenter.dc.id
}

data "vsphere_virtual_machine" "template" {
  for_each      = local.templates
  name          = each.value
  datacenter_id = data.vsphere_datacenter.dc.id
}

# ---------------- The VMs ----------------
resource "vsphere_virtual_machine" "vm" {
  for_each = local.vms

  name                 = each.key
  folder               = "_Courses/MA-NCA1/I544337"
  resource_pool_id     = data.vsphere_resource_pool.pool.id
  datastore_cluster_id = data.vsphere_datastore_cluster.students.id
  num_cpus             = each.value.cpu
  memory               = each.value.memory
  guest_id             = data.vsphere_virtual_machine.template[each.value.template].guest_id
  firmware             = data.vsphere_virtual_machine.template[each.value.template].firmware
  scsi_type            = data.vsphere_virtual_machine.template[each.value.template].scsi_type

  # NIC order sets the interface names fw01's Ansible expects: ens160 WAN, ens192 PVlanA, ens224 PVlanB.
  dynamic "network_interface" {
    for_each = each.value.networks
    content {
      network_id   = data.vsphere_network.net[network_interface.value].id
      adapter_type = "vmxnet3"
    }
  }

  disk {
    label            = "disk0"
    size             = data.vsphere_virtual_machine.template[each.value.template].disks[0].size
    thin_provisioned = data.vsphere_virtual_machine.template[each.value.template].disks[0].thin_provisioned
  }

  clone {
    template_uuid = data.vsphere_virtual_machine.template[each.value.template].id
  }

  # Office hosts get their fixed address later (first-settings.sh); until then they have none.
  wait_for_guest_net_timeout = each.value.ip == "dhcp" ? 5 : 0

  # Terraform sets the hardware when it creates a VM and leaves it alone afterwards. The VMs
  # adopted from govc (imports.tf) differ in disk label, CD-ROM and CPU layout; without this
  # the first plan replaced their disk with an empty one (found in review, 5 November).
  lifecycle {
    ignore_changes = [clone, disk, cdrom, num_cores_per_socket, enable_logging, sata_controller_count, ide_controller_count]
  }
}

# ---------------- First settings, then SSM registration (or the attacker's tools) ----------------
# Two steps per VM, both safe to repeat: first-settings.sh over VMware Tools, then register.sh
# (company VMs) or attacker-setup.sh (the lab attacker). A new VM, address or activation runs them
# again. fw01 goes first: the other VMs get their packages and reach AWS through it.

# One activation per VM, created with it: no shared code that expires after 24 hours.
resource "aws_ssm_activation" "node" {
  for_each = local.company

  name               = "innovatech-office-${each.key}"
  iam_role           = each.value.role == "firewall" ? "innovatech-onprem-firewall-role" : "innovatech-onprem-host-role"
  registration_limit = 1

  lifecycle {
    replace_triggered_by = [vsphere_virtual_machine.vm[each.key].id]
    ignore_changes       = [expiration_date]
  }
}

locals {
  setup = { for n, vm in local.vms : n => {
    first = "${path.module}/files/first-settings.sh ${n} ${vm.ip} ${vm.gateway}"
    then = (vm.role == null
      ? "ssh -o StrictHostKeyChecking=accept-new student@${vsphere_virtual_machine.vm[n].default_ip_address} sudo bash -s < ${path.module}/../../simulations/attacker-setup.sh"
    : "${path.module}/files/register.sh ${n} ${vm.role} ${vm.ip == "dhcp" ? local.fw01_wan_ip : split("/", vm.ip)[0]} ${local.fw01_wan_ip}")
    # The activation reaches register.sh through the environment, never on a command line.
    env      = { ACTIVATION_ID = try(aws_ssm_activation.node[n].id, ""), ACTIVATION_CODE = try(aws_ssm_activation.node[n].activation_code, "") }
    triggers = [vsphere_virtual_machine.vm[n].id, vm.ip, try(aws_ssm_activation.node[n].id, "")]
  } }
}

resource "terraform_data" "fw01" {
  input            = { name = "fw01" }
  triggers_replace = local.setup["fw01"].triggers

  provisioner "local-exec" {
    command = local.setup["fw01"].first
  }
  provisioner "local-exec" {
    command     = local.setup["fw01"].then
    environment = local.setup["fw01"].env
  }
  # A removed VM also leaves Systems Manager, so no stale managed node stays behind.
  provisioner "local-exec" {
    when    = destroy
    command = "${path.module}/files/register.sh --remove ${self.input.name}"
  }
}

resource "terraform_data" "vm" {
  for_each         = { for n, vm in local.vms : n => vm if n != "fw01" }
  input            = { name = each.key }
  triggers_replace = local.setup[each.key].triggers
  depends_on       = [terraform_data.fw01]

  provisioner "local-exec" {
    command = local.setup[each.key].first
  }
  provisioner "local-exec" {
    command     = local.setup[each.key].then
    environment = local.setup[each.key].env
  }
  provisioner "local-exec" {
    when    = destroy
    command = "${path.module}/files/register.sh --remove ${self.input.name}"
  }
}

# The office DNS (unbound on fw01) reads its host records from here.
resource "aws_ssm_parameter" "hosts" {
  name  = "/innovatech/onprem/hosts"
  type  = "String"
  value = jsonencode(merge(local.workstations, local.servers))
}

# A changed host list re-runs Ansible on fw01 now instead of at the next weekly run.
resource "terraform_data" "office_dns" {
  triggers_replace = [aws_ssm_parameter.hosts.value]
  depends_on       = [terraform_data.vm]

  provisioner "local-exec" {
    command     = "aws ssm start-associations-once --association-ids $(aws ssm list-associations --query 'Associations[?AssociationName==`innovatech-ansible-firewall`].AssociationId' --output text)"
    environment = { AWS_PROFILE = "Goncalo", AWS_DEFAULT_REGION = "eu-central-1" }
  }
}

output "fw01_wan_ip" {
  value = local.fw01_wan_ip
}

output "attacker_ip" {
  value = vsphere_virtual_machine.vm["attacker"].default_ip_address
}

output "office_hosts" {
  value = merge(local.workstations, local.servers)
}
