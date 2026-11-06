"""Human step: release a host the SOAR isolated (invoked by scripts/soar-release.sh).

Isolation is never undone automatically: an analyst checks the forensic snapshot first.
"""
import ipaddress
import os
import time

import boto3

import nodes
from actions import OFFICE_LOCKDOWN, _firewall, _run
from common import log

ec2 = boto3.client("ec2")
state = boto3.resource("dynamodb").Table(os.environ.get("STATE_TABLE", "innovatech-soar-state"))


def handler(payload, _context):
    instance_id = str(payload.get("instance_id", ""))
    if nodes.is_office(instance_id):
        return _release_office(instance_id, payload)
    if not instance_id.startswith("i-"):
        raise ValueError("instance_id required")
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
    if "SoarIsolated" not in tags:
        return {"instance_id": instance_id, "released": False, "reason": "not isolated"}

    for pair in tags.get("SoarOriginalSGs", "").split(";"):
        if "=" in pair:
            nic, groups = pair.split("=", 1)
            ec2.modify_network_interface_attribute(NetworkInterfaceId=nic, Groups=groups.split(","))
    ip = str(ipaddress.IPv4Address(inst["PrivateIpAddress"]))
    _firewall([f"nft delete element inet soar quarantine '{{ {ip} }}' || true"], f"SOAR release {ip}")
    ec2.delete_tags(Resources=[instance_id], Tags=[{"Key": "SoarIsolated"}, {"Key": "SoarOriginalSGs"}])
    # Events that happened before this release must not isolate the host again (found in
    # testing: a finding queued on the isolated host arrived after the release).
    state.put_item(Item={"pk": f"released#{instance_id}", "at": int(time.time()), "expires": int(time.time()) + 86400})
    log("case", case_id=tags["SoarIsolated"], status="released", instance_id=instance_id,
        released_by=payload.get("analyst", "unknown"))
    return {"instance_id": instance_id, "released": True, "case_id": tags["SoarIsolated"]}


def _release_office(node_id, payload):
    """Office VM: remove its host lockdown and its entry in the firewall's quarantine set."""
    tags = nodes.tags(node_id)
    if "SoarIsolated" not in tags:
        return {"instance_id": node_id, "released": False, "reason": "not isolated"}
    node = nodes.find(node_id=node_id)
    ip = str(ipaddress.IPv4Address(node["ip"]))
    _run(node_id, [OFFICE_LOCKDOWN[0]], f"SOAR release {node_id}")
    _firewall([f"nft delete element inet soar quarantine '{{ {ip} }}' || true"], f"SOAR release {ip}")
    nodes.remove_tags(node_id, ["SoarIsolated"])
    state.put_item(Item={"pk": f"released#{node_id}", "at": int(time.time()), "expires": int(time.time()) + 86400})
    log("case", case_id=tags["SoarIsolated"], status="released", instance_id=node_id,
        released_by=payload.get("analyst", "unknown"))
    return {"instance_id": node_id, "released": True, "case_id": tags["SoarIsolated"]}
