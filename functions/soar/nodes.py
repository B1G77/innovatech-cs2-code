"""Office VMs on vSphere: SSM hybrid managed nodes (mi-...), looked up by IP or tag.

They have no EC2 API (no security groups, no EBS), so the SOAR reaches them only through
SSM: Run Command for actions, managed-node tags for its own bookkeeping.
"""
import boto3

ssm = boto3.client("ssm")


def is_office(node_id):
    return str(node_id or "").startswith("mi-")


def tags(node_id):
    found = ssm.list_tags_for_resource(ResourceType="ManagedInstance", ResourceId=node_id)["TagList"]
    return {t["Key"]: t["Value"] for t in found}


def add_tags(node_id, values):
    ssm.add_tags_to_resource(ResourceType="ManagedInstance", ResourceId=node_id,
                             Tags=[{"Key": k, "Value": v} for k, v in values.items()])


def remove_tags(node_id, keys):
    ssm.remove_tags_from_resource(ResourceType="ManagedInstance", ResourceId=node_id, TagKeys=list(keys))


def _nodes(filters):
    # SSM rejects a tag filter next to any other filter (found in testing), so the
    # "office nodes only" part is done here instead of with a ResourceType filter.
    pages = ssm.get_paginator("describe_instance_information").paginate(Filters=filters)
    return [n for page in pages for n in page["InstanceInformationList"] if is_office(n["InstanceId"])]


def online_with_tag(key, value):
    """Ids of the online office nodes with this tag (e.g. Role=firewall)."""
    return [n["InstanceId"] for n in _nodes([{"Key": f"tag:{key}", "Values": [value]}])
            if n.get("PingStatus") == "Online"]


def find(ip=None, node_id=None):
    """The office node with this id or IP, in the same shape as decide.find_target, or None."""
    if not ip and not is_office(node_id):
        return None
    matches = [n for n in _nodes([]) if n["InstanceId"] == node_id or (ip and n.get("IPAddress") == ip)]
    if len(matches) != 1:
        return None
    node = matches[0]
    t = tags(node["InstanceId"])
    return {
        "instance_id": node["InstanceId"],
        "name": t.get("Name", node.get("ComputerName", node["InstanceId"])),
        "ip": node.get("IPAddress"),
        "vpc_id": None,
        "site": "office",
        "protected": t.get("SoarProtected") == "true",
        "isolated": "SoarIsolated" in t,
    }
