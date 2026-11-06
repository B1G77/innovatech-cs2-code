"""Playbook step 1: decide the response tier for one event (called by Step Functions).

Adds the context the pure rule engine needs: event counts in a 5-minute window, the target
host and whether it is protected, de-duplication, and the isolation circuit breaker.
"""
import os
import time
import uuid
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

import engine
import nodes
from common import log, metric

TIERS, RULES = engine.load_rules()
COUNT_WINDOW = 300     # seconds: "10 failures in 5 minutes"
DEDUP_WINDOW = 900     # seconds: the same incident within 15 minutes is the same case
MAX_ISOLATIONS = int(os.environ.get("MAX_ISOLATIONS_PER_HOUR", "5"))

state = boto3.resource("dynamodb").Table(os.environ.get("STATE_TABLE", "innovatech-soar-state"))
ec2 = boto3.client("ec2")


def _add(key, ttl):
    """Atomic counter in DynamoDB; old counters expire by themselves (TTL)."""
    resp = state.update_item(
        Key={"pk": key},
        UpdateExpression="ADD hits :one SET expires = :exp",
        ExpressionAttributeValues={":one": 1, ":exp": int(time.time()) + ttl},
        ReturnValues="UPDATED_NEW",
    )
    return int(resp["Attributes"]["hits"])


def _peek(key):
    item = state.get_item(Key={"pk": key}).get("Item")
    return int(item["hits"]) if item else 0


def count_recent(event):
    if not event.get("src_ip"):
        return 1
    bucket = int(time.time() // COUNT_WINDOW)
    return _add(f"count#{event['type']}#{event['src_ip']}#{bucket}", COUNT_WINDOW * 2)


def find_target(event):
    """The host a tier-3 action would hit: an EC2 instance (by instance id or private IP), or an
    office VM on vSphere, which is an SSM managed node (see nodes.py)."""
    if nodes.is_office(event.get("instance_id")):
        return nodes.find(node_id=event["instance_id"])
    filters = [{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
    if event.get("instance_id"):
        filters.append({"Name": "instance-id", "Values": [event["instance_id"]]})
    elif event.get("host_ip"):
        filters.append({"Name": "private-ip-address", "Values": [event["host_ip"]]})
    else:
        return None
    reservations = ec2.describe_instances(Filters=filters).get("Reservations", [])
    instances = [i for r in reservations for i in r["Instances"]]
    if not instances and event.get("host_ip"):
        return nodes.find(ip=event["host_ip"])
    if len(instances) != 1:
        return None
    inst = instances[0]
    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
    return {
        "instance_id": inst["InstanceId"],
        "name": tags.get("Name", inst["InstanceId"]),
        "ip": inst.get("PrivateIpAddress"),
        "vpc_id": inst.get("VpcId"),
        "protected": tags.get("SoarProtected") == "true",
        "isolated": "SoarIsolated" in tags,
    }


def is_duplicate(fingerprint, tier):
    """True when this incident already produced a case at this tier or higher recently."""
    try:
        state.put_item(
            Item={"pk": f"dedup#{fingerprint}", "tier": tier, "expires": int(time.time()) + DEDUP_WINDOW},
            ConditionExpression="attribute_not_exists(pk) OR #t < :tier OR expires < :now",
            ExpressionAttributeNames={"#t": "tier"},
            ExpressionAttributeValues={":tier": tier, ":now": int(time.time())},
        )
        return False
    except ClientError as err:
        if err.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return True
        raise


def _latency_ms(event):
    try:
        return max(0, int((time.time() - datetime.fromisoformat(event["time"]).timestamp()) * 1000))
    except (KeyError, ValueError, TypeError):
        return None


def handler(payload, _context):
    event = payload["event"]
    count = count_recent(event)
    tier, rule_id, reason, actions = engine.evaluate(event, count, TIERS, RULES)

    target = find_target(event) if tier == 3 else None
    hour_key = f"isolations#{int(time.time() // 3600)}"
    released = state.get_item(Key={"pk": f"released#{target['instance_id']}"}).get("Item") if target else None
    tier_after, note = engine.apply_guardrails(tier, event, target, TIERS, _peek(hour_key), MAX_ISOLATIONS,
                                               released_at=int(released["at"]) if released else None)
    if tier_after != tier:
        tier, actions = tier_after, list(TIERS[tier_after]["actions"])
        reason = f"{reason} Downgraded: {note}."

    fingerprint = "|".join(str(x) for x in (event["type"], event.get("src_ip"), (target or {}).get("ip") or event.get("host_ip") or event.get("host")))
    duplicate = tier > 0 and event["type"] != "soar.heartbeat" and is_duplicate(fingerprint, tier)
    if duplicate:
        actions = []
        metric("EventsDeduplicated")
    elif tier == 3:
        _add(hour_key, 7200)

    case = {
        "case_id": str(uuid.uuid4()),
        "created": datetime.now().astimezone().isoformat(timespec="seconds"),
        "tier": tier,
        "tier_name": engine.tier_name(tier, TIERS),
        "rule": rule_id,
        "reason": reason,
        "count_5min": count,
        "duplicate": duplicate,
        "target": target,
        "execution": payload.get("execution"),
    }
    metric("EventsProcessed", dimensions={"Tier": str(tier)})
    latency = _latency_ms(event)
    if latency is not None:
        metric("ProcessingLatency", latency, unit="Milliseconds")
    log("decision", case_id=case["case_id"], tier=tier, rule=rule_id, type=event["type"],
        severity=event["severity"], src_ip=event.get("src_ip"), duplicate=duplicate, actions=actions)
    return {"case": case, "event": event, "actions": actions}
