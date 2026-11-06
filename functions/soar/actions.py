"""Playbook step 2: run one automated action (Step Functions calls this once per action, in order).

Every action is idempotent (running it twice does no harm), because Step Functions retries
failed steps. Addresses are re-validated here before they go anywhere near a shell command.
"""
import ipaddress
import json
import os
import re
import time

import boto3

import nodes
from common import is_outside, log, metric

ssm = boto3.client("ssm")
ec2 = boto3.client("ec2")
autoscaling = boto3.client("autoscaling")
sns = boto3.client("sns")
cases = boto3.resource("dynamodb").Table(os.environ.get("CASES_TABLE", "innovatech-soar-cases"))

FW_INSTANCE_ID = os.environ.get("FW_INSTANCE_ID", "")
TOPIC_ARN = os.environ.get("TOPIC_ARN", "")
QUARANTINE_SGS = json.loads(os.environ.get("QUARANTINE_SGS", "{}"))   # vpc id -> sg id
NEVER_BLOCK = set(json.loads(os.environ.get("NEVER_BLOCK", "[]")))      # VPN peers, our own public IPs
BLOCK_TTL = os.environ.get("BLOCK_TTL", "1h")
CHAOS_PARAM = os.environ.get("CHAOS_PARAM", "")
FORENSICS_BUCKET = os.environ.get("FORENSICS_BUCKET", "")
OFFICE_DNS = os.environ.get("OFFICE_DNS", "10.10.0.10")

_chaos = {"at": 0, "value": ""}


class ActionError(Exception):
    """An action could not be completed; Step Functions retries, then reports the failure."""


def _chaos_check(action):
    """Failure injection for design-for-failure tests: list action names in the SSM parameter."""
    if not CHAOS_PARAM:
        return
    if time.time() - _chaos["at"] > 30:
        try:
            _chaos["value"] = ssm.get_parameter(Name=CHAOS_PARAM)["Parameter"]["Value"]
        except ssm.exceptions.ParameterNotFound:
            _chaos["value"] = ""
        _chaos["at"] = time.time()
    if action in [a.strip() for a in _chaos["value"].split(",")]:
        raise ActionError(f"chaos: action '{action}' is set to fail")


def _ipv4(value, want):
    """Strict check: a real IPv4 address of the expected kind, or ActionError."""
    try:
        addr = ipaddress.IPv4Address(str(value))
    except ValueError as err:
        raise ActionError(f"not an IPv4 address: {value!r}") from err
    if want == "external" and not is_outside(addr):
        raise ActionError(f"{addr} is not an internet address")
    if want == "internal" and (not addr.is_private or is_outside(addr)):
        raise ActionError(f"{addr} is not a private address")
    return str(addr)


def firewall_id():
    """The running office firewall, looked up by its Role tag at call time. A stored instance id
    goes stale when the firewall is rebuilt (found in testing); the env var is only a fallback.
    On vSphere the firewall is an SSM managed node (mi-...), elsewhere an EC2 instance."""
    res = ec2.describe_instances(Filters=[{"Name": "tag:Role", "Values": ["firewall"]},
                                          {"Name": "instance-state-name", "Values": ["running"]}])["Reservations"]
    ids = [i["InstanceId"] for r in res for i in r["Instances"]] + nodes.online_with_tag("Role", "firewall")
    if len(ids) == 1:
        return ids[0]
    if FW_INSTANCE_ID:
        return FW_INSTANCE_ID
    if not ids:
        return None  # no office firewall connected (yet): firewall actions are skipped
    raise ActionError(f"expected one running firewall, found {len(ids)}")


def _firewall(commands, comment):
    """Runs nft commands on the office firewall through SSM and waits for the result."""
    fw = firewall_id()
    if fw is None:
        return {"skipped": "no on-prem firewall connected"}
    return _run(fw, commands, comment)


def _run(node, commands, comment, wait=True, **extra):
    """Runs shell commands on one node through SSM Run Command; waits for the result by default."""
    cmd = ssm.send_command(
        InstanceIds=[node], DocumentName="AWS-RunShellScript", Comment=comment[:100],
        Parameters={"commands": ["set -e"] + commands}, TimeoutSeconds=60, **extra,
    )["Command"]["CommandId"]
    if not wait:
        return {"command_id": cmd}
    for _ in range(25):
        time.sleep(2)
        try:
            inv = ssm.get_command_invocation(CommandId=cmd, InstanceId=node)
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        if inv["Status"] == "Success":
            return {"command_id": cmd, "output": inv["StandardOutputContent"][-500:]}
        if inv["Status"] in ("Failed", "Cancelled", "TimedOut"):
            raise ActionError(f"command on {node} {inv['Status']}: {inv['StandardErrorContent'][-300:]}")
    raise ActionError(f"command on {node} did not finish in time")


# ---------------- actions ----------------
def record(case, event):
    status = "closed" if case["tier"] == 0 else "open"
    if case["tier"] > 0:
        cases.put_item(Item={"case_id": case["case_id"], "status": status, "created": case["created"],
                             "tier": case["tier"], "rule": case["rule"], "type": event["type"],
                             "summary": event["summary"], "case": json.dumps(case, default=str),
                             "event": json.dumps(event, default=str)})
    log("case", case_id=case["case_id"], status=status, tier=case["tier"], tier_name=case["tier_name"],
        rule=case["rule"], reason=case["reason"], type=event["type"], severity=event["severity"],
        summary=event["summary"], host=event.get("host"), src_ip=event.get("src_ip"),
        target=(case.get("target") or {}).get("name"))
    return {"status": status}


def notify(case, event):
    target = (case.get("target") or {}).get("name") or event.get("host") or event.get("host_ip") or "-"
    subject = f"[SOAR tier {case['tier']} {case['tier_name']}] {event['type']} on {target}"[:100]
    body = "\n".join([
        event["summary"],
        "",
        f"Case:      {case['case_id']}",
        f"Rule:      {case['rule']} - {case['reason']}",
        f"Severity:  {event['severity']}/10   seen {case.get('count_5min', 1)}x in 5 min",
        f"Source:    {event.get('src_ip') or '-'} ({event.get('scope')})",
        f"Target:    {target}",
        f"Detector:  {event['source']}   time {event['time']}",
        "",
        "Runbook: docs/soar-playbook.md. Release an isolated host with scripts/soar-release.sh <instance-id>.",
    ])
    msg = sns.publish(TopicArn=TOPIC_ARN, Subject=subject, Message=body)
    return {"message_id": msg["MessageId"]}


def block_ip(case, event):
    ip = _ipv4(event.get("src_ip"), "external")
    if ip in NEVER_BLOCK:
        raise ActionError(f"{ip} is on the never-block list")
    if not re.fullmatch(r"\d{1,3}[smhd]", BLOCK_TTL):
        raise ActionError("bad BLOCK_TTL")
    out = _firewall([f"nft add element inet soar block '{{ {ip} timeout {BLOCK_TTL} }}'",
                     f"conntrack -D -s {ip} >/dev/null 2>&1 || true",
                     "nft list set inet soar block"], f"SOAR {case['case_id']} block {ip}")
    if "skipped" in out:
        return {"target": ip, **out}
    return {"blocked": ip, "for": BLOCK_TTL, **out}


def fw_quarantine(case, event):
    target = case.get("target") or {}
    ip = _ipv4(target.get("ip") or event.get("host_ip"), "internal")
    if target.get("vpc_id") and target["vpc_id"] not in QUARANTINE_SGS:
        raise ActionError("unknown network for this host")
    out = _firewall([f"nft add element inet soar quarantine '{{ {ip} }}'",
                     f"conntrack -D -s {ip} >/dev/null 2>&1 || true",
                     f"conntrack -D -d {ip} >/dev/null 2>&1 || true"], f"SOAR {case['case_id']} quarantine {ip}")
    if "skipped" in out:
        return {"target": ip, **out}
    return {"quarantined": ip, **out}


# Host firewall on an isolated office VM: only loopback, replies, and the management channel
# (HTTPS for SSM and the SOAR webhook, DNS to the office resolver). Inside one VLAN the office
# firewall never sees host-to-host traffic, so the quarantine set there alone cannot stop
# lateral movement; this table can.
OFFICE_LOCKDOWN = [
    "nft delete table inet soar_isolation 2>/dev/null || true",
    "nft -f - <<'EOF'\n"
    # One rule per line: nft rejects "accept }" (found on vSphere, 5 November).
    "table inet soar_isolation {\n"
    "  chain input {\n"
    "    type filter hook input priority -10; policy drop;\n"
    "    iif lo accept\n"
    "    ct state established,related accept\n"
    "  }\n"
    "  chain output {\n"
    "    type filter hook output priority -10; policy drop;\n"
    "    oif lo accept\n"
    "    ct state established,related accept\n"
    "    tcp dport 443 accept\n"
    "    ip daddr {dns} udp dport 53 accept\n"
    "  }\n"
    "}\n"
    "EOF",
    "nft list table inet soar_isolation >/dev/null",
]


def isolate_host(case, _event):
    target = case.get("target") or {}
    instance_id = target.get("instance_id")
    if not instance_id or target.get("protected"):
        raise ActionError("no isolatable target")
    if nodes.is_office(instance_id):
        return _isolate_office(case, instance_id)
    sg = QUARANTINE_SGS.get(target.get("vpc_id"))
    if not sg:
        raise ActionError(f"no quarantine group for {target.get('vpc_id')}")
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
    if "SoarIsolated" in tags:
        return {"instance_id": instance_id, "already_isolated_by": tags["SoarIsolated"], **_detach_from_group(instance_id)}
    saved = ";".join(f"{n['NetworkInterfaceId']}={','.join(g['GroupId'] for g in n['Groups'])}"
                     for n in inst["NetworkInterfaces"])
    ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "SoarOriginalSGs", "Value": saved[:255]},
                                                   {"Key": "SoarIsolated", "Value": case["case_id"]},
                                                   {"Key": "SoarCase", "Value": case["case_id"]}])  # kept after release
    for nic in inst["NetworkInterfaces"]:
        ec2.modify_network_interface_attribute(NetworkInterfaceId=nic["NetworkInterfaceId"], Groups=[sg])
    return {"instance_id": instance_id, "quarantine_sg": sg, "previous": saved, **_detach_from_group(instance_id)}


def _isolate_office(case, node_id):
    if "SoarIsolated" in nodes.tags(node_id):
        return {"instance_id": node_id, "already_isolated": True}
    commands = [c.replace("{dns}", _ipv4(OFFICE_DNS, "internal")) for c in OFFICE_LOCKDOWN]
    out = _run(node_id, commands, f"SOAR {case['case_id']} isolate")
    nodes.add_tags(node_id, {"SoarIsolated": case["case_id"], "SoarCase": case["case_id"]})
    return {"instance_id": node_id, "host_firewall": "soar_isolation", "command_id": out["command_id"]}


def _detach_from_group(instance_id):
    """An Auto Scaling group replaces an instance that fails its health checks, and an isolated
    instance always fails them: the group terminated the evidence (found in testing). Detaching
    keeps the isolated instance for forensics; the group launches a healthy replacement."""
    found = autoscaling.describe_auto_scaling_instances(InstanceIds=[instance_id])["AutoScalingInstances"]
    if not found:
        return {}
    group = found[0]["AutoScalingGroupName"]
    autoscaling.detach_instances(InstanceIds=[instance_id], AutoScalingGroupName=group,
                                 ShouldDecrementDesiredCapacity=False)
    return {"detached_from": group}


# Forensic capture on an office VM (vSphere has no EBS snapshot the SOAR can reach): what runs,
# who is connected, and a hash of every running program. Run Command writes it to S3.
FORENSIC_CAPTURE = [
    "date -u; hostname; uptime",
    "ps -eo pid,ppid,user,%cpu,%mem,lstart,args --sort=-%cpu | head -50",
    "ss -tunap",
    "who; last -n 20 || true",
    "for p in /proc/[0-9]*; do readlink -f $p/exe; done 2>/dev/null | sort -u | xargs -r sha256sum 2>/dev/null",
    "journalctl -n 200 --no-pager || true",
]


def snapshot(case, _event):
    instance_id = (case.get("target") or {}).get("instance_id")
    if not instance_id:
        raise ActionError("no target instance")
    if nodes.is_office(instance_id):
        if not FORENSICS_BUCKET:
            raise ActionError("no forensics bucket configured")
        prefix = f"soar-forensics/{case['case_id']}"
        out = _run(instance_id, FORENSIC_CAPTURE, f"SOAR {case['case_id']} forensics", wait=False,
                   OutputS3BucketName=FORENSICS_BUCKET, OutputS3KeyPrefix=prefix)
        return {"forensics": f"s3://{FORENSICS_BUCKET}/{prefix}/", **out}
    vols = ec2.describe_volumes(Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}])["Volumes"]
    snaps = []
    for vol in vols:
        # Idempotent: two detectors can open two cases for the same host seconds apart, and EC2
        # refuses a second snapshot of a volume that quickly (found in testing). Reuse a recent one.
        recent = [x for x in ec2.describe_snapshots(OwnerIds=["self"], Filters=[
            {"Name": "volume-id", "Values": [vol["VolumeId"]]}, {"Name": "tag-key", "Values": ["SoarCase"]}])["Snapshots"]
            if time.time() - x["StartTime"].timestamp() < 900]
        if recent:
            snaps.append(recent[0]["SnapshotId"])
            continue
        snap = ec2.create_snapshot(
            VolumeId=vol["VolumeId"], Description=f"SOAR forensic copy, case {case['case_id']}",
            TagSpecifications=[{"ResourceType": "snapshot", "Tags": [
                {"Key": "Project", "Value": "innovatech"}, {"Key": "SoarCase", "Value": case["case_id"]},
                {"Key": "Name", "Value": f"soar-forensic-{instance_id}"}]}])
        snaps.append(snap["SnapshotId"])
    return {"snapshots": snaps}


def heartbeat(_case, _event):
    metric("Heartbeat")
    return {"alive": True}


def report_failure(case, event, error=None):
    """Called by the playbook's Catch: a person must take over."""
    metric("PlaybookFailures")
    sns.publish(TopicArn=TOPIC_ARN, Subject=f"[SOAR FAILED] {event['type']} case {case['case_id'][:8]}"[:100],
                Message=f"An automated action failed after retries.\n\nError: {json.dumps(error)[:1500]}\n\n"
                        f"Event: {event['summary']}\nCase: {case['case_id']}\n"
                        "Check the Step Functions execution and finish the response by hand.")
    log("case", case_id=case["case_id"], status="action-failed", tier=case["tier"], error=error)
    return {"reported": True}


ACTIONS = {f.__name__: f for f in (record, notify, block_ip, fw_quarantine, isolate_host, snapshot, heartbeat)}


def handler(payload, _context):
    action, case, event = payload["action"], payload["case"], payload["event"]
    if action == "report_failure":
        return report_failure(case, event, payload.get("error"))
    if action not in ACTIONS:
        raise ActionError(f"unknown action {action}")
    try:
        _chaos_check(action)
        result = ACTIONS[action](case, event)
    except Exception as err:
        metric("ActionsFailed", dimensions={"Action": action})
        log("action", case_id=case["case_id"], action=action, ok=False, error=str(err)[:500])
        raise
    if isinstance(result, dict) and "skipped" in result:
        # Not a failure (nothing to retry), but not a success either: the case must not claim
        # a containment that never happened.
        metric("ActionsSkipped", dimensions={"Action": action})
        log("action", case_id=case["case_id"], action=action, ok=False, skipped=result["skipped"], result=result)
        return {"action": action, "ok": False, "skipped": result["skipped"], "result": result}
    metric("ActionsSucceeded", dimensions={"Action": action})
    log("action", case_id=case["case_id"], action=action, ok=True, result=result)
    return {"action": action, "ok": True, "result": result}
