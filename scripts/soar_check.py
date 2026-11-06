#!/usr/bin/env python3
"""Shows what the SOAR did since a point in time: cases, actions, firewall sets, isolated
hosts, forensic snapshots and the notifications that reached the test queue.

    .venv/bin/python scripts/soar_check.py --since 2026-10-12T05:50:00Z [--expect R13-internal-scan]
Exit code 1 when --expect names a rule that produced no case.
"""
import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parent.parent


def tf_output(name):
    out = subprocess.run(["terraform", f"-chdir={ROOT}/terraform/platform", "output", "-json", name],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", required=True, help="ISO time, e.g. 2026-10-12T05:50:00Z")
    parser.add_argument("--expect", action="append", default=[], help="rule id that must have produced a case")
    args = parser.parse_args()
    since = datetime.fromisoformat(args.since.replace("Z", "+00:00"))
    ms = int(since.timestamp() * 1000)

    logs = boto3.client("logs")
    print(f"== Decisions and actions since {since.isoformat()}")
    seen_rules = set()
    for group, kind in (("/aws/lambda/innovatech-soar-decide", "decision"), ("/aws/lambda/innovatech-soar-act", "action")):
        events = logs.filter_log_events(logGroupName=group, startTime=ms,
                                        filterPattern=f'{{ $.log_type = "{kind}" }}').get("events", [])
        for e in events:
            d = json.loads(e["message"])
            if kind == "decision":
                if d["type"] == "soar.heartbeat":
                    continue
                seen_rules.add(d["rule"])
                print(f"  {d['@timestamp'][11:19]} DECIDE tier {d['tier']} {d['rule']:<24} {d['type']:<26} "
                      f"src={d.get('src_ip')} dup={d['duplicate']} actions={d['actions']}")
            elif d.get("action") != "heartbeat":
                res = json.dumps(d.get("result") or d.get("error"))[:110]
                print(f"  {d['@timestamp'][11:19]} ACT    {d['action']:<14} ok={d['ok']} {res}")

    print("\n== Firewall SOAR sets (fw01)")
    out = subprocess.run([str(ROOT / "scripts/onhost.sh"), "fw01", "nft list table inet soar | sed -n '/set block/,/chain/p'"],
                         capture_output=True, text=True).stdout
    print("  " + "\n  ".join(l for l in out.splitlines() if "elements" in l or "set " in l) or "  (empty)")

    ec2 = boto3.client("ec2")
    print("\n== Isolated hosts")
    res = ec2.describe_instances(Filters=[{"Name": "tag-key", "Values": ["SoarIsolated"]}])["Reservations"]
    for r in res:
        for i in r["Instances"]:
            tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
            print(f"  {tags.get('Name')} {i['InstanceId']} case={tags['SoarIsolated'][:8]} "
                  f"sgs={[g['GroupName'] for g in i['SecurityGroups']]}")
    if not res:
        print("  (none)")

    print("\n== Forensic snapshots")
    snaps = ec2.describe_snapshots(OwnerIds=["self"], Filters=[{"Name": "tag-key", "Values": ["SoarCase"]}])["Snapshots"]
    for s in snaps:
        if s["StartTime"] >= since:
            print(f"  {s['SnapshotId']} {s['VolumeId']} {s['State']} {s['Description']}")

    print("\n== Notifications received by the test queue")
    sqs = boto3.client("sqs")
    url = tf_output("alert_test_queue_url")
    while True:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get("Messages", [])
        if not msgs:
            break
        for m in msgs:
            body = json.loads(m["Body"])
            print(f"  {body.get('Timestamp', '')[11:19]} {body.get('Subject')}")
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])

    missing = [r for r in args.expect if r not in seen_rules]
    if missing:
        print(f"\nMISSING expected rule(s): {missing}")
        return 1
    if args.expect:
        print(f"\nPASS: expected rule(s) fired: {args.expect}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
