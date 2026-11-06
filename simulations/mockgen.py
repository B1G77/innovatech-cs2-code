#!/usr/bin/env python3
"""Mock security data (Flavor A): fake process telemetry, mock connection logs and suspicious
SSH sessions, sent to the SOAR webhook as source "mockgen".

Used to test SOAR rules without running real attacks, e.g. from the ops host:
    mockgen.py --scenario all --dry-run         # print the events only
    mockgen.py --scenario high-cpu               # post them to the webhook
It reads the webhook settings from SSM like the real detectors do. Note: the "internet" source
uses a public address on purpose; documentation ranges (198.51.100.0/24, 203.0.113.0/24) count as
non-global, so the SOAR would treat them as internal (found in testing).
"""
import argparse
import json
import random
import sys
import urllib.request

SCENARIOS = {
    "high-cpu": lambda: [{"type": "process.suspicious_cpu", "severity": 5, "host": "ws01", "host_ip": "10.10.10.11",
                          "summary": "mock: 'kworkerds' at 97% CPU for 30s",
                          "details": {"process": "kworkerds", "cpu": 97, "mem_mb": random.randint(800, 1500), "mock": True}}],
    "miner": lambda: [{"type": "process.cryptominer", "severity": 9, "host": "ws02", "host_ip": "10.10.10.12",
                       "dst_ip": "203.0.113.50", "summary": "mock: xmrig talking to a pool on 3333",
                       "details": {"process": "xmrig", "ports": [3333], "mock": True}}],
    "connections": lambda: [{"type": "network.unusual_protocol", "severity": 5, "host": "fw01",
                             "src_ip": "10.10.10.11", "dst_ip": f"198.51.100.{random.randint(1, 254)}",
                             "summary": "mock: telnet from a workstation", "details": {"port": 23, "mock": True}}],
    "ssh": lambda: [{"type": "process.lateral_movement", "severity": 8, "host": "ws01", "host_ip": "10.10.10.11",
                     "src_ip": "10.10.10.11", "summary": "mock: SSH to 4 internal hosts in 2 min",
                     "details": {"targets": ["10.10.20.10", "10.10.10.12", "10.10.0.10", "10.10.20.11"], "mock": True}}],
    "external-scan": lambda: [{"type": "network.portscan", "severity": 6, "host": "fw01",
                               "src_ip": "93.184.215.77", "summary": "mock: internet scan of the office",
                               "details": {"ports": list(range(20, 60)), "mock": True}}],
}


def settings(region):
    import boto3
    ssm = boto3.client("ssm", region_name=region)
    get = lambda n, d=False: ssm.get_parameter(Name=f"/innovatech/soar/{n}", WithDecryption=d)["Parameter"]["Value"]
    return get("webhook-url"), get("api-id"), get("api-key", True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=[*SCENARIOS, "all"], default="all")
    parser.add_argument("--region", default="eu-central-1")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    events = [dict(source="mockgen", **e) for n in names for e in SCENARIOS[n]()]
    if args.dry_run:
        print(json.dumps(events, indent=2))
        return
    url, api_id, key = settings(args.region)
    req = urllib.request.Request(url, data=json.dumps(events).encode(), method="POST", headers={
        "Content-Type": "application/json", "x-api-key": key, "x-apigw-api-id": api_id})
    with urllib.request.urlopen(req, timeout=15) as resp:
        print(resp.status, resp.read().decode())


if __name__ == "__main__":
    sys.exit(main())
