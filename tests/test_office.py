"""The office on vSphere: SSM managed nodes (mi-...) instead of EC2 instances."""
import ipaddress
from datetime import datetime, timedelta, timezone

import pytest

import actions
import common
import normalize
import nodes


def test_netlab_wan_counts_as_outside(monkeypatch):
    monkeypatch.setattr(common, "OUTSIDE_NETS", [ipaddress.ip_network("192.168.121.0/24")])
    assert common.scope_of("192.168.121.50") == "external"
    assert common.scope_of("10.10.10.11") == "internal"
    assert actions._ipv4("192.168.121.50", "external") == "192.168.121.50"
    with pytest.raises(actions.ActionError):
        actions._ipv4("192.168.121.50", "internal")  # never quarantine an outside address


def test_firewall_found_as_managed_node(monkeypatch):
    class NoEc2:
        def describe_instances(self, **_):
            return {"Reservations": []}

    monkeypatch.setattr(actions, "ec2", NoEc2())
    monkeypatch.setattr(nodes, "online_with_tag", lambda key, value: ["mi-0fw"] if (key, value) == ("Role", "firewall") else [])
    assert actions.firewall_id() == "mi-0fw"


def test_skipped_action_is_not_reported_as_success(monkeypatch):
    monkeypatch.setattr(actions, "block_ip", lambda case, event: {"skipped": "no on-prem firewall connected"})
    monkeypatch.setitem(actions.ACTIONS, "block_ip", actions.block_ip)
    out = actions.handler({"action": "block_ip", "case": {"case_id": "c"}, "event": {}}, None)
    assert out["ok"] is False and out["skipped"] == "no on-prem firewall connected"


def test_isolate_office_vm_locks_host_and_tags_it(monkeypatch):
    sent, tagged = [], {}
    monkeypatch.setattr(nodes, "tags", lambda node: {})
    monkeypatch.setattr(nodes, "add_tags", lambda node, values: tagged.update(values))
    monkeypatch.setattr(actions, "_run", lambda node, commands, comment, **kw: sent.append((node, commands)) or {"command_id": "cmd-1"})
    out = actions.isolate_host({"case_id": "c5", "target": {"instance_id": "mi-0ws01", "site": "office"}}, {})
    node, commands = sent[0]
    assert node == "mi-0ws01" and any("policy drop" in c and "10.10.0.10" in c for c in commands)
    assert tagged == {"SoarIsolated": "c5", "SoarCase": "c5"} and out["host_firewall"] == "soar_isolation"


def test_office_snapshot_is_a_forensic_capture(monkeypatch):
    seen = {}
    monkeypatch.setattr(actions, "FORENSICS_BUCKET", "bucket")
    monkeypatch.setattr(actions, "_run", lambda node, commands, comment, **kw: seen.update(kw) or {"command_id": "cmd-2"})
    out = actions.snapshot({"case_id": "c6", "target": {"instance_id": "mi-0ws01"}}, {})
    assert out["forensics"] == "s3://bucket/soar-forensics/c6/"
    assert seen["OutputS3KeyPrefix"] == "soar-forensics/c6" and seen["wait"] is False


def _hook(**extra):
    return {"source": "procwatch", "type": "process.cryptominer", "severity": 9, "host": "ws01", **extra}


def test_webhook_keeps_occurrence_time_and_sample_flag():
    seen = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    ev = normalize.from_webhook(_hook(time=seen, sample=True))
    assert abs(datetime.fromisoformat(ev["time"]) - datetime.fromisoformat(seen)) < timedelta(milliseconds=1)
    assert ev["sample"] is True


@pytest.mark.parametrize("bad", [
    {"time": "yesterday"},
    {"time": "2026-11-04T10:00:00"},  # no time zone
    {"time": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()},
    {"time": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()},
    {"sample": "yes"},
])
def test_webhook_rejects_bad_time_or_sample(bad):
    with pytest.raises(normalize.InvalidEvent):
        normalize.from_webhook(_hook(**bad))


def test_node_lookup_never_mixes_tag_and_type_filters(monkeypatch):
    # SSM rejects a tag filter next to any other filter (found live: block_ip failed).
    seen = []

    class Pages:
        def paginate(self, Filters):
            seen.append(Filters)
            return [{"InstanceInformationList": [{"InstanceId": "mi-0fw"}, {"InstanceId": "i-0cloud"}]}]

    class Ssm:
        def get_paginator(self, name):
            return Pages()

    monkeypatch.setattr(nodes, "ssm", Ssm())
    found = nodes._nodes([{"Key": "tag:Role", "Values": ["firewall"]}])
    assert [n["InstanceId"] for n in found] == ["mi-0fw"]  # EC2 instances are not office nodes
    assert all(not f["Key"].startswith("tag:") or len(filters) == 1 for filters in seen for f in filters)
