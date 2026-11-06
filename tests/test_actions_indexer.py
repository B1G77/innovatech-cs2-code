import base64
import gzip
import json

import pytest

import actions
import indexer


@pytest.mark.parametrize("value,want", [("8.8.8.8", "external"), ("10.10.10.11", "internal")])
def test_ipv4_accepts(value, want):
    assert actions._ipv4(value, want) == value


@pytest.mark.parametrize("value,want", [
    ("10.10.10.11", "external"),   # never block our own range
    ("8.8.8.8", "internal"),
    ("8.8.8.8; reboot", "external"),
    ("'{ 1.1.1.1 }'", "external"),
    (None, "external"),
])
def test_ipv4_rejects(value, want):
    with pytest.raises(actions.ActionError):
        actions._ipv4(value, want)


def test_block_ip_respects_never_block(monkeypatch):
    monkeypatch.setattr(actions, "NEVER_BLOCK", {"3.120.1.1"})
    with pytest.raises(actions.ActionError, match="never-block"):
        actions.block_ip({"case_id": "c"}, {"src_ip": "3.120.1.1"})


def test_isolate_refuses_protected_target():
    with pytest.raises(actions.ActionError):
        actions.isolate_host({"case_id": "c", "target": {"instance_id": "i-1", "protected": True}}, {})


def test_unknown_action_is_rejected():
    with pytest.raises(actions.ActionError):
        actions.handler({"action": "rm", "case": {"case_id": "c"}, "event": {}}, None)


@pytest.mark.parametrize("group,expected", [
    ("/innovatech/onprem/suricata", "logs-onprem-suricata-2026.10"),
    ("/aws/lambda/innovatech-soar-act", "logs-soar-act-2026.10"),
    ("/innovatech/vpc-flow-logs", "logs-vpc-flow-logs-2026.10"),
])
def test_index_names(group, expected):
    assert indexer.index_name(group, 1791806400000) == expected


def test_docs_parse_json_and_plain_lines():
    payload = {"logGroup": "/innovatech/onprem/auth", "logStream": "srv01", "logEvents": [
        {"id": "1", "timestamp": 1791806400000, "message": "sshd: Invalid user x from 1.2.3.4"},
        {"id": "2", "timestamp": 1791806400000, "message": json.dumps({"log_type": "case", "tier": 3})},
    ]}
    docs = list(indexer.to_docs(payload))
    assert docs[0][2]["message"].startswith("sshd") and docs[0][2]["host"] == "srv01"
    assert docs[1][2]["tier"] == 3
    body = indexer.bulk_body(docs).decode().splitlines()
    assert len(body) == 4 and json.loads(body[0])["index"]["_id"] == "1"


def test_ingest_logs_payload_roundtrip(monkeypatch):
    import ingest
    sent = []
    monkeypatch.setattr(ingest, "publish", lambda evs: sent.extend(evs))
    payload = {"logGroup": "/innovatech/onprem/auth", "logStream": "fw01", "logEvents": [
        {"id": "1", "timestamp": 0, "message": "sshd[1]: Invalid user admin from 18.192.1.1 port 1"},
        {"id": "2", "timestamp": 0, "message": "systemd: started"}]}
    data = base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()
    ingest.handler({"awslogs": {"data": data}}, None)
    assert [e["type"] for e in sent] == ["auth.ssh_failed"]


def test_ingest_webhook_bad_request(monkeypatch):
    import ingest
    monkeypatch.setattr(ingest, "publish", lambda evs: None)
    resp = ingest.handler({"requestContext": {}, "body": json.dumps({"source": "x"})}, None)
    assert resp["statusCode"] == 400


def test_snapshot_reuses_recent_forensic_copy(monkeypatch):
    from datetime import datetime, timezone

    class FakeEc2:
        created = 0

        def describe_volumes(self, **_):
            return {"Volumes": [{"VolumeId": "vol-1"}]}

        def describe_snapshots(self, **_):
            return {"Snapshots": [{"SnapshotId": "snap-recent", "StartTime": datetime.now(timezone.utc)}]}

        def create_snapshot(self, **_):
            FakeEc2.created += 1
            return {"SnapshotId": "snap-new"}

    monkeypatch.setattr(actions, "ec2", FakeEc2())
    out = actions.snapshot({"case_id": "c2", "target": {"instance_id": "i-1"}}, {})
    assert out == {"snapshots": ["snap-recent"]} and FakeEc2.created == 0


def test_firewall_found_by_tag_not_stale_id(monkeypatch):
    class FakeEc2:
        def describe_instances(self, **_):
            return {"Reservations": [{"Instances": [{"InstanceId": "i-newfw"}]}]}

    monkeypatch.setattr(actions, "ec2", FakeEc2())
    monkeypatch.setattr(actions, "FW_INSTANCE_ID", "i-oldfw")
    assert actions.firewall_id() == "i-newfw"


def test_firewall_actions_skip_when_no_office_firewall(monkeypatch):
    class FakeEc2:
        def describe_instances(self, **_):
            return {"Reservations": []}

    class FailSsm:
        def send_command(self, **_):
            raise AssertionError("no command may be sent without a firewall")

    monkeypatch.setattr(actions, "ec2", FakeEc2())
    monkeypatch.setattr(actions, "ssm", FailSsm())
    monkeypatch.setattr(actions, "FW_INSTANCE_ID", "")
    out = actions.block_ip({"case_id": "c3"}, {"src_ip": "1.1.1.1"})
    assert out["skipped"] == "no on-prem firewall connected"
    assert "blocked" not in out  # a skipped step must not claim it acted


def test_isolate_detaches_from_auto_scaling_group(monkeypatch):
    """An Auto Scaling group terminates an isolated (unhealthy) instance, which destroys the
    evidence (found in testing on 28 October). Isolation must detach it first."""
    calls = {}

    class FakeEc2:
        def describe_instances(self, **_):
            return {"Reservations": [{"Instances": [{"Tags": [], "NetworkInterfaces": [
                {"NetworkInterfaceId": "eni-1", "Groups": [{"GroupId": "sg-app"}]}]}]}]}

        def create_tags(self, **_):
            pass

        def modify_network_interface_attribute(self, **kw):
            calls["sg"] = kw["Groups"]

    class FakeAutoscaling:
        def describe_auto_scaling_instances(self, InstanceIds):
            return {"AutoScalingInstances": [{"InstanceId": InstanceIds[0], "AutoScalingGroupName": "innovatech-app"}]}

        def detach_instances(self, **kw):
            calls["detach"] = kw

    monkeypatch.setattr(actions, "ec2", FakeEc2())
    monkeypatch.setattr(actions, "autoscaling", FakeAutoscaling(), raising=False)
    monkeypatch.setattr(actions, "QUARANTINE_SGS", {"vpc-w": "sg-q"})
    out = actions.isolate_host({"case_id": "c4", "target": {"instance_id": "i-app", "vpc_id": "vpc-w"}}, {})
    assert calls["sg"] == ["sg-q"]
    assert calls["detach"] == {"InstanceIds": ["i-app"], "AutoScalingGroupName": "innovatech-app",
                               "ShouldDecrementDesiredCapacity": False}
    assert out["detached_from"] == "innovatech-app"
