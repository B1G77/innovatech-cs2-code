import json

import pytest

import normalize
from common import scope_of


def test_suricata_alert_from_internet_is_external_with_internal_host():
    line = json.dumps({"event_type": "alert", "src_ip": "18.192.1.1", "dest_ip": "10.10.0.10",
                       "proto": "TCP", "dest_port": 22,
                       "alert": {"signature": "INNOVATECH SCAN possible SYN port scan", "signature_id": 9000001,
                                 "severity": 2, "category": "Attempted Information Leak"}})
    ev = normalize.from_suricata(line, "fw01")
    assert ev["type"] == "ids.alert"
    assert ev["severity"] == 5
    assert ev["scope"] == "external"
    assert ev["host_ip"] == "10.10.0.10"
    assert ev["details"]["signature_id"] == 9000001


def test_suricata_non_alert_lines_are_ignored():
    assert normalize.from_suricata(json.dumps({"event_type": "flow"}), "fw01") is None
    assert normalize.from_suricata("not json", "fw01") is None


@pytest.mark.parametrize("line,type_,ip", [
    ("Oct 12 10:00:01 fw01 sshd[1]: Invalid user admin from 18.192.1.1 port 4242", "auth.ssh_failed", "18.192.1.1"),
    ("sshd[2]: Failed password for root from 10.10.10.11 port 22 ssh2", "auth.ssh_failed", "10.10.10.11"),
    ("sshd[3]: Connection closed by authenticating user ubuntu 10.10.10.11 port 5 [preauth]", "auth.ssh_failed",
     "10.10.10.11"),
    ("sshd[4]: Accepted publickey for ubuntu from 10.10.10.11 port 5 ssh2", "auth.ssh_login", "10.10.10.11"),
])
def test_auth_lines(line, type_, ip):
    ev = normalize.from_auth(line, "srv01")
    assert ev["type"] == type_
    assert ev["src_ip"] == ip


def test_auth_unrelated_line():
    assert normalize.from_auth("CRON[5]: pam_unix(cron:session): session opened", "srv01") is None


def good_webhook(**overrides):
    body = {"source": "traffic-analyzer", "type": "network.portscan", "severity": 7, "host": "fw01",
            "src_ip": "10.10.10.11", "dst_ip": "10.10.20.10", "summary": "scan", "details": {"ports": 40}}
    body.update(overrides)
    return body


def test_webhook_valid():
    ev = normalize.from_webhook(good_webhook())
    assert ev["scope"] == "internal" and ev["severity"] == 7


@pytest.mark.parametrize("bad", [
    {"source": "guardduty"},                 # only detectors may use the webhook
    {"type": "PortScan"},                    # type format
    {"type": "network.portscan; rm -rf /"},
    {"severity": 11},
    {"severity": True},
    {"severity": "7"},
    {"src_ip": "10.10.10.11; reboot"},
    {"host": "fw01 && id"},
    {"details": {"x": "y" * 9000}},
])
def test_webhook_rejects_bad_input(bad):
    with pytest.raises(normalize.InvalidEvent):
        normalize.from_webhook(good_webhook(**bad))


def test_guardduty_sample_is_flagged():
    detail = {"type": "CryptoCurrency:EC2/BitcoinTool.B!DNS", "severity": 8.0, "id": "abc",
              "resource": {"instanceDetails": {"instanceId": "i-123",
                                               "networkInterfaces": [{"privateIpAddress": "10.40.10.5"}]}},
              "service": {"additionalInfo": {"sample": True}}}
    ev = normalize.from_guardduty(detail)
    assert ev["type"] == "guardduty.cryptocurrency_ec2_bitcointool_b_dns"
    assert ev["sample"] is True and ev["severity"] == 8 and ev["instance_id"] == "i-123"


def test_alarm_only_on_alarm_state():
    assert normalize.from_alarm({"alarmName": "x", "state": {"value": "OK"}}) is None
    assert normalize.from_alarm({"alarmName": "x", "state": {"value": "ALARM"}})["type"] == "metric.anomaly"


def test_scope():
    assert scope_of("10.10.10.11") == "internal"
    assert scope_of("8.8.8.8") == "external"
    assert scope_of(None) == "unknown"
