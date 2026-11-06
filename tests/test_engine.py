from datetime import datetime

import pytest

import engine
from common import make_event

TIERS, RULES = engine.load_rules()


def decide(type_, severity, src_ip=None, count=1, sample=False):
    ev = make_event("mockgen", type_, severity, "test", src_ip=src_ip, sample=sample)
    return engine.evaluate(ev, count, TIERS, RULES)


@pytest.mark.parametrize("type_,sev,src,count,tier", [
    ("process.cryptominer", 9, None, 1, 3),
    ("process.lateral_movement", 8, "10.10.10.11", 1, 3),
    ("process.exfiltration", 8, None, 1, 3),
    ("network.portscan", 6, "10.10.10.11", 1, 3),      # scan from inside -> isolate
    ("network.portscan", 6, "18.192.1.1", 1, 2),       # scan from internet -> block source
    ("auth.ssh_failed", 3, "18.192.1.1", 10, 2),       # brute force threshold reached
    ("auth.ssh_failed", 3, "18.192.1.1", 9, 1),        # below threshold: notify only
    ("auth.ssh_failed", 3, "18.192.1.1", 2, 0),        # a typo is not an incident
    ("auth.ssh_failed", 3, "10.10.10.11", 5, 3),       # internal brute force
    ("ids.alert", 8, "10.10.10.11", 1, 3),
    ("ids.alert", 8, "18.192.1.1", 1, 2),
    ("ids.alert", 5, "18.192.1.1", 1, 1),
    ("network.exfil_volume", 6, "10.10.20.10", 1, 1),  # statistical signal: notify only
    ("metric.anomaly", 4, None, 1, 1),
    ("guardduty.backdoor_ec2_c_cactivity_b", 8, None, 1, 3),
    ("guardduty.recon_ec2_portprobeunprotectedport", 5, None, 1, 1),
    ("auth.ssh_login", 2, "10.10.10.11", 1, 0),
    ("soar.heartbeat", 0, None, 1, 0),
])
def test_tiers(type_, sev, src, count, tier):
    assert decide(type_, sev, src, count)[0] == tier


def test_sample_findings_never_act():
    tier, rule, _, _ = decide("guardduty.cryptocurrency_ec2_bitcointool_b_dns", 8, sample=True)
    assert (tier, rule) == (1, "R01-sample")


def test_heartbeat_runs_only_the_heartbeat_action():
    assert decide("soar.heartbeat", 0)[3] == ["heartbeat"]


def test_tier_actions_are_graduated():
    actions = [set(TIERS[t]["actions"]) for t in range(4)]
    assert actions[0] < actions[1]                      # every tier does more than the one below
    assert "block_ip" in actions[2] and "isolate_host" not in actions[2]
    assert {"isolate_host", "snapshot", "fw_quarantine"} <= actions[3]


def test_guardrail_no_block_without_internet_source():
    ev = make_event("mockgen", "network.portscan", 6, "x", src_ip="10.10.10.11")
    assert engine.apply_guardrails(2, ev, None, TIERS, 0, 5) == (1, "no internet source address to block")


def test_guardrail_protected_host_is_not_isolated():
    ev = make_event("mockgen", "process.cryptominer", 9, "x", host_ip="10.10.0.10")
    tier, note = engine.apply_guardrails(3, ev, {"name": "fw01", "protected": True}, TIERS, 0, 5)
    assert tier == 1 and "protected" in note


def test_guardrail_circuit_breaker():
    ev = make_event("mockgen", "process.cryptominer", 9, "x", host_ip="10.10.10.11")
    tier, note = engine.apply_guardrails(3, ev, {"name": "ws01", "protected": False}, TIERS, 5, 5)
    assert tier == 1 and "circuit breaker" in note


def test_every_rule_has_a_reason_and_valid_tier():
    for rule in RULES:
        assert rule["tier"] in TIERS
        assert rule.get("reason"), rule["id"]
    assert RULES[-1]["match"] == {}, "last rule must be the catch-all"


def test_guardrail_event_before_release_does_not_isolate_again():
    ev = make_event("procwatch", "process.lateral_movement", 8, "x", host_ip="10.10.10.11",
                    time_="2026-10-12T06:23:47+00:00")
    target = {"name": "ws01", "protected": False}
    released = int(datetime.fromisoformat("2026-10-12T06:26:40+00:00").timestamp())  # after the event
    tier, note = engine.apply_guardrails(3, ev, target, TIERS, 0, 5, released_at=released)
    assert tier == 1 and "released" in note
    assert engine.apply_guardrails(3, ev, target, TIERS, 0, 5, released_at=released - 600)[0] == 3
