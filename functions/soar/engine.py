"""The rule engine: picks a response tier for a normalised event. Pure logic, no AWS calls.

decide.py feeds it the event plus context (how often this happened recently, whether the
target host is protected) and adds the safety rails.
"""
import json
from datetime import datetime
from pathlib import Path

RULES_FILE = Path(__file__).with_name("rules.json")


def load_rules(path=RULES_FILE):
    with open(path) as f:
        data = json.load(f)
    tiers = {int(k): v for k, v in data["tiers"].items()}
    return tiers, data["rules"]


def matches(cond, event, count):
    """True when every condition in the rule holds for this event."""
    if "type" in cond and event["type"] != cond["type"]:
        return False
    if "type_prefix" in cond and not event["type"].startswith(cond["type_prefix"]):
        return False
    if "type_in" in cond and event["type"] not in cond["type_in"]:
        return False
    if "scope" in cond and event.get("scope") != cond["scope"]:
        return False
    if "sample" in cond and bool(event.get("sample")) != cond["sample"]:
        return False
    if "min_severity" in cond and event["severity"] < cond["min_severity"]:
        return False
    if "min_count" in cond and count < cond["min_count"]:
        return False
    return True


def evaluate(event, count, tiers, rules):
    """Returns (tier, rule_id, reason, actions) for the first matching rule."""
    for rule in rules:
        if matches(rule.get("match", {}), event, count):
            tier = rule["tier"]
            actions = rule.get("actions", tiers[tier]["actions"])
            return tier, rule["id"], rule.get("reason", ""), list(actions)
    return 0, "none", "no rule matched", list(tiers[0]["actions"])


def apply_guardrails(tier, event, target, tiers, isolations_last_hour, max_isolations, released_at=None):
    """Downgrades a decision that would be unsafe or impossible. Returns (tier, note or None).

    * Tier 2 blocks a source address: it needs an internet source (never block our own ranges).
    * Tier 3 isolates a host: it needs a known host that is not protected (firewall, ops host),
      and a circuit breaker stops a flood of events from isolating the whole office. Events
      older than the host's last release by an analyst do not isolate it again.
    """
    if tier == 2 and event.get("scope") != "external":
        return 1, "no internet source address to block"
    if tier == 3:
        if not target:
            return 1, "target host not found"
        if target.get("protected"):
            return 1, f"{target.get('name', 'host')} is protected from automatic isolation"
        if isolations_last_hour >= max_isolations:
            return 1, f"circuit breaker: {isolations_last_hour} isolations in the last hour"
        if released_at and event_epoch(event) and event_epoch(event) < released_at:
            return 1, "event happened before an analyst released this host"
    return tier, None


def event_epoch(event):
    try:
        return datetime.fromisoformat(event["time"]).timestamp()
    except (KeyError, ValueError, TypeError):
        return None


def tier_name(tier, tiers):
    return tiers[tier]["name"]
