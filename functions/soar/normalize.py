"""Turns every input format into the normalised event shape (common.make_event).

Inputs: Suricata eve.json alerts, SSH lines from auth.log, detector webhooks, GuardDuty
findings, CloudWatch anomaly alarms and the SOAR heartbeat. Everything here is untrusted
input, so it is validated before it is used.
"""
import json
import re
from datetime import datetime, timedelta, timezone

from common import SOURCES, TYPE_RE, make_event, parse_ip, scope_of

SURICATA_SEVERITY = {1: 8, 2: 5, 3: 3}  # Suricata: 1 = high ... 3 = low

AUTH_PATTERNS = [
    (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)"), "auth.ssh_failed", 3),
    (re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F.:]+)"), "auth.ssh_failed", 3),
    (re.compile(r"Connection closed by authenticating user (?P<user>\S+) (?P<ip>[0-9a-fA-F.:]+)"), "auth.ssh_failed", 3),
    (re.compile(r"Accepted (?:publickey|password) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)"), "auth.ssh_login", 2),
]


class InvalidEvent(ValueError):
    """Raised for webhook input that does not match the contract."""


def _occurred(value):
    """When the detector saw it: needed by the 'event before an analyst release' guard rail,
    because a detector queues findings while its host is offline or isolated. Must be an
    ISO 8601 time with a zone, not in the future, at most a day old."""
    if value is None:
        return None
    try:
        when = datetime.fromisoformat(str(value))
    except ValueError as err:
        raise InvalidEvent("time must be ISO 8601") from err
    if when.tzinfo is None:
        raise InvalidEvent("time needs a time zone")
    now = datetime.now(timezone.utc)
    if not now - timedelta(days=1) <= when <= now + timedelta(minutes=2):
        raise InvalidEvent("time is not within the last day")
    return when.isoformat(timespec="milliseconds")


def _internal_side(src, dst):
    """The office/cloud address involved in a flow: that is the host we may have to act on."""
    for ip in (parse_ip(src), parse_ip(dst)):
        if scope_of(ip) == "internal":
            return ip
    return None


def from_suricata(message, host):
    try:
        eve = json.loads(message)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(eve, dict) or eve.get("event_type") != "alert":
        return None
    alert = eve.get("alert") or {}
    severity = SURICATA_SEVERITY.get(alert.get("severity"), 3)
    signature = str(alert.get("signature", "unknown"))
    return make_event(
        "suricata", "ids.alert", severity, f"IDS: {signature}",
        host=host, src_ip=eve.get("src_ip"), dst_ip=eve.get("dest_ip"),
        host_ip=_internal_side(eve.get("src_ip"), eve.get("dest_ip")),
        details={"signature": signature, "signature_id": alert.get("signature_id"),
                 "category": alert.get("category"), "proto": eve.get("proto"), "dest_port": eve.get("dest_port"),
                 "community_id": eve.get("community_id")},
    )


def from_auth(message, host, host_ip=None):
    for pattern, type_, severity in AUTH_PATTERNS:
        m = pattern.search(message or "")
        if m:
            user = m.group("user") or "?"
            return make_event(
                "auth", type_, severity, f"SSH {type_.split('_')[-1]} for '{user}' from {m.group('ip')} on {host}",
                host=host, host_ip=host_ip, src_ip=m.group("ip"), details={"user": user[:64], "line": message[:500]},
            )
    return None


def from_webhook(body):
    """Validates a detector alert (POST /events). Raises InvalidEvent when it is not acceptable."""
    if not isinstance(body, dict):
        raise InvalidEvent("body must be a JSON object")
    source, type_ = body.get("source"), body.get("type")
    if source not in SOURCES - {"guardduty", "cloudwatch", "heartbeat", "suricata", "auth"}:
        raise InvalidEvent("unknown source")
    if not isinstance(type_, str) or not TYPE_RE.match(type_):
        raise InvalidEvent("type must look like 'network.portscan'")
    severity = body.get("severity")
    if not isinstance(severity, int) or isinstance(severity, bool) or not 0 <= severity <= 10:
        raise InvalidEvent("severity must be an integer 0-10")
    for field in ("src_ip", "dst_ip", "host_ip"):
        if body.get(field) is not None and parse_ip(body[field]) is None:
            raise InvalidEvent(f"{field} is not an IP address")
    details = body.get("details") or {}
    if not isinstance(details, dict) or len(json.dumps(details)) > 8000:
        raise InvalidEvent("details must be an object under 8 KB")
    host = body.get("host")
    if host is not None and (not isinstance(host, str) or not re.match(r"^[A-Za-z0-9.-]{1,64}$", host)):
        raise InvalidEvent("host must be a hostname")
    sample = body.get("sample", False)
    if not isinstance(sample, bool):
        raise InvalidEvent("sample must be true or false")
    return make_event(
        source, type_, severity, str(body.get("summary", type_)),
        host=host, host_ip=body.get("host_ip"), src_ip=body.get("src_ip"), dst_ip=body.get("dst_ip"),
        time_=_occurred(body.get("time")), sample=sample, details=details,
    )


def from_guardduty(detail):
    resource = detail.get("resource") or {}
    instance = resource.get("instanceDetails") or {}
    nics = instance.get("networkInterfaces") or [{}]
    action = (detail.get("service") or {}).get("action") or {}
    remote = None
    for key in ("networkConnectionAction", "portProbeAction", "awsApiCallAction", "dnsRequestAction"):
        part = action.get(key) or {}
        details = part.get("remoteIpDetails") or (part.get("portProbeDetails") or [{}])[0].get("remoteIpDetails") or {}
        if details.get("ipAddressV4"):
            remote = details["ipAddressV4"]
            break
    finding_type = str(detail.get("type", "unknown"))
    sample = bool(((detail.get("service") or {}).get("additionalInfo") or {}).get("sample"))
    return make_event(
        "guardduty", "guardduty." + re.sub(r"[^a-z0-9_]+", "_", finding_type.lower()).strip("_")[:50],
        round(float(detail.get("severity", 0))), f"GuardDuty: {finding_type}",
        instance_id=instance.get("instanceId"), host_ip=nics[0].get("privateIpAddress"), src_ip=remote,
        sample=sample, details={"finding_id": detail.get("id"), "finding_type": finding_type,
                                "title": detail.get("title")},
    )


def from_alarm(detail):
    if (detail.get("state") or {}).get("value") != "ALARM":
        return None
    name = str(detail.get("alarmName", "alarm"))
    return make_event("cloudwatch", "metric.anomaly", 4, f"Anomaly alarm: {name}",
                      details={"alarm": name, "reason": (detail.get("state") or {}).get("reason", "")[:500]})


def heartbeat():
    return make_event("heartbeat", "soar.heartbeat", 0, "SOAR heartbeat")
