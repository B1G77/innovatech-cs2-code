"""Shared helpers: the normalised event shape, IP checks, structured logs and metrics."""
import ipaddress
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone

METRIC_NAMESPACE = "Innovatech/SOAR"
TYPE_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+){1,3}$")
SOURCES = {"suricata", "auth", "traffic-analyzer", "procwatch", "mockgen", "guardduty", "cloudwatch", "heartbeat"}
# Private ranges outside the office firewall that stand in for the internet (the netlab WAN).
OUTSIDE_NETS = [ipaddress.ip_network(c) for c in json.loads(os.environ.get("OUTSIDE_CIDRS", "[]"))]


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def parse_ip(value):
    """Returns the address as a string, or None when it is not a valid IPv4/IPv6 address."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def is_outside(addr):
    """True for an internet address, or one on the lab segment that stands in for the internet."""
    return addr.is_global or any(addr in net for net in OUTSIDE_NETS)


def scope_of(ip):
    """internal = our private ranges, external = internet address (or the lab's stand-in)."""
    if ip is None:
        return "unknown"
    addr = ipaddress.ip_address(ip)
    if is_outside(addr):
        return "external"
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return "internal"
    return "unknown"


def make_event(source, type_, severity, summary, *, host=None, host_ip=None, instance_id=None,
               src_ip=None, dst_ip=None, time_=None, sample=False, details=None):
    """Builds one normalised security event. Every detector ends up in this shape."""
    src = parse_ip(src_ip)
    return {
        "id": str(uuid.uuid4()),
        "time": time_ or now_iso(),
        "source": source,
        "type": type_,
        "severity": max(0, min(10, int(severity))),
        "host": host,
        "host_ip": parse_ip(host_ip),
        "instance_id": instance_id,
        "src_ip": src,
        "dst_ip": parse_ip(dst_ip),
        "scope": scope_of(src),
        "summary": str(summary)[:300],
        "sample": bool(sample),
        "details": details or {},
    }


def log(log_type, **fields):
    """One JSON line on stdout. CloudWatch keeps it; the indexer copies it to OpenSearch."""
    print(json.dumps({"log_type": log_type, "@timestamp": now_iso(), **fields}, default=str))


def metric(name, value=1, unit="Count", dimensions=None):
    """CloudWatch Embedded Metric Format: a log line that CloudWatch turns into a metric.

    Each metric is published with and without its dimension, so dashboards get both the
    total and the per-value breakdown.
    """
    dims = dimensions or {}
    dim_sets = [list(dims.keys()), []] if dims else [[]]
    print(json.dumps({
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": METRIC_NAMESPACE,
                "Dimensions": dim_sets,
                "Metrics": [{"Name": name, "Unit": unit}],
            }],
        },
        name: value,
        **dims,
    }))
