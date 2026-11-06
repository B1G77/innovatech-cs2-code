#!/usr/bin/env python3
"""Traffic pattern analyzer (Flavor A: traffic pattern analysis), runs on the office firewall.

Two views of the same traffic:
  * packets (pyshark/tshark): connection openings and DNS queries
      network.portscan          15+ ports on one host, or one port on 15+ internal hosts, in 10 s
      network.unusual_protocol  telnet, IRC, mining ports, or non-TCP/UDP/ICMP traffic from the office
      network.dns_tunnel        long, random-looking DNS names in bulk (data hidden in DNS)
  * flows (conntrack byte counters): bytes each office host sends to the internet
      network.exfil_volume      far above that host's normal (baseline.json + running average)
Findings go to the SOAR webhook (soarclient).
"""
import argparse
import json
import math
import re
import subprocess
import threading
import time
from collections import Counter, defaultdict, deque
from pathlib import Path

from soarclient import SoarClient, Suppressor

SUSPICIOUS_PORTS = {23: "telnet", 6667: "irc", 3333: "mining", 4444: "mining", 5555: "mining", 14444: "mining", 31337: "backdoor"}
BPF = "(tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0) or udp dst port 53 or (ip and not tcp and not udp and not icmp and not esp and not igmp)"
BASELINE_FILE = Path("/var/lib/innovatech/baseline.json")
CONNTRACK_RE = re.compile(r"src=(\S+) dst=(\S+) .*?bytes=(\d+)")


def entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def is_office(ip):
    return ip.startswith("10.10.")


def is_private(ip):
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")


class PacketRules:
    """Pure detection logic, fed one packet summary at a time (unit-tested without tshark)."""

    def __init__(self, scan_threshold=15, dns_label_len=40, dns_count=10, ignore=()):
        self.scan_threshold = scan_threshold
        self.ignore = set(ignore)          # this host's own addresses: its own traffic is not a scan
        self.dns_label_len = dns_label_len
        self.dns_count = dns_count
        self.syns = defaultdict(deque)     # src -> deque[(t, dst, port)]
        self.dns = defaultdict(deque)      # (src, base domain) -> deque[(t, label)]

    def syn(self, t, src, dst, port):
        """A scan is many ports on one host (vertical) or one port on many internal hosts
        (horizontal sweep). Browsing many internet sites on 443 is neither."""
        if src in self.ignore:
            return []
        q = self.syns[src]
        q.append((t, dst, port))
        while q and t - q[0][0] > 10:
            q.popleft()
        ports_per_host = defaultdict(set)
        internal_hosts_per_port = defaultdict(set)
        for _, d, p in q:
            ports_per_host[d].add(p)
            if is_private(d):
                internal_hosts_per_port[p].add(d)
        vertical = max(ports_per_host.items(), key=lambda kv: len(kv[1]))
        horizontal = max(internal_hosts_per_port.items(), key=lambda kv: len(kv[1]), default=(None, set()))
        findings = []
        if len(vertical[1]) >= self.scan_threshold or len(horizontal[1]) >= self.scan_threshold:
            kind = "ports on one host" if len(vertical[1]) >= self.scan_threshold else "internal hosts on one port"
            findings.append(("network.portscan", 7 if is_office(src) else 6,
                             f"{src} probed {max(len(vertical[1]), len(horizontal[1]))} {kind} in 10 s",
                             {"src_ip": src, "target": vertical[0], "ports": sorted(vertical[1])[:30],
                              "sweep_port": horizontal[0], "sweep_hosts": sorted(horizontal[1])[:20]}))
        if is_office(src) and port in SUSPICIOUS_PORTS and not is_private(dst):
            sev = 6 if SUSPICIOUS_PORTS[port] == "mining" else 5
            findings.append(("network.unusual_protocol", sev, f"{src} -> {dst}:{port} ({SUSPICIOUS_PORTS[port]})",
                             {"src_ip": src, "dst_ip": dst, "port": port, "protocol": SUSPICIOUS_PORTS[port]}))
        return findings

    def dns_query(self, t, src, name):
        if src in self.ignore:  # the firewall forwarding the office's queries upstream
            return []
        labels = name.rstrip(".").split(".")
        if len(labels) < 3:
            return []
        first, base = labels[0], ".".join(labels[-2:])
        if len(first) < self.dns_label_len and not (len(first) > 25 and entropy(first) > 3.8):
            return []
        q = self.dns[(src, base)]
        q.append((t, first))
        while q and t - q[0][0] > 60:
            q.popleft()
        if len(q) >= self.dns_count:
            return [("network.dns_tunnel", 6, f"{src}: {len(q)} long random DNS names under {base} in 60 s",
                     {"src_ip": src, "domain": base, "queries": len(q), "example": first[:63]})]
        return []

    def other_protocol(self, src, dst, proto):
        if is_office(src):
            return [("network.unusual_protocol", 5, f"{src} -> {dst} IP protocol {proto}",
                     {"src_ip": src, "dst_ip": dst, "ip_proto": proto})]
        return []


class VolumeRule:
    """Per-host outbound bytes per minute vs. normal. Normal = baseline file, then a running average."""

    def __init__(self, baseline=None, factor=4.0, floor=5_000_000):
        self.factor = factor
        self.floor = floor
        self.normal = dict(baseline or {})   # host ip -> bytes per minute
        self.last = {}

    def update(self, totals, minutes=1.0):
        findings = []
        for host, total in totals.items():
            sent = max(0, total - self.last.get(host, total)) / minutes
            self.last[host] = total
            normal = self.normal.get(host, 0)
            limit = max(self.floor, normal * self.factor)
            if sent > limit:
                findings.append(("network.exfil_volume", 6,
                                 f"{host} sent {sent / 1e6:.1f} MB/min to the internet (normal {normal / 1e6:.1f})",
                                 {"src_ip": host, "bytes_per_min": int(sent), "normal": int(normal)}))
            else:  # only learn from normal minutes
                self.normal[host] = 0.9 * normal + 0.1 * sent if normal else sent
        return findings


def conntrack_totals():
    """Bytes sent by each office host to internet destinations, from the conntrack table."""
    out = subprocess.run(["conntrack", "-L", "-o", "extended"], capture_output=True, text=True).stdout
    totals = defaultdict(int)
    for line in out.splitlines():
        m = CONNTRACK_RE.search(line)
        if m and is_office(m.group(1)) and not is_private(m.group(2)):
            totals[m.group(1)] += int(m.group(3))
    return totals


def report(client, suppress, findings):
    for type_, sev, summary, details in findings:
        if suppress.first((type_, details.get("src_ip"), details.get("domain"))):
            client.finding(type_, sev, summary, src_ip=details.get("src_ip"), dst_ip=details.get("dst_ip"),
                           host_ip=details.get("src_ip") if is_office(details.get("src_ip", "")) else None,
                           details=details)


def volume_loop(client, suppress, rule, interval):
    while True:
        time.sleep(interval)
        try:
            report(client, suppress, rule.update(conntrack_totals(), interval / 60))
        except Exception as err:  # keep watching; report the problem
            client.write("status", message=f"volume check failed: {err}")


def main():
    import pyshark  # only needed on the firewall

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="ens192,ens224", help="one or more, comma-separated")
    parser.add_argument("--region", default="eu-central-1")
    args = parser.parse_args()

    baseline = json.loads(BASELINE_FILE.read_text()) if BASELINE_FILE.exists() else {}
    client = SoarClient("traffic-analyzer", args.region)
    suppress = Suppressor(300)
    own = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split()
    rules = PacketRules(dns_label_len=baseline.get("dns_label_p99", 40) + 10 if baseline else 40, ignore=own)
    volume = VolumeRule(baseline.get("bytes_per_min", {}))
    threading.Thread(target=volume_loop, args=(client, suppress, volume, 60), daemon=True).start()
    client.write("status", message=f"traffic analyzer started on {args.interface}", baseline=bool(baseline))

    capture = pyshark.LiveCapture(interface=args.interface.split(","), bpf_filter=BPF)
    for pkt in capture.sniff_continuously():
        try:
            if "IP" not in pkt:
                continue
            t, src, dst = time.time(), pkt.ip.src, pkt.ip.dst
            if "TCP" in pkt:
                findings = rules.syn(t, src, dst, int(pkt.tcp.dstport))
            elif "DNS" in pkt and hasattr(pkt.dns, "qry_name"):
                findings = rules.dns_query(t, src, str(pkt.dns.qry_name))
            elif "UDP" not in pkt:
                findings = rules.other_protocol(src, dst, pkt.ip.proto)
            else:
                findings = []
            report(client, suppress, findings)
        except AttributeError:
            continue


if __name__ == "__main__":
    main()
