#!/usr/bin/env python3
"""Builds a traffic baseline from packet captures (pyshark), for the traffic analyzer.

The firewall keeps a rolling capture (tcpdump, /var/log/pcap). Run this over a quiet period:
    baseline.py /var/log/pcap/*.pcap --out /var/lib/innovatech/baseline.json --report baseline.md
It records what "normal" looks like: protocol and port mix, top talkers, DNS name lengths and
bytes per minute each office host sends to the internet. Anything far outside it is suspect.
"""
import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path


def is_office(ip):
    return ip.startswith("10.10.")


def summarise(packets):
    """packets: iterable of dicts {t, src, dst, proto, dport, length, dns}. Pure, unit-tested."""
    protos, ports, talkers = Counter(), Counter(), Counter()
    dns_lengths = []
    per_minute = defaultdict(lambda: defaultdict(int))
    first = last = None
    for p in packets:
        first = p["t"] if first is None else first
        last = p["t"]
        protos[p["proto"]] += 1
        if p.get("dport"):
            ports[p["dport"]] += 1
        talkers[p["src"]] += p["length"]
        if p.get("dns"):
            dns_lengths.append(len(p["dns"].split(".")[0]))
        if is_office(p["src"]) and not p["dst"].startswith("10."):
            per_minute[p["src"]][int(p["t"] // 60)] += p["length"]
    duration_min = max(1.0, ((last or 0) - (first or 0)) / 60)
    dns_lengths.sort()
    p99 = dns_lengths[int(len(dns_lengths) * 0.99) - 1] if dns_lengths else 30
    return {
        "duration_minutes": round(duration_min, 1),
        "packets": sum(protos.values()),
        "protocols": dict(protos.most_common()),
        "top_ports": dict(ports.most_common(15)),
        "top_talkers_bytes": dict(talkers.most_common(10)),
        "dns_queries": len(dns_lengths),
        "dns_label_p99": p99,
        "bytes_per_min": {h: int(sum(m.values()) / duration_min) for h, m in per_minute.items()},
        "bytes_per_min_stdev": {h: int(statistics.pstdev(m.values())) if len(m) > 1 else 0 for h, m in per_minute.items()},
    }


def read_pcap(path):
    import pyshark
    cap = pyshark.FileCapture(str(path), keep_packets=False)
    try:
        for pkt in cap:
            if "IP" not in pkt:
                continue
            layer = pkt.transport_layer
            yield {
                "t": float(pkt.sniff_timestamp), "src": pkt.ip.src, "dst": pkt.ip.dst,
                "proto": layer or pkt.highest_layer, "length": int(pkt.length),
                "dport": int(pkt[layer].dstport) if layer in ("TCP", "UDP") else None,
                "dns": str(pkt.dns.qry_name) if "DNS" in pkt and hasattr(pkt.dns, "qry_name") else None,
            }
    except pyshark.capture.capture.TSharkCrashException as err:
        # The newest ring file is still being written and ends mid-packet: keep what was read.
        print(f"warning: {path}: {str(err).splitlines()[0]}", file=sys.stderr)
    finally:
        try:
            cap.close()
        except Exception:
            pass


def markdown(b):
    rows = "\n".join(f"| {k} | {v} |" for k, v in b["protocols"].items())
    ports = "\n".join(f"| {k} | {v} |" for k, v in b["top_ports"].items())
    hosts = "\n".join(f"| {k} | {v / 1e3:.1f} kB/min |" for k, v in b["bytes_per_min"].items())
    return (f"# Traffic baseline\n\n{b['packets']} packets over {b['duration_minutes']} minutes.\n\n"
            f"## Protocols\n\n| protocol | packets |\n|---|---|\n{rows}\n\n"
            f"## Top destination ports\n\n| port | packets |\n|---|---|\n{ports}\n\n"
            f"## Office hosts to internet\n\n| host | normal |\n|---|---|\n{hosts}\n\n"
            f"DNS queries: {b['dns_queries']}, 99th percentile first-label length: {b['dns_label_p99']} characters.\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcaps", nargs="+")
    parser.add_argument("--out", default="/var/lib/innovatech/baseline.json")
    parser.add_argument("--report")
    args = parser.parse_args()
    packets = (p for f in args.pcaps for p in read_pcap(f))
    baseline = summarise(packets)
    Path(args.out).write_text(json.dumps(baseline, indent=2))
    if args.report:
        Path(args.report).write_text(markdown(baseline))
    print(json.dumps(baseline, indent=2))


if __name__ == "__main__":
    main()
