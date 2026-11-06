#!/usr/bin/env python3
"""Process watcher (Flavor A: simulated process detection & response).

Runs on every office host. Every 10 seconds it looks at processes and their connections and
reports, through the SOAR webhook:
  process.cryptominer       known miner name, stratum URL or a connection to a mining port
  process.suspicious_cpu    an unknown process burning >85% CPU for 30 seconds
  process.lateral_movement  SSH to 3+ internal hosts, or 20+ connection attempts inside the office
  process.exfiltration      an upload command (curl -T / --data-binary @ / scp / nc) to the internet
"""
import argparse
import ipaddress
import re
import time
from collections import defaultdict, deque

import psutil

from soarclient import SoarClient, Suppressor, primary_ip

MINER_NAMES = {"xmrig", "minerd", "cpuminer", "ethminer", "t-rex", "nbminer", "xmr-stak", "kdevtmpfsi", "kinsing"}
MINING_PORTS = {3333, 4444, 5555, 7777, 14444, 45700}
CPU_ALLOW = {"apt", "apt-get", "dpkg", "unattended-upgr", "snapd", "fluent-bit", "suricata", "tshark", "dumpcap",
             "ansible-playboo", "python3", "systemd", "dnf", "cc1", "gzip"}
UPLOAD_RE = re.compile(r"(\bcurl\b.*(\s-T\s|--upload-file|--data-binary\s+@|-F\s+\S*=@))|(\bscp\b.*\S+:)|(\bnc\b.*\s\d+\s*$)|(\bwget\b.*--post-file)")
ARCHIVE_RE = re.compile(r"\b(tar|zip|7z|gzip)\b")
ARCHIVE_FILE_RE = re.compile(r"\.(tgz|tar|zip|7z|gz)\b")


def is_internal(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class ProcWatch:
    def __init__(self, client, my_ip):
        self.client = client
        self.my_ip = my_ip
        self.suppress = Suppressor(300)
        self.hot = defaultdict(int)               # pid -> consecutive high-CPU samples
        self.ssh_targets = deque()                # (time, dst ip) of outbound SSH
        self.attempts = deque()                   # (time, dst ip, dst port) of internal SYN_SENT
        self.recent_archives = deque()            # time of archive commands

    def check_process(self, proc, conns, now):
        name = (proc.info["name"] or "").lower()
        cmd = " ".join(proc.info["cmdline"] or [])[:400]
        pid = proc.info["pid"]
        remote_ports = {c.raddr.port for c in conns if c.raddr}
        remote_ips = {c.raddr.ip for c in conns if c.raddr}

        if name in MINER_NAMES or "stratum+tcp" in cmd or remote_ports & MINING_PORTS:
            if self.suppress.first(("miner", pid)):
                dst = next((c.raddr.ip for c in conns if c.raddr and c.raddr.port in MINING_PORTS), None)
                self.client.finding("process.cryptominer", 9, f"Crypto miner '{name}' (pid {pid}) on {self.client.host}",
                                    host_ip=self.my_ip, dst_ip=dst,
                                    details={"pid": pid, "process": name, "cmdline": cmd, "ports": sorted(remote_ports)[:10]})

        cpu = proc.info["cpu_percent"] or 0
        self.hot[pid] = self.hot[pid] + 1 if cpu > 85 and name not in CPU_ALLOW else 0
        if self.hot[pid] >= 3 and self.suppress.first(("cpu", pid)):
            self.client.finding("process.suspicious_cpu", 5, f"'{name}' (pid {pid}) at {cpu:.0f}% CPU for 30s",
                                host_ip=self.my_ip, details={"pid": pid, "process": name, "cmdline": cmd, "cpu": cpu})

        if ARCHIVE_RE.search(cmd):
            self.recent_archives.append(now)
        if UPLOAD_RE.search(cmd):
            external = [ip for ip in remote_ips if not is_internal(ip)]
            if external and self.suppress.first(("exfil", pid)):
                staged = any(now - t < 300 for t in self.recent_archives) or bool(ARCHIVE_FILE_RE.search(cmd))
                self.client.finding("process.exfiltration", 8 if staged else 6,
                                    f"Upload by '{name}' (pid {pid}) to {external[0]}" + (" after archiving data" if staged else ""),
                                    host_ip=self.my_ip, dst_ip=external[0],
                                    details={"pid": pid, "process": name, "cmdline": cmd, "staged": staged})

        for c in conns:
            if not c.raddr or not is_internal(c.raddr.ip) or c.raddr.ip == self.my_ip:
                continue
            if c.raddr.port == 22 and c.status in ("ESTABLISHED", "SYN_SENT"):
                self.ssh_targets.append((now, c.raddr.ip))
            if c.status == "SYN_SENT":
                self.attempts.append((now, c.raddr.ip, c.raddr.port))

    def check_spread(self, now):
        while self.ssh_targets and now - self.ssh_targets[0][0] > 120:
            self.ssh_targets.popleft()
        while self.attempts and now - self.attempts[0][0] > 60:
            self.attempts.popleft()
        ssh_hosts = {ip for _, ip in self.ssh_targets}
        tried = {(ip, port) for _, ip, port in self.attempts}
        if len(ssh_hosts) >= 3 and self.suppress.first("ssh-spread"):
            self.client.finding("process.lateral_movement", 8, f"SSH from {self.client.host} to {len(ssh_hosts)} internal hosts in 2 min",
                                host_ip=self.my_ip, src_ip=self.my_ip, details={"targets": sorted(ssh_hosts)[:20]})
        if len(tried) >= 20 and self.suppress.first("conn-spread"):
            self.client.finding("process.lateral_movement", 8, f"{len(tried)} connection attempts inside the office from {self.client.host}",
                                host_ip=self.my_ip, src_ip=self.my_ip,
                                details={"targets": sorted({ip for ip, _ in tried})[:20], "attempts": len(tried)})

    def scan_once(self):
        now = time.time()
        by_pid = defaultdict(list)
        for c in psutil.net_connections(kind="inet"):
            if c.pid:
                by_pid[c.pid].append(c)
        for proc in psutil.process_iter(["pid", "name", "cmdline", "cpu_percent"]):
            try:
                self.check_process(proc, by_pid.get(proc.info["pid"], []), now)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self.check_spread(now)
        self.client.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="eu-central-1")
    parser.add_argument("--interval", type=int, default=10)
    args = parser.parse_args()
    client = SoarClient("procwatch", args.region)
    watch = ProcWatch(client, primary_ip())
    client.write("status", message="procwatch started")
    psutil.cpu_percent()
    while True:
        watch.scan_once()
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
