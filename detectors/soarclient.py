"""Sends detector findings to the SOAR webhook and to the local detector log.

Settings come from SSM (written by terraform/soar): webhook URL, API id, API key. When the
SOAR is unreachable (VPN down), findings wait in a bounded queue and are re-sent later; the
local log line is written either way, so Fluent Bit still ships it once the link is back.
"""
import json
import logging
import socket
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone

LOG_FILE = "/var/log/innovatech/detectors.log"


def primary_ip():
    """The address this host uses to reach the network (no packets are sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("10.30.10.53", 53))
        return s.getsockname()[0]


class SoarClient:
    def __init__(self, source, region, log_file=LOG_FILE, ssm=None):
        self.source = source
        self.region = region
        self.host = socket.gethostname()
        self.pending = deque(maxlen=500)
        self.settings = None
        self._ssm = ssm
        self._own_client = ssm is None
        self.log = logging.getLogger(source)
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.log.addHandler(handler)
        self.log.setLevel(logging.INFO)
        # Load the webhook settings now, not at the first finding: by then the SOAR may already
        # have isolated this host (found in testing: an isolated host could not fetch them).
        self._load_settings()

    def _load_settings(self):
        if self.settings:
            return True
        try:
            if self._ssm is None:
                import boto3  # imported lazily so unit tests need no AWS
                self._ssm = boto3.client("ssm", region_name=self.region)
            get = lambda n, d=False: self._ssm.get_parameter(Name=f"/innovatech/soar/{n}", WithDecryption=d)["Parameter"]["Value"]
            self.settings = {"url": get("webhook-url"), "api_id": get("api-id"), "key": get("api-key", True)}
            return True
        except Exception as err:  # SOAR not deployed yet, or no network: try again later
            self.write("status", message=f"webhook settings unavailable: {err}")
            # Build a new client next time: on an SSM hybrid node the agent rotates the credentials
            # file hourly, and a kept client holds expired credentials forever (found 5 November).
            if self._own_client:
                self._ssm = None
            return False

    def write(self, kind, **fields):
        self.log.info(json.dumps({"@timestamp": datetime.now(timezone.utc).isoformat(), "kind": kind,
                                  "source": self.source, "host": self.host, **fields}, default=str))

    def finding(self, type_, severity, summary, **fields):
        """Record one finding locally and queue it for the SOAR."""
        event = {"source": self.source, "type": type_, "severity": int(severity), "host": self.host,
                 "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                 "summary": summary[:300], **{k: v for k, v in fields.items() if v is not None}}
        self.write("finding", **event)
        self.pending.append(event)
        self.flush()

    def flush(self):
        if not self.pending or not self._load_settings():
            return
        batch = list(self.pending)[:25]
        req = urllib.request.Request(self.settings["url"], data=json.dumps(batch).encode(), method="POST", headers={
            "Content-Type": "application/json", "x-api-key": self.settings["key"],
            "x-apigw-api-id": self.settings["api_id"]})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 202:
                    for _ in batch:
                        self.pending.popleft()
        except urllib.error.HTTPError as err:
            if err.code == 400:  # rejected by validation: retrying will not help
                self.write("status", message=f"SOAR rejected batch: {err.read()[:300]!r}")
                for _ in batch:
                    self.pending.popleft()
            else:
                self.write("status", message=f"SOAR unavailable (HTTP {err.code}); {len(self.pending)} queued")
        except (urllib.error.URLError, OSError) as err:
            self.write("status", message=f"SOAR unreachable ({err}); {len(self.pending)} queued")


class Suppressor:
    """Report the same thing at most once per window (detectors re-check every few seconds)."""

    def __init__(self, window=300):
        self.window = window
        self.seen = {}

    def first(self, key, now=None):
        now = time.time() if now is None else now
        if now - self.seen.get(key, float("-inf")) < self.window:
            return False
        self.seen[key] = now
        return True
