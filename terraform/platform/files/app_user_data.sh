#!/bin/bash
# Cloud app server first boot: a tiny inventory API plus the CloudWatch agent.
# Log: /var/log/cloud-init-output.log
set -euxo pipefail

for i in $(seq 1 30); do dnf -y makecache && break; sleep 10; done
dnf install -y amazon-cloudwatch-agent

install -d /opt/app
cat > /opt/app/app.py <<'EOF'
"""Innovatech inventory API (demo workload)."""
import json, logging, socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(filename="/var/log/innovatech-app.log", level=logging.INFO,
                    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}')
ITEMS = [{"id": 1, "name": "laptop", "stock": 12}, {"id": 2, "name": "router", "stock": 3}]


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        elif self.path == "/items":
            self._send(200, {"server": socket.gethostname(), "items": ITEMS})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        logging.info(json.dumps({"client": self.client_address[0], "request": fmt % args}))


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
EOF

cat > /etc/systemd/system/innovatech-app.service <<'EOF'
[Unit]
Description=Innovatech inventory API
After=network-online.target
[Service]
ExecStart=/usr/bin/python3 /opt/app/app.py
Restart=always
User=nobody
[Install]
WantedBy=multi-user.target
EOF
touch /var/log/innovatech-app.log && chmod 666 /var/log/innovatech-app.log
systemctl daemon-reload
systemctl enable --now innovatech-app

cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'EOF'
{
  "agent": { "metrics_collection_interval": 60 },
  "metrics": {
    "namespace": "Innovatech/Hosts",
    "append_dimensions": { "InstanceId": "${aws:InstanceId}" },
    "metrics_collected": {
      "mem": { "measurement": ["mem_used_percent"] },
      "disk": { "measurement": ["used_percent"], "resources": ["/"] }
    }
  },
  "logs": {
    "logs_collected": {
      "files": { "collect_list": [
        { "file_path": "/var/log/innovatech-app.log", "log_group_name": "/innovatech/cloud/app", "log_stream_name": "{instance_id}" }
      ] }
    }
  }
}
EOF
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
