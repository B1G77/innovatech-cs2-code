#!/bin/bash
# Simulated internet attacker: the Kali VM on the netlab WAN (192.168.121.0/24, outside the
# office). It also plays the "mining pool" and the "exfiltration drop" that infected office
# hosts connect to. terraform/office runs it once as root; "scenarios.sh prepare" runs it again.
set -eux
# No apt here: the 2024.1 template has an outdated archive key and a partial upgrade of the
# rolling release breaks openssl (found in testing). It already ships nmap, hydra and nc.

# Fake stratum pool on 3333 and an upload sink on 8080. A threaded Python listener drains
# every connection (nc serves one at a time and stalls a second upload - found in testing).
cat > /usr/local/bin/lab-sink <<'EOF'
#!/usr/bin/env python3
import socketserver, sys
class Drain(socketserver.BaseRequestHandler):
    def handle(self):
        while self.request.recv(65536):
            pass
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
Server(("0.0.0.0", int(sys.argv[1])), Drain).serve_forever()
EOF
chmod 755 /usr/local/bin/lab-sink

for svc in "fake-pool 3333 Fake mining pool" "exfil-sink 8080 Exfiltration drop"; do
  set -- $svc
  cat > /etc/systemd/system/$1.service <<EOF
[Unit]
Description=${*:3} (lab only)
[Service]
ExecStart=/usr/local/bin/lab-sink $2
Restart=always
[Install]
WantedBy=multi-user.target
EOF
done

systemctl daemon-reload
systemctl enable --now fake-pool exfil-sink
