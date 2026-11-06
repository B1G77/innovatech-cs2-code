#!/usr/bin/env python3
"""Generates the Grafana dashboard JSON (terraform/platform/files/grafana_dashboard.json).

Writing the panels in Python keeps the dashboard reviewable; run this after changing a panel.
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "terraform/platform/files/grafana_dashboard.json"
CW = {"type": "cloudwatch", "uid": "cloudwatch"}
OS = {"type": "grafana-opensearch-datasource", "uid": "opensearch"}

panels = []
_next_id = iter(range(1, 100))


def place(w, h):
    """Simple left-to-right layout on a 24-column grid."""
    x, y = place.x, place.y
    if x + w > 24:
        x, y = 0, y + place.row_h
        place.row_h = 0
    place.x, place.y = x + w, y
    place.row_h = max(place.row_h, h)
    return {"x": x, "y": y, "w": w, "h": h}


place.x, place.y, place.row_h = 0, 0, 0


def row(title):
    place.x, place.y = 0, place.y + place.row_h
    place.row_h = 0
    panels.append({"type": "row", "title": title, "id": next(_next_id),
                   "gridPos": {"x": 0, "y": place.y, "w": 24, "h": 1}, "collapsed": False})
    place.y += 1


def cw_target(ref, namespace, metric, stat="Sum", dims=None, label=None, period="60"):
    return {
        "refId": ref, "datasource": CW, "region": "default", "queryMode": "Metrics",
        "metricQueryType": 0, "metricEditorMode": 0, "namespace": namespace, "metricName": metric,
        "dimensions": dims or {}, "matchExact": not dims, "statistic": stat, "period": period,
        "label": label or "", "id": "", "expression": "",
    }


def cw_search(ref, expression, label=""):
    return {"refId": ref, "datasource": CW, "region": "default", "queryMode": "Metrics",
            "metricQueryType": 0, "metricEditorMode": 1, "expression": expression, "id": "",
            "label": label, "period": "300"}


def timeseries(title, targets, w=8, h=7, unit="short", bars=False, description=""):
    panels.append({
        "type": "timeseries", "title": title, "id": next(_next_id), "datasource": targets[0]["datasource"],
        "description": description, "gridPos": place(w, h), "targets": targets,
        "fieldConfig": {"defaults": {"unit": unit, "custom": {
            "drawStyle": "bars" if bars else "line", "fillOpacity": 30 if bars else 10, "lineWidth": 2}},
            "overrides": []},
        "options": {"legend": {"displayMode": "list", "placement": "bottom"}, "tooltip": {"mode": "multi"}},
    })


def stat(title, target, w=4, h=4, unit="short", thresholds=None, description="", calc="sum"):
    panels.append({
        "type": "stat", "title": title, "id": next(_next_id), "datasource": target["datasource"],
        "description": description, "gridPos": place(w, h), "targets": [target],
        "fieldConfig": {"defaults": {"unit": unit, "thresholds": {"mode": "absolute", "steps": thresholds or [
            {"color": "green", "value": None}]}}, "overrides": []},
        "options": {"reduceOptions": {"calcs": [calc]}, "colorMode": "background"},
    })


def os_target(ref, query, metrics, buckets):
    return {"refId": ref, "datasource": OS, "query": query, "queryType": "lucene",
            "metrics": metrics, "bucketAggs": buckets, "timeField": "@timestamp"}


# ---------------- SOAR (REQ-NCA-P2-09) ----------------
row("SOAR - is the response system healthy?")
red_if_any = [{"color": "green", "value": None}, {"color": "red", "value": 1}]
stat("Events processed", cw_target("A", "Innovatech/SOAR", "EventsProcessed"), unit="short")
stat("Actions succeeded", cw_target("A", "Innovatech/SOAR", "ActionsSucceeded"))
stat("Actions failed", cw_target("A", "Innovatech/SOAR", "ActionsFailed"), thresholds=red_if_any,
     description="Any failed automated action needs a human: check the Step Functions execution.")
stat("Playbook runs failed", cw_target("A", "AWS/States", "ExecutionsFailed", dims={"StateMachineArn": "*"}),
     thresholds=red_if_any)
stat("Heartbeats (expect 1 per 5 min)", cw_target("A", "Innovatech/SOAR", "Heartbeat"),
     thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}])
stat("Dead-letter messages", cw_target("A", "AWS/SQS", "ApproximateNumberOfMessagesVisible", stat="Maximum",
                                       dims={"QueueName": "innovatech-soar-dlq"}), thresholds=red_if_any,
     calc="lastNotNull", description="Messages waiting now (a sum over time would overstate it). Replay: scripts/redrive-dlq.py")
timeseries("Events by response tier", [cw_target("A", "Innovatech/SOAR", "EventsProcessed", dims={"Tier": "*"},
                                                 label="tier ${PROP('Dim.Tier')}")], bars=True,
           description="0 observe, 1 notify, 2 contain network, 3 isolate host")
timeseries("Automated actions", [cw_target("A", "Innovatech/SOAR", "ActionsSucceeded", dims={"Action": "*"},
                                           label="ok ${PROP('Dim.Action')}"),
                                 cw_target("B", "Innovatech/SOAR", "ActionsFailed", dims={"Action": "*"},
                                           label="failed ${PROP('Dim.Action')}")], bars=True)
timeseries("Detection-to-response latency", [cw_target("A", "Innovatech/SOAR", "ProcessingLatency", stat="p95",
                                                       label="p95"),
                                             cw_target("B", "Innovatech/SOAR", "ProcessingLatency",
                                                       stat="Average", label="avg")], unit="ms")

# ---------------- Security signals (REQ-NCA-P2-07) ----------------
row("Security signals - office and cloud")
timeseries("IDS alerts (Suricata)", [cw_target("A", "Innovatech/Security", "IdsAlerts", label="all"),
                                     cw_target("B", "Innovatech/Security", "IdsHighAlerts", label="high")], bars=True)
timeseries("Failed SSH logins", [cw_target("A", "Innovatech/Security", "SshFailures")], bars=True)
timeseries("Firewall", [cw_target("A", "Innovatech/Security", "FirewallDrops", label="policy drops"),
                        cw_target("B", "Innovatech/Security", "SoarBlockedPkts", label="dropped by SOAR block")],
           bars=True)
timeseries("Detector findings (traffic + process)", [cw_target("A", "Innovatech/Security", "DetectorFindings")],
           bars=True)
timeseries("Rejected flows (all VPCs)", [cw_target("A", "Innovatech/Security", "FlowLogRejects")], bars=True)
timeseries("Normalised security events by type (OpenSearch)",
           [os_target("A", "log_type:event",
                      [{"type": "count", "id": "1"}],
                      [{"type": "terms", "id": "2", "field": "type.keyword",
                        "settings": {"size": "10", "order": "desc", "orderBy": "_count", "min_doc_count": "1"}},
                       {"type": "date_histogram", "id": "3", "field": "@timestamp", "settings": {"interval": "auto"}}])],
           bars=True)

# ---------------- Network ----------------
row("Hybrid network")
timeseries("VPN tunnels up (1 = up)", [cw_target("A", "AWS/VPN", "TunnelState", stat="Maximum",
                                                 dims={"TunnelIpAddress": "*"},
                                                 label="${PROP('Dim.TunnelIpAddress')}")])
timeseries("VPN traffic", [cw_target("A", "AWS/VPN", "TunnelDataIn", dims={"VpnId": "*"}, label="in"),
                           cw_target("B", "AWS/VPN", "TunnelDataOut", dims={"VpnId": "*"}, label="out")],
           unit="bytes")
timeseries("Transit Gateway traffic", [cw_target("A", "AWS/TransitGateway", "BytesIn",
                                                 dims={"TransitGateway": "*"}, label="in"),
                                       cw_target("B", "AWS/TransitGateway", "PacketDropCountNoRoute",
                                                 dims={"TransitGateway": "*"}, label="dropped: no route")])

# ---------------- Hosts and services ----------------
row("Hosts and services")
timeseries("CPU per instance", [cw_search("A", "SEARCH('{AWS/EC2,InstanceId} MetricName=\"CPUUtilization\"', "
                                               "'Average', 300)")], unit="percent")
timeseries("App: healthy servers / requests", [
    cw_target("A", "AWS/ApplicationELB", "HealthyHostCount", stat="Minimum",
              dims={"TargetGroup": "*", "LoadBalancer": "*"}, label="healthy"),
    cw_target("B", "AWS/ApplicationELB", "RequestCount", dims={"LoadBalancer": "*"}, label="requests")])
timeseries("Log database (OpenSearch)", [
    cw_target("A", "AWS/ES", "ClusterStatus.green", stat="Maximum", dims={"DomainName": "*", "ClientId": "*"},
              label="green"),
    cw_target("B", "AWS/ES", "SearchableDocuments", stat="Maximum", dims={"DomainName": "*", "ClientId": "*"},
              label="documents")])

# ---------------- Logs ----------------
row("SOAR cases and raw events (OpenSearch)")
panels.append({"type": "logs", "title": "Latest SOAR cases", "id": next(_next_id), "datasource": OS,
               "gridPos": place(12, 10),
               "targets": [os_target("A", "log_type:case", [{"type": "logs", "id": "1"}], [])],
               "options": {"showTime": True, "wrapLogMessage": True, "sortOrder": "Descending"}})
panels.append({"type": "logs", "title": "Suricata IDS alerts", "id": next(_next_id), "datasource": OS,
               "gridPos": place(12, 10),
               "targets": [os_target("A", "event_type:alert", [{"type": "logs", "id": "1"}], [])],
               "options": {"showTime": True, "wrapLogMessage": True, "sortOrder": "Descending"}})

dashboard = {
    "title": "Innovatech - Hybrid operations and SOAR",
    "uid": "innovatech-cs2",
    "timezone": "browser",
    "schemaVersion": 39,
    "refresh": "1m",
    "time": {"from": "now-3h", "to": "now"},
    "tags": ["innovatech", "soar"],
    "panels": panels,
}
OUT.write_text(json.dumps(dashboard, indent=1) + "\n")
print(f"wrote {OUT} ({len(panels)} panels)")
