"""SOAR collector: receives events from every source, normalises them, puts them on the SOAR bus.

Called by:
  * CloudWatch Logs subscriptions (Suricata alerts, SSH lines from the office)
  * API Gateway (private webhook POST /events used by the traffic analyzer and process watcher)
  * EventBridge (GuardDuty findings, CloudWatch anomaly alarms)
  * EventBridge Scheduler (heartbeat every 5 minutes)
"""
import base64
import gzip
import json
import os

import boto3

import normalize
from common import log, metric

BUS = os.environ.get("EVENT_BUS", "innovatech-soar")
events = boto3.client("events")


def _from_logs(data):
    payload = json.loads(gzip.decompress(base64.b64decode(data)))
    group, host = payload.get("logGroup", ""), payload.get("logStream", "")
    out = []
    for item in payload.get("logEvents", []):
        msg = item.get("message", "")
        if group.endswith("/suricata"):
            ev = normalize.from_suricata(msg, host)
        elif group.endswith("/auth"):
            ev = normalize.from_auth(msg, host)
        else:
            ev = None
        if ev:
            out.append(ev)
    return out


def publish(normalised):
    for i in range(0, len(normalised), 10):
        batch = normalised[i:i + 10]
        resp = events.put_events(Entries=[{
            "Source": "innovatech.soar.ingest", "DetailType": "SecurityEvent",
            "Detail": json.dumps(ev), "EventBusName": BUS} for ev in batch])
        if resp.get("FailedEntryCount"):
            raise RuntimeError(f"{resp['FailedEntryCount']} events not accepted by EventBridge")
    for ev in normalised:
        metric("EventsReceived", dimensions={"Source": ev["source"]})
        log("event", **ev)


def _api_response(code, body):
    return {"statusCode": code, "headers": {"Content-Type": "application/json"}, "body": json.dumps(body)}


def handler(event, _context):
    if "awslogs" in event:
        normalised = _from_logs(event["awslogs"]["data"])
    elif "requestContext" in event:  # API Gateway webhook
        try:
            body = json.loads(event.get("body") or "")
            items = body if isinstance(body, list) else [body]
            if len(items) > 25:
                raise normalize.InvalidEvent("at most 25 events per request")
            normalised = [normalize.from_webhook(b) for b in items]
        except (json.JSONDecodeError, normalize.InvalidEvent) as err:
            metric("EventsRejected")
            return _api_response(400, {"error": str(err)})
        publish(normalised)
        return _api_response(202, {"accepted": len(normalised), "ids": [e["id"] for e in normalised]})
    elif event.get("source") == "aws.guardduty":
        normalised = [normalize.from_guardduty(event.get("detail", {}))]
    elif event.get("source") == "aws.cloudwatch":
        normalised = [e for e in [normalize.from_alarm(event.get("detail", {}))] if e]
    elif event.get("heartbeat"):
        normalised = [normalize.heartbeat()]
    else:
        log("ignored", keys=list(event)[:10])
        return {"accepted": 0}

    publish(normalised)
    return {"accepted": len(normalised)}
