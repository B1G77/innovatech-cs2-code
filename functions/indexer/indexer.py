"""Copies CloudWatch Logs into OpenSearch (one index per log group per day).

CloudWatch Logs stays the collection point and short-term store; OpenSearch is the
searchable, replicated store for investigation and dashboards. Failed batches raise, so
the asynchronous invoke retries and finally lands in the dead-letter queue.
"""
import base64
import gzip
import json
import os
import re
import urllib.request
from datetime import datetime, timezone

import boto3

ENDPOINT = os.environ.get("OPENSEARCH_ENDPOINT", "")
USER = os.environ.get("OPENSEARCH_USER", "ingest")
PASSWORD_PARAM = os.environ.get("OPENSEARCH_PASSWORD_PARAM", "")
_auth = {}


def _authorization():
    if "header" not in _auth:
        pw = boto3.client("ssm").get_parameter(Name=PASSWORD_PARAM, WithDecryption=True)["Parameter"]["Value"]
        _auth["header"] = "Basic " + base64.b64encode(f"{USER}:{pw}".encode()).decode()
    return _auth["header"]


def index_name(log_group, ts_ms):
    """/innovatech/onprem/suricata -> logs-onprem-suricata-2026.10; /aws/lambda/innovatech-soar-act -> logs-soar-act-..."""
    name = re.sub(r"^/(aws/lambda/)?(innovatech[-/])?", "", log_group).replace("/", "-").lower()
    name = re.sub(r"[^a-z0-9-]", "-", name).strip("-") or "misc"
    # Monthly, not daily: daily indices reached 108 shards on two small nodes, the JVM stalled
    # and the cluster lost its manager (found 29 October).
    month = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).strftime("%Y.%m")
    return f"logs-{name}-{month}"


def to_docs(payload):
    group, stream = payload["logGroup"], payload["logStream"]
    for item in payload.get("logEvents", []):
        msg = item.get("message", "").strip()
        try:
            doc = json.loads(msg)
            if not isinstance(doc, dict):
                doc = {"message": msg}
        except json.JSONDecodeError:
            doc = {"message": msg}
        doc.pop("_aws", None)
        doc.setdefault("@timestamp", datetime.fromtimestamp(item["timestamp"] / 1000, tz=timezone.utc).isoformat())
        doc["log_group"], doc["log_stream"] = group, stream
        doc.setdefault("host", stream)
        yield index_name(group, item["timestamp"]), item["id"], doc


def bulk_body(docs):
    lines = []
    for index, doc_id, doc in docs:
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(doc, default=str))
    return ("\n".join(lines) + "\n").encode()


def handler(event, _context):
    payload = json.loads(gzip.decompress(base64.b64decode(event["awslogs"]["data"])))
    if payload.get("messageType") != "DATA_MESSAGE":
        return {"indexed": 0}
    body = bulk_body(to_docs(payload))
    req = urllib.request.Request(f"https://{ENDPOINT}/_bulk", data=body, method="POST", headers={
        "Content-Type": "application/x-ndjson", "Authorization": _authorization()})
    with urllib.request.urlopen(req, timeout=50) as resp:
        result = json.loads(resp.read())
    if result.get("errors"):
        failed = [i for i in result["items"] if i.get("index", {}).get("error")]
        reasons = {json.dumps(i["index"]["error"].get("type")) for i in failed}
        # Mapping conflicts on single documents are logged, not retried forever.
        print(json.dumps({"log_type": "indexer", "failed": len(failed), "reasons": sorted(reasons)}))
        if len(failed) == len(result["items"]):
            raise RuntimeError(f"bulk indexing failed: {sorted(reasons)}")
    return {"indexed": len(result.get("items", []))}
