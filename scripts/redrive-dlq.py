#!/usr/bin/env python3
"""Replays failed asynchronous Lambda invocations parked in the SOAR dead-letter queue.

The queue receives Lambda on-failure records (indexer, ingest); each keeps the original
event ("requestPayload"), so nothing is lost. After fixing the cause, run:
    .venv/bin/python scripts/redrive-dlq.py [--max 5000]
Successful replays are deleted from the queue; failures stay for the next attempt.
"""
import argparse
import json
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.config import Config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", default="innovatech-soar-dlq")
    parser.add_argument("--max", type=int, default=5000)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    sqs = boto3.client("sqs")
    lam = boto3.client("lambda", config=Config(retries={"max_attempts": 10, "mode": "adaptive"}, read_timeout=120))
    url = sqs.get_queue_url(QueueName=args.queue)["QueueUrl"]
    counts = {"replayed": 0, "failed": 0, "skipped": 0}

    def replay(m):
        body = json.loads(m["Body"])
        fn = body.get("requestContext", {}).get("functionArn", "").split(":function:")[-1].split(":")[0]
        payload = body.get("requestPayload")
        if not fn or payload is None:
            return "skipped"  # e.g. an EventBridge DLQ record: handle by hand
        try:
            resp = lam.invoke(FunctionName=fn, Payload=json.dumps(payload).encode())
        except Exception:
            return "failed"
        if resp.get("FunctionError"):
            return "failed"
        sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        return "replayed"

    # As many parallel replays as the indexer may run at once.
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        while sum(counts.values()) < args.max:
            msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2,
                                       VisibilityTimeout=300).get("Messages", [])
            if not msgs:
                break
            for result in pool.map(replay, msgs):
                counts[result] += 1
    done, failed, skipped = counts["replayed"], counts["failed"], counts["skipped"]
    print(f"replayed {done}, still failing {failed}, skipped {skipped}")


if __name__ == "__main__":
    main()
