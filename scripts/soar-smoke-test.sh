#!/usr/bin/env bash
# Posts a harmless test event to the private SOAR webhook and waits until the playbook has
# recorded it as a case. Run from inside AWS (the ops host / pipeline runner): the webhook is private.
set -euo pipefail
export AWS_PAGER="" AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1}
param() { aws ssm get-parameter --name "/innovatech/soar/$1" --with-decryption --query Parameter.Value --output text; }
URL=$(param webhook-url); API=$(param api-id); KEY=$(param api-key)
marker="smoke-$(date +%s)"
# A unique host per run: the SOAR de-duplicates identical incidents for 15 minutes
# (found when two pipeline runs 14 minutes apart produced only one case).
body=$(printf '{"source":"mockgen","type":"test.smoke","severity":5,"host":"%s","summary":"%s","details":{"smoke":true}}' "$marker" "$marker")

echo "POST $URL"
code=$(curl -s -o /tmp/smoke.json -w '%{http_code}' -X POST "$URL" -H "x-api-key: $KEY" -H "x-apigw-api-id: $API" \
  -H 'Content-Type: application/json' -d "$body")
cat /tmp/smoke.json; echo
[ "$code" = 202 ] || { echo "FAIL: webhook answered $code"; exit 1; }

# Severity 5 without a specific playbook -> tier 1 (notify) -> a case in DynamoDB.
for _ in $(seq 1 24); do
  found=$(aws dynamodb scan --table-name innovatech-soar-cases --filter-expression "summary = :m" \
    --expression-attribute-values "{\":m\":{\"S\":\"$marker\"}}" --query 'Count' --output text)
  [ "$found" -ge 1 ] && { echo "PASS: case recorded for $marker"; exit 0; }
  sleep 5
done
echo "FAIL: no case recorded within 2 minutes"; exit 1
