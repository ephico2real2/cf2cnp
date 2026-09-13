#!/usr/bin/env bash
# regenerate.sh <cf2cnp binary> — rewrite every golden expected.yaml with the given binary's /generate answer.
# Use only for a deliberate output change; commit the regenerated files with the change that caused them.
set -euo pipefail; cd "$(dirname "$0")/../.."; BIN="${1:?cf2cnp binary}"; PORT=28096
"$BIN" serve --port $PORT >/dev/null 2>&1 & PID=$!; trap 'kill $PID 2>/dev/null' EXIT; sleep 2
for d in internal/testdata/golden/*/; do
  q=$(python3 -c "import json,urllib.parse; print(urllib.parse.urlencode(json.load(open('$d/options.json'))))")
  curl -s --fail-with-body -X POST "http://127.0.0.1:$PORT/generate${q:+?$q}" --data-binary @"$d/flows.ndjson" -o "$d/expected.yaml"
  echo "$(basename "$d"): $(grep -c '^kind: CiliumNetworkPolicy' "$d/expected.yaml") policies"
done
