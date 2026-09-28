#!/usr/bin/env bash
# Capture Falco's JSON output to run/falco.jsonl for the comparison (Sprint Handoff §5, Role 1).
# Start this in the background before running the scenarios:
#     eval/capture_falco.sh &
# and stop it (Ctrl-C or kill) once the scenarios are done. Needs Falco running with
# json_output=true (Sprint Handoff §10). Appends, so it survives across scenario runs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

: "${PROVBIND_RUN:=./run}"
: "${FALCO_NAMESPACE:=falco}"
OUT="$PROVBIND_RUN/falco.jsonl"
mkdir -p "$PROVBIND_RUN"

echo "capturing Falco JSON to $OUT (Ctrl-C to stop)" >&2
# Keep only JSON object lines (json_output=true), so startup log lines are dropped.
kubectl logs -n "$FALCO_NAMESPACE" -l app.kubernetes.io/name=falco -f --tail=0 \
  | grep --line-buffered '^{' >> "$OUT"
