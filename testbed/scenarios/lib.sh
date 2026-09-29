#!/usr/bin/env bash
# Shared helpers for the Role 1 scenario scripts (Sprint Handoff §5). Sourced, not run.
# Runs on the demo PC; needs kubectl, curl and python3. Scenarios reach the demo app through
# `kubectl port-forward` from the host, so a trigger runs NOTHING inside the app container: a
# `kubectl exec … curl` would add its own D_exec to the scenario's window (Role 3 handoff §4: no other
# activity in the pod during a scenario), and would fail attack-2's "no deterministic detection".
set -euo pipefail

: "${PROVBIND_RUN:=./run}"
: "${NAMESPACE:=demo}"
: "${DEPLOY:=demo-app}"
: "${POD_PREFIX:=demo-app}"
: "${PORT:=8080}"
: "${ENVELOPE_TIMEOUT:=120}"
: "${LOCAL_PORT:=18080}"
: "${CURL_TIMEOUT:=90}"         # attack-2's paced burst holds its request for about 20 s

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

PF_PID=""
stop_port_forward() {
  if [ -n "$PF_PID" ]; then kill "$PF_PID" 2>/dev/null || true; wait "$PF_PID" 2>/dev/null || true; fi
  PF_PID=""
}

# Forward LOCAL_PORT on the host to the app's PORT. Call it before a scenario's START time.
start_port_forward() {
  if [ -n "$PF_PID" ] && kill -0 "$PF_PID" 2>/dev/null; then return 0; fi
  kubectl port-forward -n "$NAMESPACE" "deploy/$DEPLOY" "${LOCAL_PORT}:${PORT}" >/dev/null 2>&1 &
  PF_PID=$!
  trap stop_port_forward EXIT
  local _
  for _ in $(seq 1 40); do
    curl -s -o /dev/null --max-time 2 "http://127.0.0.1:${LOCAL_PORT}/healthz" && return 0
    sleep 0.5
  done
  echo "lib: kubectl port-forward to deploy/$DEPLOY:${PORT} did not come up" >&2
  return 1
}

# GET an app endpoint (the attack endpoints act inside the app's own process). A failed trigger
# stops the script, so no ground-truth row is written for a run that did not happen.
app_curl() {
  start_port_forward
  curl -sf -o /dev/null --max-time "$CURL_TIMEOUT" "http://127.0.0.1:${LOCAL_PORT}$1" \
    || { echo "lib: GET $1 failed" >&2; return 1; }
}

# Wait until the pod's binding shows envelope_ready: true (Sprint Handoff §4.2, pitfall: trigger
# the attack only after the envelope exists, or its events land in the cold-start window).
wait_for_envelope() {
  local deadline=$(( $(date +%s) + ENVELOPE_TIMEOUT ))
  while true; do
    if PROVBIND_RUN="$PROVBIND_RUN" NAMESPACE="$NAMESPACE" POD_PREFIX="$POD_PREFIX" \
        python3 - <<'PY'
import json, os, sys
run = os.environ["PROVBIND_RUN"]; ns = os.environ["NAMESPACE"]; prefix = os.environ["POD_PREFIX"]
try:
    b = json.load(open(os.path.join(run, "bindings.json")))
except (OSError, ValueError):
    sys.exit(1)
for v in (b.values() if isinstance(b, dict) else []):
    if v.get("namespace") == ns and str(v.get("pod", "")).startswith(prefix) and v.get("envelope_ready"):
        sys.exit(0)
sys.exit(1)
PY
    then
      return 0
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "lib: timed out after ${ENVELOPE_TIMEOUT}s waiting for envelope_ready" >&2
      return 1
    fi
    sleep 2
  done
}

# Append one ground-truth row for this run (Sprint Handoff §4.7; one row per run, §12.2).
record_gt() {   # scenario label start end expected
  python3 -m eval.ground_truth --run "$PROVBIND_RUN" \
    --scenario "$1" --label "$2" --namespace "$NAMESPACE" --pod-prefix "$POD_PREFIX" \
    --start "$3" --end "$4" --expected "$5"
}
