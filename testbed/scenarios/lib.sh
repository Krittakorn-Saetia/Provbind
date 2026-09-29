#!/usr/bin/env bash
# Shared helpers for the Role 1 scenario scripts (Sprint Handoff §5). Sourced, not run.
# Runs on the demo PC; needs kubectl and python3. All scenarios talk to the demo app by
# hitting its own endpoint from inside its pod, so no port-forward is needed.
set -euo pipefail

: "${PROVBIND_RUN:=./run}"
: "${NAMESPACE:=demo}"
: "${DEPLOY:=demo-app}"
: "${POD_PREFIX:=demo-app}"
: "${PORT:=8080}"
: "${ENVELOPE_TIMEOUT:=120}"

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Hit an app endpoint from inside the pod (the attack endpoints act inside the container).
app_curl() {
  kubectl exec -n "$NAMESPACE" "deploy/$DEPLOY" -- curl -s "http://127.0.0.1:${PORT}$1" >/dev/null || true
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
