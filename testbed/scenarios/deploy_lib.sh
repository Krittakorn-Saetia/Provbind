#!/usr/bin/env bash
# Helpers for the admission-cell scenarios (comparison test plan section 3.1). Sourced by the A-K*
# and A-U2 deploy scripts. Each admission scenario deploys its OWN short-lived deployment in the demo
# namespace and tears it down again, so the long-lived runtime pod (the R-* and benign scenarios) is
# never disturbed. Runs on the demo PC with the controller watching namespace demo.
set -euo pipefail

# lib.sh gives us now(), record_gt() and the run-folder defaults; source it from the repo root.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

: "${PROVBIND_REGISTRY:=localhost:5001}"
: "${BINDING_TIMEOUT:=120}"

# Deploy REF under a temporary deployment NAME (no volume; admission scenarios do not need /data).
deploy_temp() {   # NAME REF
  kubectl -n "$NAMESPACE" create deployment "$1" --image="$2" --port=8080 \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
}

teardown_temp() { kubectl -n "$NAMESPACE" delete deployment "$1" --ignore-not-found >/dev/null 2>&1 || true; }

# Wait until the controller has WRITTEN a binding for pods whose name starts with PREFIX, whatever its
# verification result (an admission failure still records a binding with verified:false). Returns 0
# once one exists, 1 on timeout.
wait_binding() {   # PREFIX
  local deadline=$(( $(date +%s) + BINDING_TIMEOUT ))
  while true; do
    if PROVBIND_RUN="$PROVBIND_RUN" NAMESPACE="$NAMESPACE" PREFIX="$1" python3 - <<'PY'
import json, os, sys
run, ns, prefix = os.environ["PROVBIND_RUN"], os.environ["NAMESPACE"], os.environ["PREFIX"]
try:
    b = json.load(open(os.path.join(run, "bindings.json")))
except (OSError, ValueError):
    sys.exit(1)
for v in (b.values() if isinstance(b, dict) else []):
    if v.get("namespace") == ns and str(v.get("pod", "")).startswith(prefix):
        sys.exit(0)
sys.exit(1)
PY
    then return 0; fi
    [ "$(date +%s)" -ge "$deadline" ] && { echo "deploy_lib: timed out waiting for a binding for $1" >&2; return 1; }
    sleep 2
  done
}
