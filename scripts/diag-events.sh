#!/usr/bin/env bash
# Which Tetragon events reached PROVBIND in a run, and whether the loaded policies are healthy.
# Compares two run folders' raw event recordings (rec.jsonl), kind by kind and hook by hook:
#   scripts/diag-events.sh ./run ./run-opt-cmp
# Prints counts only (no event content).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
echo "== tracing policies in the cluster"
kubectl get tracingpoliciesnamespaced -A 2>&1 | head -20
kubectl get tracingpolicies 2>&1 | head -20
echo; echo "== policy state inside the Tetragon agent"
kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra tracingpolicy list 2>&1 | head -20
echo; echo "== Tetragon agent log lines about provbind policies or errors (last 15)"
kubectl logs -n kube-system ds/tetragon -c tetragon --since=48h 2>/dev/null \
  | grep -iE "provbind|level=error|level=warn.*(policy|sensor|kprobe)" | tail -15 | cut -c1-300
for run in "$@"; do
  echo; echo "== events in $run/rec.jsonl (namespace demo only)"
  python3 - "$run/rec.jsonl" <<'PY'
import collections, json, sys
c = collections.Counter()
try:
    f = open(sys.argv[1], encoding="utf-8", errors="replace")
except OSError as e:
    sys.exit(f"  cannot read: {e}")
for line in f:
    try:
        d = json.loads(line)
    except ValueError:
        c["(not JSON)"] += 1
        continue
    for kind, body in d.items():
        if not isinstance(body, dict) or "process" not in body:
            continue
        ns = ((body.get("process") or {}).get("pod") or {}).get("namespace")
        if ns != "demo":
            continue
        key = kind if kind != "process_kprobe" else f"process_kprobe {body.get('function_name')} ({body.get('policy_name')})"
        c[key] += 1
for k, v in sorted(c.items()):
    print(f"  {v:>9}  {k}")
PY
  echo "  -- node summary (last stats line of logs/node.out or node.log):"
  { grep -h '"dropped"' "$run/logs/node.out" "$run/logs/node.log" 2>/dev/null | tail -1 | cut -c1-1500; } || true
done
