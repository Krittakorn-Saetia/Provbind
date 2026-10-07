#!/usr/bin/env bash
# Does Tetragon report the demo app's OWN process? Sends 20 GET /cache (each makes the long-running
# server process write a file under /tmp/app-cache) and counts the write events that come through the
# stream for that path. Counts only.   scripts/probe-events.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
: "${NAMESPACE:=demo}"; : "${DEPLOY:=demo-app}"; : "${TETRAGON_CONTAINER:=export-stdout}"
OUT=$(mktemp); PF=""
trap 'kill $LP $PF 2>/dev/null; rm -f "$OUT"' EXIT
echo "== pods"
kubectl -n "$NAMESPACE" get pods -o wide | cut -c1-120
kubectl -n kube-system get pods -l app.kubernetes.io/name=tetragon | cut -c1-100
kubectl logs -n kube-system ds/tetragon -c "$TETRAGON_CONTAINER" -f --tail=0 > "$OUT" 2>/dev/null & LP=$!
kubectl port-forward -n "$NAMESPACE" "deploy/$DEPLOY" 18081:8080 >/dev/null 2>&1 & PF=$!
sleep 4
ok=0; for i in $(seq 1 20); do curl -sf -o /dev/null --max-time 5 http://127.0.0.1:18081/cache && ok=$((ok+1)); sleep 0.2; done
sleep 6
echo "== $ok of 20 GET /cache answered"
python3 - "$OUT" <<'PY'
import collections, json, sys
c = collections.Counter()
for line in open(sys.argv[1], errors="replace"):
    try: d = json.loads(line)
    except ValueError: continue
    for kind, b in d.items():
        if not isinstance(b, dict) or "process" not in b: continue
        p = b["process"]; ns = (p.get("pod") or {}).get("namespace")
        if kind == "process_kprobe":
            path = next((a["file_arg"].get("path", "") for a in b.get("args", []) if "file_arg" in a), "")
            tag = "app-cache write" if path.startswith("/tmp/app-cache") else b.get("function_name")
        else:
            tag = kind
        c[(ns, p.get("binary"), tag)] += 1
print("== events in those 30 s (namespace, binary, what): count")
for k, v in sorted(c.items(), key=lambda x: -x[1])[:15]: print(f"  {v:>6}  {k}")
hit = sum(v for k, v in c.items() if k[2] == "app-cache write")
print(f"== RESULT: {hit} app-cache write events (expect about 20; 0 means Tetragon does not report the app process)")
PY
