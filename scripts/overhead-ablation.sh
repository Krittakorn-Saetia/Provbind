#!/usr/bin/env bash
# Where PROVBIND's runtime cost comes from (follow-up to scripts/overhead-run.sh, supervisor's question 4):
# each Tetragon policy on its own (the sensor's share, policy by policy), and the whole of PROVBIND
# without ML-B (the userspace share of ML-B). Every set is measured against `none` in the same run, so
# drift between runs cancels out. About 1.5 h with the defaults, unattended:
#   DEMO_REF=<registry>/demo-app@sha256:<hex> scripts/overhead-ablation.sh
# Results: run-ablation/<set>/results/OVERHEAD.md, and run-ablation/ABLATION.md (one table).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
: "${DEMO_REF:?set DEMO_REF to the demo image ref@digest}"; export DEMO_REF
: "${OUT:=./run-ablation}"
: "${REPS:=2}"; : "${MIX_S:=60}"; : "${CACHE_S:=40}"
export REPS MIX_S CACHE_S SKIP_PREP=1
T=node/tetragon
if [ -e "$OUT" ]; then echo "overhead-ablation: $OUT exists; move it aside first" >&2; exit 1; fi
mkdir -p "$OUT"

run_set() {   # NAME CONFIGS POLICIES NODE_MLB
  echo; echo "##### $(date -u +%H:%M:%S) ablation set: $1 ($2; policies: $3; ML-B $4)"
  OUT_RUN="$OUT/$1" CONFIGS="$2" POLICIES="$3" NODE_MLB="$4" scripts/overhead-run.sh 2>&1 | tee "$OUT/$1.log" \
    || echo "overhead-ablation: set $1 failed (see $OUT/$1.log)"
}
ALL="$T/write.yaml $T/truncate.yaml $T/cap.yaml $T/load.yaml $T/connect.yaml"
for pol in write truncate cap load connect; do
  # only this policy loaded: remove the others first (overhead-run.sh applies what it is given)
  for other in write truncate cap load connect; do kubectl delete -f "$T/$other.yaml" --ignore-not-found >/dev/null; done
  run_set "only-$pol" "none tetragon" "$T/$pol.yaml" 1
done
for other in write truncate cap load connect; do kubectl delete -f "$T/$other.yaml" --ignore-not-found >/dev/null; done
run_set "provbind-no-mlb" "none provbind" "$ALL" 0
for p in $ALL; do kubectl apply -f "$p" >/dev/null; done                 # back to the comparison's policies

python3 - "$OUT" <<'PY'
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
rows = ["# Where the cost comes from (ablation)", "",
        "Each set against `none` in the same run; worst application overhead (request mix and /cache) and "
        "the worst-case micro-benchmark.", "",
        "| Set | Configuration | p95 mix | p95 /cache | file write | process spawn | worst app | worst micro |",
        "|---|---|---|---|---|---|---|---|"]
for d in sorted(out.iterdir()):
    f = d / "results" / "OVERHEAD.json"
    if not f.exists():
        continue
    doc = json.loads(f.read_text())
    for cfg in doc["configs"]:
        if cfg == "none":
            continue
        get = lambda name: next((e["overhead_pct"].get(cfg) for e in doc["table"] if e["metric"].startswith(name)), None)
        v = doc["verdict"].get(cfg, {})
        fmt = lambda x: "—" if x is None else f"{x:.1f}%"
        rows.append(f"| {d.name} | {cfg} | {fmt(get('request latency p95, mix'))} | {fmt(get('request latency p95, /cache'))} | "
                    f"{fmt(get('file write'))} | {fmt(get('process spawn'))} | {fmt(v.get('worst_app_overhead_pct'))} | "
                    f"{fmt(v.get('worst_micro_overhead_pct'))} |")
text = "\n".join(rows) + "\n"
(out / "ABLATION.md").write_text(text)
print(text)
PY
echo "overhead ablation done: $OUT/ABLATION.md"
