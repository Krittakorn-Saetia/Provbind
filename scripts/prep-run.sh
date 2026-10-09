#!/usr/bin/env bash
# Figure 1's preparation times and the zero-day checks for a FINISHED comparison run folder, without the
# 1.5 h overhead measurement: the same steps 0b and 0c as scripts/overhead-run.sh, plus one timed Falco
# restart. (The comparison run itself already recorded OH-01, OH-04 and OH-05.) Writes PREP.md, PREP.json
# and ZERODAY.md into $PROVBIND_RUN/results, where the figures read them. About 10 minutes on the demo VM:
#   PROVBIND_RUN=./run-final MLB_DATA=ml/data/mlb/<hex>-opt RECORD_LOG=record-d2-opt.log \
#     COMPARISON_LOG=run-final.log scripts/prep-run.sh
# DEMO_REF must be set as for the runs. Falco is stopped and started once (it is back on at the end).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
: "${PROVBIND_RUN:=./run}"; export PROVBIND_RUN
: "${DEMO_REF:?set DEMO_REF to the demo image ref@digest}"
: "${NAMESPACE:=demo}"; : "${DEPLOY:=demo-app}"
: "${PROVBIND_KEY:=pipeline/keys/cosign.pub}"
: "${EGRESS:=testbed/egress.json}"
: "${PREP_RUNS:=5}"
HEX="${DEMO_REF##*@sha256:}"
: "${MLB_DATA:=ml/data/mlb/$HEX}"
: "${RECORD_LOG:=$PROVBIND_RUN/record-d2.log}"            # record-d2.sh's output (D2's benign load)
: "${COMPARISON_LOG:=$PROVBIND_RUN/comparison-run.log}"   # comparison-run.sh's output (DeSFAM's baseline load)
RES="$PROVBIND_RUN/results"; WORK="$PROVBIND_RUN/prep-work"; BINS="$PROVBIND_RUN/prep-binaries"
BASE="$PROVBIND_RUN/traces/baseline"; PREP="$RES/prep.jsonl"     # append-only; the last row per system wins
mkdir -p "$RES" "$WORK"
step() { echo; echo "=== $(date -u +%H:%M:%S) $*"; }
[ -d "$MLB_DATA" ] || { echo "prep-run: no ML-B data folder $MLB_DATA (set MLB_DATA)" >&2; exit 1; }
for f in "$RECORD_LOG" "$COMPARISON_LOG" "$BASE/startup.txt"; do
  [ -f "$f" ] || echo "prep-run: $f not found; the numbers taken from it stay empty" >&2
done

step "1. the demo app (the binaries are exported from the running pod)"
if ! kubectl -n "$NAMESPACE" get deploy "$DEPLOY" >/dev/null 2>&1; then
  kubectl -n "$NAMESPACE" create deployment "$DEPLOY" --image="$DEMO_REF" --port=8080 >/dev/null
  kubectl -n "$NAMESPACE" patch deployment "$DEPLOY" --patch-file testbed/demo-app/volume-patch.yaml >/dev/null
fi
kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOY" --timeout=180s >/dev/null

step "2. PROVBIND: $PREP_RUNS cold compiles of the envelope"
python3 -m eval.prep_time provbind --ref "$DEMO_REF" --runs "$PREP_RUNS" --work "$WORK" \
  --key "$PROVBIND_KEY" --out "$PREP" || echo "  PROVBIND compile timing failed (see above)"

step "3. Confine-E and DeSFAM-E: export the binaries the start-up trace ran, then analyse them"
EXPORT_S=""
t0=$(date +%s.%N)
eval/baselines/export_binaries.sh --run "$PROVBIND_RUN" --namespace "$NAMESPACE" --deploy "$DEPLOY" \
  --digest "${DEMO_REF##*@}" --out "$BINS" --startup-trace "$BASE/startup.txt" \
  && EXPORT_S=$(python3 -c "import sys; print(round(float(sys.argv[2]) - float(sys.argv[1]), 3))" "$t0" "$(date +%s.%N)") \
  || echo "  exporting the binaries failed"
# Which packages own the analysed ELF files (dpkg in the demo container; a source-built runtime such as
# the image's Python under /usr/local belongs to no package and is counted apart).
OWN=$(ls "$BINS" 2>/dev/null | sed 's|%|/|g' | kubectl -n "$NAMESPACE" exec -i "deploy/$DEPLOY" -- sh -c \
  'while read p; do q=$(dpkg -S "$p" 2>/dev/null | head -1); [ -n "$q" ] || q=$(dpkg -S "${p#/usr}" 2>/dev/null | head -1);
   if [ -n "$q" ]; then echo "PKG ${q%%:*}"; else echo NONE; fi; done' 2>/dev/null || true)
PKGS=$( { printf '%s\n' "$OWN" | grep '^PKG' || true; } | sort -u | wc -l)
UNOWNED=$(printf '%s\n' "$OWN" | grep -c '^NONE' || true)
echo "  analysed ELF files come from $PKGS packages (+$UNOWNED files outside any package)"
python3 -m eval.prep_time confine --binaries "$BINS" --startup "$BASE/startup.txt" \
  --export-s "${EXPORT_S:-0}" --packages "$PKGS" --unowned "$UNOWNED" --out "$PREP" \
  || echo "  Confine-E timing failed"
REQS=$(grep -oE "loadgen: [0-9]+ requests in 600s" "$COMPARISON_LOG" 2>/dev/null | head -3 \
       | awk '{s += $2} END {print s + 0}')
python3 -m eval.prep_time desfam --binaries "$BINS" --benign "$BASE/benign-*.txt" \
  --requests "${REQS:-0}" --packages "$PKGS" --unowned "$UNOWNED" --out "$PREP" || echo "  DeSFAM-E timing failed"

step "4. ML-B: D2's benign load from $RECORD_LOG, training timed again"
python3 -m eval.prep_time mlb --log "$RECORD_LOG" --data "$MLB_DATA" --work "$WORK" --out "$PREP" \
  || echo "  ML-B timing failed"

step "5. Falco: no per-image step; one timed restart (its rules load at start)"
falco_on() { kubectl -n falco patch ds falco --type merge \
  -p '{"spec":{"template":{"spec":{"nodeSelector":{"provbind-overhead":null}}}}}' >/dev/null; }
falco_pods() { kubectl -n falco get pods -o name 2>/dev/null | grep -E "^pod/falco-[a-z0-9]{5}$" || true; }
trap 'falco_on || true' EXIT                     # never leave Falco off
kubectl -n falco patch ds falco --type merge \
  -p '{"spec":{"template":{"spec":{"nodeSelector":{"provbind-overhead":"off"}}}}}' >/dev/null
for _ in $(seq 1 90); do [ -z "$(falco_pods)" ] && break; sleep 2; done
t0=$(date +%s.%N)
falco_on
kubectl -n falco rollout status ds/falco --timeout=300s >/dev/null
READY=$(python3 -c "import sys; print(round(float(sys.argv[2]) - float(sys.argv[1]), 3))" "$t0" "$(date +%s.%N)")
echo "  Falco ready ${READY}s after it was scheduled again"
python3 -m eval.prep_time falco --ready-s "$READY" --out "$PREP"

step "6. the report and the zero-day checks"
python3 -m eval.prep_time report --prep "$PREP" --out "$RES"
python3 -m eval.zero_day_check --run "$PROVBIND_RUN" --mlb-data "$MLB_DATA" --digest "$HEX" --egress "$EGRESS" \
  || echo "  a zero-day check FAILED: see $RES/ZERODAY.md"
echo "prep-run done: $RES/PREP.md, $RES/PREP.json and $RES/ZERODAY.md"
