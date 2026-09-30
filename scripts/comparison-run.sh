#!/usr/bin/env bash
# The four-system comparison run (comparison test plan sections 3-6). Runs on the demo VM after
# `make up` and `make demo-app`, in a FRESH run folder. It:
#   1. starts PROVBIND (controller, node, alerts, trust loop) and the Falco capture, as `make scored`;
#   2. deploys the signed demo app with an emptyDir at /data (for B5), and waits for its envelope;
#   3. records the pod's system calls for the estimated baselines: a start-up trace, a benign baseline,
#      and one trace per scenario run, named run/traces/<scenario>-<k>.txt (what the aggregator wants);
#   4. runs every Tier 1 + Tier 2 runtime/benign scenario ROUNDS times, then the admission scenarios;
#   5. applies Confine-E and DeSFAM-E to the traces and builds the four-system tables (aggregate),
#      plus the PROVBIND-vs-Falco scoring matrix and the time-to-alert summary.
#
#   DEMO_REF=<registry>/demo-app@sha256:<hex> sudo -E scripts/comparison-run.sh
#
# bpftrace needs root, so run the whole script under `sudo -E` (or set TRACE=0 to skip all syscall
# tracing and compare PROVBIND vs Falco only). Every scenario is our own harmless test code; no real
# malicious sample is downloaded or run (comparison test plan section 8). Do not type in the terminal
# or take a VM snapshot while it runs (a snapshot shifts Falco's clock).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

: "${PROVBIND_RUN:=./run}"; export PROVBIND_RUN
: "${NAMESPACE:=demo}"; export NAMESPACE
: "${DEPLOY:=demo-app}"; export DEPLOY
: "${DEMO_REF:?set DEMO_REF to the signed ref@digest that make demo-app printed}"
: "${PROVBIND_KEY:=pipeline/keys/cosign.pub}"
: "${TETRAGON_CONTAINER:=export-stdout}"
: "${POLICIES:=node/tetragon/write.yaml node/tetragon/truncate.yaml node/tetragon/cap.yaml}"
: "${ROUNDS:=5}"              # comparison plan: every scenario at least 5 times
: "${GAP:=10}"
: "${WAIT_S:=120}"
: "${TRACE:=1}"              # 0 = no bpftrace; PROVBIND vs Falco only, estimators skipped
: "${ATTACK2:=0}"           # 1 = also R-U2 (needs an ML-B model; off by default)
: "${ADMISSION:=1}"         # 1 = also the A-K1/A-K2/A-K3/A-U2 admission scenarios
: "${BASELINE_SECONDS:=600}"   # DeSFAM baseline: 3 x 10 min of loadgen by default
: "${BASELINE_CYCLES:=3}"
: "${STARTUP_SECONDS:=30}"     # Confine watches the first 30 s
: "${DOCKER_SECCOMP:=eval/baselines/docker-seccomp.json}"   # optional; DeSFAM template

TRACES="$PROVBIND_RUN/traces"
BASE="$TRACES/baseline"
BIN="$TRACES/binaries"
RESULTS="$PROVBIND_RUN/results"

if [ -e "$PROVBIND_RUN/ground_truth.csv" ]; then
  echo "comparison-run: $PROVBIND_RUN already has a ground_truth.csv; move it aside (mv run run-old) first" >&2
  exit 1
fi
if [ "$TRACE" = 1 ] && ! command -v bpftrace >/dev/null; then
  echo "comparison-run: TRACE=1 but bpftrace is not installed (apt install bpftrace), or set TRACE=0" >&2
  exit 1
fi

mkdir -p "$PROVBIND_RUN/logs" "$TRACES" "$BASE" "$RESULTS"
LOGS="$PROVBIND_RUN/logs"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
step() { echo; echo "=== $(date -u +%H:%M:%S) $*"; }

# --- syscall tracing helpers (only when TRACE=1) --------------------------------------------------
APP_PID=""
TRACE_BG=""
find_app_pid() {   # the host pid of the demo pod's `python app.py` process, for the bpftrace ns filter
  APP_PID="${APP_PID:-$(pgrep -f 'python app.py' | head -1 || true)}"
  [ -n "$APP_PID" ] || { echo "comparison-run: could not find the demo app pid (set APP_PID=...)" >&2; return 1; }
}
trace_start() {   # OUTFILE : start recording into OUTFILE, then wait for bpftrace to attach
  [ "$TRACE" = 1 ] || return 0
  eval/baselines/record_trace.sh --pid "$APP_PID" --out "$1" >/dev/null 2>&1 &
  TRACE_BG=$!
  sleep 2
}
trace_stop() {    # stop the current recording and flush the file
  [ "$TRACE" = 1 ] || return 0
  pkill -INT -x bpftrace 2>/dev/null || true
  wait "$TRACE_BG" 2>/dev/null || true
  sleep 1
}

# Run one scenario `make TARGET`, tracing into <scenario>-<k>.txt. REST=1 also runs RESTORE=1 after
# (for trust/trust2, which set a condition and must undo it).
run_traced() {    # SCENARIO K TARGET [REST]
  local scenario="$1" k="$2" target="$3" rest="${4:-0}"
  step "round $k: $scenario (make $target)"
  trace_start "$TRACES/$scenario-$k.txt"
  make --no-print-directory "$target"
  [ "$rest" = 1 ] && RESTORE=1 make --no-print-directory "$target"
  trace_stop
  sleep "$GAP"
}

step "0. background: controller, node, alerts, trust loop, Falco"
for policy in $POLICIES; do kubectl apply -f "$policy" >/dev/null; done
python3 -m controller.watch --run "$PROVBIND_RUN" --namespace "$NAMESPACE" --key "$PROVBIND_KEY" \
  > "$LOGS/controller.out" 2> "$LOGS/controller.log" & PIDS+=($!)
( kubectl logs -n kube-system ds/tetragon -c "$TETRAGON_CONTAINER" -f --tail=0 \
    | tee "$PROVBIND_RUN/rec.jsonl" \
    | python3 -m node.run --run "$PROVBIND_RUN" ) > "$LOGS/node.out" 2> "$LOGS/node.log" & PIDS+=($!)
python3 -m alerts.run --run "$PROVBIND_RUN" > "$LOGS/alerts.out" 2> "$LOGS/alerts.log" & PIDS+=($!)
python3 -m alerts.trust --run "$PROVBIND_RUN" --poll 2 > "$LOGS/trust.out" 2> "$LOGS/trust.log" & PIDS+=($!)
./eval/capture_falco.sh > "$LOGS/falco.out" 2> "$LOGS/falco.log" & PIDS+=($!)
sleep 3

step "1. deploy the signed demo app by digest, with an emptyDir at /data (B5)"
kubectl -n "$NAMESPACE" create deployment "$DEPLOY" --image="$DEMO_REF" --port=8080 \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NAMESPACE" patch deployment "$DEPLOY" --patch-file testbed/demo-app/volume-patch.yaml >/dev/null
kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOY" --timeout="${WAIT_S}s"
( source testbed/scenarios/lib.sh; ENVELOPE_TIMEOUT="$WAIT_S" wait_for_envelope )
python3 -m alerts.attribute --run "$PROVBIND_RUN" >/dev/null \
  || echo "Neo4j is not reachable: attribution uses the envelope's layer field"
sleep 30

if [ "$TRACE" = 1 ]; then
  find_app_pid
  step "2. start-up trace + export the image's binaries for the estimators"
  eval/baselines/record_trace.sh --pid "$APP_PID" --out "$BASE/startup.txt" --seconds "$STARTUP_SECONDS" || true
  eval/baselines/export_binaries.sh --run "$PROVBIND_RUN" --namespace "$NAMESPACE" --deploy "$DEPLOY" \
    --digest "${DEMO_REF##*@}" --out "$BIN" --startup-trace "$BASE/startup.txt" \
    || echo "comparison-run: export_binaries failed; the estimators need $BIN"

  step "2b. benign baseline for DeSFAM: $BASELINE_CYCLES x ${BASELINE_SECONDS}s of load"
  for c in $(seq 1 "$BASELINE_CYCLES"); do
    trace_start "$BASE/benign-$c.txt"
    DURATION="$BASELINE_SECONDS" make --no-print-directory loadgen || true
    trace_stop
  done
fi

step "3. runtime + benign scenarios, $ROUNDS rounds each (Tier 1 + Tier 2)"
for k in $(seq 1 "$ROUNDS"); do
  run_traced benign-1        "$k" benign
  run_traced benign-traffic  "$k" benign-traffic
  run_traced ph4-14          "$k" ph4-14
  run_traced attack-1        "$k" attack
  [ "$ATTACK2" = 1 ] && run_traced attack-2 "$k" attack2
  run_traced trust-1         "$k" trust 1
  run_traced trust-2         "$k" trust2 1
  run_traced rk-2            "$k" rk2
  run_traced rk-3            "$k" rk3
  run_traced ru-3            "$k" ru3
  run_traced ru-4            "$k" ru4
  run_traced ru-5            "$k" ru5
  run_traced benign-3        "$k" benign-dns
  run_traced benign-4        "$k" benign-vol
done

if [ "$ADMISSION" = 1 ]; then
  step "4. admission scenarios (own short-lived deployments; not syscall-traced)"
  for k in $(seq 1 "$ROUNDS"); do
    step "round $k: A-K1 advisory-first"; make --no-print-directory ak1 || true; sleep "$GAP"
    step "round $k: A-K2 unsigned";       make --no-print-directory ak2 || true; sleep "$GAP"
    step "round $k: A-K3 revoked key";    make --no-print-directory ak3 || true; sleep "$GAP"
    step "round $k: A-U2 build-time";     make --no-print-directory au2-deploy || true; sleep "$GAP"
  done
fi

step "5. estimated baselines: Confine-E and DeSFAM-E over the scenario traces"
if [ "$TRACE" = 1 ]; then
  mapfile -t SCEN_TRACES < <(find "$TRACES" -maxdepth 1 -name '*.txt' | sort)
  CONFINE_ARGS=(); for t in "${SCEN_TRACES[@]}"; do CONFINE_ARGS+=(--trace "$t"); done
  python3 -m eval.baselines.confine_estimate --binaries "$BIN" "${CONFINE_ARGS[@]}" \
    --out "$RESULTS/confine.json" >/dev/null
  DES_SECCOMP=(); [ -f "$DOCKER_SECCOMP" ] && DES_SECCOMP=(--docker-seccomp "$DOCKER_SECCOMP")
  python3 -m eval.baselines.desfam_estimate --binaries "$BIN" "${DES_SECCOMP[@]}" \
    --benign "$BASE/benign-*.txt" "${CONFINE_ARGS[@]}" --out "$RESULTS/desfam.json" >/dev/null
  CONF="--confine $RESULTS/confine.json --desfam $RESULTS/desfam.json"
else
  echo "TRACE=0: skipping the estimators; the tables will show PROVBIND and Falco only"
  CONF=""
fi

step "6. build the tables"
python3 -m eval.baselines.aggregate --run "$PROVBIND_RUN" $CONF --write
make --no-print-directory compare
python3 -m eval.baselines.alert_latency --run "$PROVBIND_RUN" --offline --out "$RESULTS/latency.json"

echo
echo "comparison run done:"
echo "  $RESULTS/COMPARISON.md   four-system tables"
echo "  $RESULTS/SCORING.md      PROVBIND vs Falco scoring matrix"
echo "  $RESULTS/confine.json $RESULTS/desfam.json $RESULTS/latency.json"
