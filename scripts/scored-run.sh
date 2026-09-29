#!/usr/bin/env bash
# The balanced scored run (Role 1): ROUNDS rounds of two malicious and two benign scenarios, then
# tamper-1 once, then the comparison and the report. Runs on the demo PC after `make up` and
# `make demo-app`, in a FRESH run folder (move the old one aside first).
#   DEMO_REF=<registry>/demo-app@sha256:<hex> make scored            # ROUNDS=3 by default
#
# Each round: benign-1, attack-1, trust-1 (then its advisory is removed again), ph4-14.
# 3 rounds give 6 malicious and 6 benign runs, each scenario 3 times (Test Plan §12.2, D4).
# attack-2 is left out: it needs an ML-B model (make demo's MLB=--mlb), which this run has not trained.
#
# Like scripts/demo.sh, it starts the controller, the node (fed by Tetragon), the alert engine, the
# trust loop and the Falco capture in the background (logs in $PROVBIND_RUN/logs/) and stops them on
# exit. Do not type into the terminal, run kubectl exec in the demo pod, or take a VM snapshot while
# it runs: a snapshot pauses the VM and shifts Falco's clock (restart Falco afterwards).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

: "${PROVBIND_RUN:=./run}"; export PROVBIND_RUN
: "${NAMESPACE:=demo}"; export NAMESPACE
: "${DEPLOY:=demo-app}"; export DEPLOY
: "${DEMO_REF:?set DEMO_REF to the ref@digest that make demo-app printed}"
: "${PROVBIND_KEY:=pipeline/keys/cosign.pub}"
: "${TETRAGON_CONTAINER:=export-stdout}"
: "${POLICIES:=node/tetragon/write.yaml node/tetragon/truncate.yaml node/tetragon/cap.yaml}"
: "${ROUNDS:=3}"
: "${GAP:=10}"          # seconds between scenarios, so no window catches the previous one's tail
: "${WAIT_S:=120}"

if [ -e "$PROVBIND_RUN/ground_truth.csv" ]; then
  echo "scored-run: $PROVBIND_RUN already has a ground_truth.csv; move it aside (mv run run-old) first" >&2
  exit 1
fi

LOGS="$PROVBIND_RUN/logs"
mkdir -p "$LOGS"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
step() { echo; echo "=== $(date -u +%H:%M:%S) $*"; }

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

step "1. deploy the signed demo app by digest; wait for envelope_ready"
kubectl -n "$NAMESPACE" create deployment "$DEPLOY" --image="$DEMO_REF" --port=8080 \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOY" --timeout="${WAIT_S}s"
( source testbed/scenarios/lib.sh; ENVELOPE_TIMEOUT="$WAIT_S" wait_for_envelope )
python3 -m alerts.attribute --run "$PROVBIND_RUN" >/dev/null \
  || echo "Neo4j is not reachable: attribution uses the envelope's layer field"
sleep 30                # let the pod's start-up activity (kind's hooks, imports) settle before round 1

for round in $(seq 1 "$ROUNDS"); do
  step "round $round/$ROUNDS: benign-1";  make --no-print-directory benign;  sleep "$GAP"
  step "round $round/$ROUNDS: attack-1";  make --no-print-directory attack;  sleep "$GAP"
  step "round $round/$ROUNDS: trust-1";   make --no-print-directory trust
  RESTORE=1 make --no-print-directory trust; sleep "$GAP"      # trust restored before the next run
  step "round $round/$ROUNDS: ph4-14";    make --no-print-directory ph4-14;  sleep "$GAP"
done

step "tamper-1 (once, last: it breaks the log for every later record)"
python3 -m alerts.verify_log --run "$PROVBIND_RUN" && echo "verify_log passed before the edit"
make --no-print-directory tamper
python3 -m alerts.verify_log --run "$PROVBIND_RUN" && echo "UNEXPECTED: verify_log still passes" \
  || echo "verify_log failed after the edit, as expected"
echo "(the untampered log is at $PROVBIND_RUN/log/violations.jsonl.orig)"

step "compare and report"
make --no-print-directory compare
make --no-print-directory report
echo
echo "scored run done: $PROVBIND_RUN/results/SCORING.md, $PROVBIND_RUN/results/REPORT.md"
