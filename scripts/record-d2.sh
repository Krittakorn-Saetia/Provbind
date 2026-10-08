#!/usr/bin/env bash
# ML-B's dataset D2 for the demo image, recorded the way the comparison run sees the app, then the model
# (ml/data/mlb/README.md, Test Plan §5). Runs on the demo VM, unattended, in the run folder the
# comparison will use next, so the model ends up beside that run's envelope:
#   DEMO_REF=<registry>/demo-app@sha256:<hex> scripts/record-d2.sh
# With the optimised policies (the model must be trained on the event stream it will score), into the run
# folder the final comparison will use:
#   POLICY_SET=opt PROVBIND_RUN=./run-final DEMO_REF=... scripts/record-d2.sh
#
# 1. starts the controller; deploys the demo app exactly as scripts/comparison-run.sh does (same
#    Tetragon policies, same /data volume), and waits for its envelope;
# 2. records Tetragon while `make loadgen` runs TRAIN_SECONDS (default 7 h: at about 53 windows an
#    hour, that gives the 360 windows Test Plan §12.2 asks for), then builds the windows and the 70/30
#    split into ml/data/mlb/<hex>/;
# 3. waits GAP_SECONDS (default 1 h, MLB-04), records HELDOUT_SECONDS more (default 1 h) as heldout.jsonl;
# 4. trains the model (written to $PROVBIND_RUN/envelopes/<hex>.mlb/model.json) and prints MLB-04's
#    held-out false-positive rate;
# 5. deletes the demo deployment, so the comparison run starts a fresh pod (its start-up trace needs one).
# Keep the pod free of any other activity while it runs (no kubectl exec, no scenarios).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

: "${PROVBIND_RUN:=./run}"; export PROVBIND_RUN
: "${NAMESPACE:=demo}"; export NAMESPACE
: "${DEPLOY:=demo-app}"; export DEPLOY
: "${DEMO_REF:?set DEMO_REF to the signed ref@digest that make demo-app printed}"
: "${PROVBIND_KEY:=pipeline/keys/cosign.pub}"
: "${TETRAGON_CONTAINER:=export-stdout}"
: "${POLICY_SET:=orig}"     # orig = node/tetragon/*.yaml; opt = node/tetragon/opt/: record with the set the comparison will run
PDIR=node/tetragon; OTHER=node/tetragon/opt
if [ "$POLICY_SET" = opt ]; then PDIR=node/tetragon/opt; OTHER=node/tetragon; fi
: "${POLICIES:=$PDIR/write.yaml $PDIR/truncate.yaml $PDIR/cap.yaml $PDIR/load.yaml $PDIR/connect.yaml}"
: "${EGRESS:=testbed/egress.json}"
: "${TRAIN_SECONDS:=25200}"
: "${GAP_SECONDS:=3600}"
: "${HELDOUT_SECONDS:=3600}"
: "${WAIT_S:=120}"

HEX="${DEMO_REF##*@sha256:}"
D2="$PROVBIND_RUN/d2"
# the optimised set's windows go beside the original ones, not over them
if [ "$POLICY_SET" = opt ]; then : "${DATA:=ml/data/mlb/$HEX-opt}"; else : "${DATA:=ml/data/mlb/$HEX}"; fi
LOGS="$PROVBIND_RUN/logs-d2"
mkdir -p "$D2" "$DATA" "$LOGS"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
step() { echo; echo "=== $(date -u +%H:%M:%S) $*"; }

record() {   # OUTFILE SECONDS : Tetragon to OUTFILE while the benign load runs
  local out="$1" secs="$2" rec
  kubectl logs -n kube-system ds/tetragon -c "$TETRAGON_CONTAINER" -f --tail=0 > "$out" 2>>"$LOGS/tetragon.log" &
  rec=$!
  sleep 3
  DURATION="$secs" make --no-print-directory loadgen
  sleep 35                                    # let the last 30 s windows close
  kill "$rec" 2>/dev/null || true; wait "$rec" 2>/dev/null || true
  echo "record-d2: $(wc -l < "$out") Tetragon events in $out"
}
windows() {  # RECORDING OUTFILE
  python3 -m node.mlb windows --run "$PROVBIND_RUN" --replay "$1" --digest "sha256:$HEX" \
    ${EGRESS:+--egress "$EGRESS"} --out "$2"
  echo "record-d2: $(wc -l < "$2") windows in $2"
}

step "0. policies ($POLICY_SET), controller, demo app (as the comparison run deploys it)"
for f in write truncate cap load connect; do kubectl delete -f "$OTHER/$f.yaml" --ignore-not-found >/dev/null 2>&1 || true; done
for policy in $POLICIES; do kubectl apply -f "$policy" >/dev/null; done
python3 -m controller.watch --run "$PROVBIND_RUN" --namespace "$NAMESPACE" --key "$PROVBIND_KEY" \
  > "$LOGS/controller.out" 2> "$LOGS/controller.log" & PIDS+=($!)
sleep 3
kubectl -n "$NAMESPACE" create deployment "$DEPLOY" --image="$DEMO_REF" --port=8080 \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NAMESPACE" patch deployment "$DEPLOY" --patch-file testbed/demo-app/volume-patch.yaml >/dev/null
# A fresh pod, started while Tetragon runs: Tetragon reports only processes it saw start (7 October 2026).
kubectl -n "$NAMESPACE" rollout restart "deploy/$DEPLOY" >/dev/null
kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOY" --timeout="${WAIT_S}s"
( source testbed/scenarios/lib.sh; ENVELOPE_TIMEOUT="$WAIT_S" wait_for_envelope )
for _ in $(seq 1 45); do
  [ "$(kubectl -n "$NAMESPACE" get pods --no-headers 2>/dev/null | grep -c "^$DEPLOY-")" -le 1 ] && break
  sleep 2
done
if ! scripts/probe-events.sh > "$LOGS/probe.log" 2>&1; then
  echo "record-d2: Tetragon does not report the demo app's own process (see $LOGS/probe.log); restart" >&2
  echo "  Tetragon, wait a minute, restart the app, then run this again" >&2
  exit 1
fi
echo "  Tetragon reports the app's own process: $(grep RESULT "$LOGS/probe.log")"
sleep 30                                      # the pod's start-up activity settles first

step "1. first benign run: ${TRAIN_SECONDS}s of loadgen"
record "$D2/benign-1.jsonl" "$TRAIN_SECONDS"
windows "$D2/benign-1.jsonl" "$D2/benign-1.windows.jsonl"
python3 -m node.mlb split --windows "$D2/benign-1.windows.jsonl" --out-dir "$DATA"

step "2. gap of ${GAP_SECONDS}s, then the held-out run: ${HELDOUT_SECONDS}s"
sleep "$GAP_SECONDS"
record "$D2/benign-2.jsonl" "$HELDOUT_SECONDS"
windows "$D2/benign-2.jsonl" "$DATA/heldout.jsonl"

step "3. train and evaluate ML-B"
python3 -m node.mlb train --data "$DATA" --run "$PROVBIND_RUN" --digest "sha256:$HEX" | tee "$D2/train.json"
python3 -m node.mlb evaluate --data "$DATA" --run "$PROVBIND_RUN" --digest "sha256:$HEX" | tee "$D2/evaluate.json"

step "4. delete the demo deployment (the comparison run deploys a fresh pod)"
kubectl -n "$NAMESPACE" delete deployment "$DEPLOY" --wait=true >/dev/null || true
echo "record-d2 done: windows in $DATA, model in $PROVBIND_RUN/envelopes/$HEX.mlb/model.json"
