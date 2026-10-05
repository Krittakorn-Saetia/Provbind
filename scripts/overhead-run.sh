#!/usr/bin/env bash
# The overhead test (supervisor's questions 3 and 4): what PROVBIND costs at runtime, against no
# monitoring and against Falco, and whether that cost stays under 20%. Runs on the demo VM after the
# comparison run, unattended, about 1.5 h with the defaults (REPS=3):
#   DEMO_REF=<registry>/demo-app@sha256:<hex> scripts/overhead-run.sh
#
# 0. PROVBIND's own cost from the comparison run's files (no new run): OH-01 per-event verification
#    latency (replays $PROVBIND_RUN/rec.jsonl), OH-04/OH-05 compile time and index memory; then each
#    system's measured preparation time for a new image (eval/prep_time.py): PROVBIND compiles the image
#    PREP_RUNS times cold, Confine-E's export and static analysis and DeSFAM-E's training are timed, their
#    start-up and profiling recordings come from the comparison run, Falco's restart is timed in step 1.
# 1. For each repetition, the four configurations in a shuffled order (eval/overhead.py):
#      none      Tetragon and Falco stopped (their DaemonSets scheduled nowhere)
#      falco     Falco only
#      tetragon  Tetragon with PROVBIND's policies, its output read and dropped (the sensor's share)
#      provbind  all of PROVBIND: Tetragon + policies, controller, node (--mlb, egress list), alerts, trust
#    and in each: a warm-up, then three workloads on the same demo pod:
#      mix    MIX_S seconds of the load generator's request mix from an in-cluster client (no port-forward)
#      cache  CACHE_S seconds of /cache only (every request writes a file: PROVBIND's write hook)
#      micro  FILE_OPS file writes and SPAWNS process starts inside the demo container (the worst case)
#    with the CPU and memory of every monitor sampled around them.
# 2. The report: $OUT_RUN/results/OVERHEAD.md (and .json), overhead against `none`, PROVBIND minus Falco,
#    the verdict against THRESHOLD (20%), and the cost beside the comparison run's accuracy.
# At the end both DaemonSets are scheduled again, whatever happened. Nothing here is an attack.
# Do not type in the terminal, run kubectl exec, or take a VM snapshot while it runs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

: "${PROVBIND_RUN:=./run}"                 # the comparison run: envelopes, ML-B model, rec.jsonl, COMPARISON.json
: "${OUT_RUN:=./run-overhead}"
: "${DEMO_REF:?set DEMO_REF to the demo image ref@digest (the one the comparison ran)}"
: "${NAMESPACE:=demo}"
: "${DEPLOY:=demo-app}"
: "${PROVBIND_KEY:=pipeline/keys/cosign.pub}"
: "${TETRAGON_CONTAINER:=export-stdout}"
: "${POLICY_SET:=orig}"                    # orig = node/tetragon/*.yaml; opt = node/tetragon/opt/*.yaml (rate-limited)
: "${EVENT_SOURCE:=kubectl}"               # kubectl = kubectl logs; file = read Tetragon's export file in the kind node
: "${KIND_NODE:=kind-control-plane}"
: "${TETRAGON_LOG:=/var/run/cilium/tetragon/tetragon.log}"
PDIR=node/tetragon; [ "$POLICY_SET" = opt ] && PDIR=node/tetragon/opt
: "${POLICIES:=$PDIR/write.yaml $PDIR/truncate.yaml $PDIR/cap.yaml $PDIR/load.yaml $PDIR/connect.yaml}"
: "${EGRESS:=testbed/egress.json}"
: "${REPS:=3}"
: "${MIX_S:=120}"
: "${CACHE_S:=60}"
: "${CONC:=4}"
: "${FILE_OPS:=20000}"
: "${SPAWNS:=500}"
: "${WARM_S:=20}"
: "${THRESHOLD:=20}"
: "${CONFIGS:=none falco tetragon provbind}"
: "${SKIP_PREP:=0}"                         # 1 = skip steps 0, 0b, 0c (an ablation run reuses them)
: "${NODE_MLB:=1}"                          # 0 = the provbind configuration's node runs without ML-B
: "${PREP_RUNS:=5}"                         # cold compiles of the image for PROVBIND's preparation time
LOADNS=provbind-load
RES="$OUT_RUN/results"; LOGS="$OUT_RUN/logs"; ROWS="$RES/overhead.jsonl"
URL="http://$DEPLOY.$NAMESPACE.svc.cluster.local:8080"

if [ -e "$ROWS" ]; then
  echo "overhead-run: $ROWS exists; move $OUT_RUN aside first" >&2; exit 1
fi
mkdir -p "$RES" "$LOGS"
step() { echo; echo "=== $(date -u +%H:%M:%S) $*"; }
PIDS=()

# --- switching the monitors -----------------------------------------------------------------------
ds_pods() {   # NS DS : running pods of the DaemonSet (not its operator)
  kubectl -n "$1" get pods -o name 2>/dev/null | grep -E "^pod/$2-[a-z0-9]{5}$" || true
}
ds_off() {    # NS DS
  kubectl -n "$1" patch ds "$2" --type merge \
    -p '{"spec":{"template":{"spec":{"nodeSelector":{"provbind-overhead":"off"}}}}}' >/dev/null
  for _ in $(seq 1 90); do [ -z "$(ds_pods "$1" "$2")" ] && return 0; sleep 2; done
  echo "overhead-run: $2 did not stop" >&2; return 1
}
FALCO_READY=()
ds_on() {     # NS DS : schedule it again; when it was off, time how long it takes to be ready
  local was_off t0
  [ -z "$(ds_pods "$1" "$2")" ] && was_off=1 || was_off=0
  t0=$(date +%s.%N)
  kubectl -n "$1" patch ds "$2" --type merge \
    -p '{"spec":{"template":{"spec":{"nodeSelector":{"provbind-overhead":null}}}}}' >/dev/null
  kubectl -n "$1" rollout status "ds/$2" --timeout=300s >/dev/null
  if [ "$was_off" = 1 ] && [ "$2" = falco ]; then
    FALCO_READY+=("$(python3 -c "import sys; print(round(float(sys.argv[2]) - float(sys.argv[1]), 3))" "$t0" "$(date +%s.%N)")")
  fi
}
provbind_stop() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  PIDS=()
  pkill -f "node.run --run $OUT_RUN" 2>/dev/null || true
  pkill -f "kubectl logs -n kube-system ds/tetragon" 2>/dev/null || true
  pkill -f "tail -n 0 -F $TETRAGON_LOG" 2>/dev/null || true
  sleep 2
}
swap_policy_set() {   # SET : load one policy set and remove the other (both at once would double every event)
  local keep=node/tetragon drop=node/tetragon/opt
  [ "$1" = opt ] && keep=node/tetragon/opt && drop=node/tetragon
  for f in write truncate cap load connect; do kubectl delete -f "$drop/$f.yaml" --ignore-not-found >/dev/null 2>&1 || true; done
}
events() {    # Tetragon's event stream, from kubectl logs or straight from the export file in the kind node
  if [ "$EVENT_SOURCE" = file ]; then
    docker exec "$KIND_NODE" tail -n 0 -F "$TETRAGON_LOG"
  else
    kubectl logs -n kube-system ds/tetragon -c "$TETRAGON_CONTAINER" -f --tail=0
  fi
}
restore() {
  provbind_stop
  if [ "$POLICY_SET" = opt ] && [ "${KEEP_POLICY_SET:-0}" != 1 ]; then   # leave the original policies in place
    swap_policy_set orig
    for f in write truncate cap load connect; do kubectl apply -f "node/tetragon/$f.yaml" >/dev/null 2>&1 || true; done
  fi
  ds_on kube-system tetragon || true
  ds_on falco falco || true
}
trap restore EXIT

configure() { # CONFIG
  provbind_stop
  case "$1" in
    none)     ds_off kube-system tetragon; ds_off falco falco ;;
    falco)    ds_off kube-system tetragon; ds_on falco falco ;;
    tetragon) ds_off falco falco; ds_on kube-system tetragon
              ( events > /dev/null ) &
              PIDS+=($!) ;;
    provbind) ds_off falco falco; ds_on kube-system tetragon
              python3 -m controller.watch --run "$OUT_RUN" --namespace "$NAMESPACE" --key "$PROVBIND_KEY" \
                >> "$LOGS/controller.out" 2>> "$LOGS/controller.log" & PIDS+=($!)
              ( events \
                  | python3 -m node.run --run "$OUT_RUN" $([ "$NODE_MLB" = 1 ] && echo --mlb) ${EGRESS:+--egress "$EGRESS"} ) \
                >> "$LOGS/node.out" 2>> "$LOGS/node.log" & PIDS+=($!)
              python3 -m alerts.run --run "$OUT_RUN" >> "$LOGS/alerts.out" 2>> "$LOGS/alerts.log" & PIDS+=($!)
              python3 -m alerts.trust --run "$OUT_RUN" --poll 2 >> "$LOGS/trust.out" 2>> "$LOGS/trust.log" & PIDS+=($!) ;;
  esac
  sleep "$WARM_S"
}

client() {    # SECONDS MIX
  kubectl -n "$LOADNS" exec -i loadgen -- python3 - "$URL" "$1" "$CONC" "$2" < eval/overhead_client.py
}
micro() {
  kubectl -n "$NAMESPACE" exec -i "deploy/$DEPLOY" -- python3 - "$FILE_OPS" "$SPAWNS" < eval/overhead_micro.py
}

if [ "$SKIP_PREP" != 1 ]; then
# --- 0. PROVBIND's own cost from the comparison run's files ----------------------------------------
step "0. OH-01 (per-event verification), OH-04/OH-05 (compile, index) from $PROVBIND_RUN"
if [ -f "$PROVBIND_RUN/rec.jsonl" ]; then
  PROVBIND_RUN="$PROVBIND_RUN" PROVBIND_RECORDING="$PROVBIND_RUN/rec.jsonl" \
    python3 -m pytest -q -p no:cacheprovider tests/capability/test_oh_node_cost.py -k oh_01 >/dev/null 2>&1 || true
fi
PROVBIND_RUN="$PROVBIND_RUN" python3 -m pytest -q -p no:cacheprovider tests/capability/test_ph3_12_oh_04_05_cost.py \
  >/dev/null 2>&1 || true
for f in OH-01 OH-04 OH-05 PH3-12; do
  [ -f "$PROVBIND_RUN/results/$f.json" ] && cp "$PROVBIND_RUN/results/$f.json" "$RES/" && echo "  $f recorded"
done

step "0b. preparation time per system, measured (PROVBIND x$PREP_RUNS cold compiles, Confine-E, DeSFAM-E)"
PREP="$RES/prep.jsonl"
mkdir -p "$OUT_RUN/prep-work"
python3 -m eval.prep_time provbind --ref "$DEMO_REF" --runs "$PREP_RUNS" --work "$OUT_RUN/prep-work" \
  --key "$PROVBIND_KEY" --out "$PREP" || echo "  PROVBIND compile timing failed (see above)"
BASE="$PROVBIND_RUN/traces/baseline"
t0=$(date +%s.%N)
eval/baselines/export_binaries.sh --run "$PROVBIND_RUN" --namespace "$NAMESPACE" --deploy "$DEPLOY" \
  --digest "${DEMO_REF##*@}" --out "$OUT_RUN/prep-binaries" --startup-trace "$BASE/startup.txt" \
  && EXPORT_S=$(python3 -c "import sys; print(round(float(sys.argv[2]) - float(sys.argv[1]), 3))" "$t0" "$(date +%s.%N)") \
  || echo "  exporting the binaries failed"
# Which packages own the analysed ELF files (dpkg in the demo container; a source-built runtime such as
# the image's Python under /usr/local belongs to no package and is counted apart).
OWN=$(ls "$OUT_RUN/prep-binaries" 2>/dev/null | sed 's|%|/|g' | kubectl -n "$NAMESPACE" exec -i "deploy/$DEPLOY" -- sh -c \
  'while read p; do q=$(dpkg -S "$p" 2>/dev/null | head -1); [ -n "$q" ] || q=$(dpkg -S "${p#/usr}" 2>/dev/null | head -1);
   if [ -n "$q" ]; then echo "PKG ${q%%:*}"; else echo NONE; fi; done' 2>/dev/null || true)
PKGS=$( { printf '%s\n' "$OWN" | grep '^PKG' || true; } | sort -u | wc -l)
UNOWNED=$(printf '%s\n' "$OWN" | grep -c '^NONE' || true)
echo "  analysed ELF files come from $PKGS packages (+$UNOWNED files outside any package)"
python3 -m eval.prep_time confine --binaries "$OUT_RUN/prep-binaries" --startup "$BASE/startup.txt" \
  --export-s "${EXPORT_S:-0}" --packages "$PKGS" --unowned "$UNOWNED" --out "$PREP" \
  || echo "  Confine-E timing failed"
python3 -m eval.prep_time mlb --log "$PROVBIND_RUN/record-d2.log" --data "ml/data/mlb/${DEMO_REF##*@sha256:}" \
  --work "$OUT_RUN/prep-work" --out "$PREP" || echo "  ML-B timing failed"
REQS=$(grep -oE "loadgen: [0-9]+ requests in 600s" "$PROVBIND_RUN/comparison-run.log" 2>/dev/null | head -3 \
       | awk '{s += $2} END {print s + 0}')
python3 -m eval.prep_time desfam --binaries "$OUT_RUN/prep-binaries" --benign "$BASE/benign-*.txt" \
  --requests "${REQS:-0}" --packages "$PKGS" --unowned "$UNOWNED" --out "$PREP" || echo "  DeSFAM-E timing failed"

step "0c. zero-day validity checks on the comparison run (eval/zero_day_check.py)"
python3 -m eval.zero_day_check --run "$PROVBIND_RUN" --mlb-data "ml/data/mlb/${DEMO_REF##*@sha256:}" \
  --egress "$EGRESS" || echo "  a zero-day check FAILED: see $PROVBIND_RUN/results/ZERODAY.md"
cp "$PROVBIND_RUN/results/ZERODAY.md" "$RES/" 2>/dev/null || true

fi   # SKIP_PREP

# --- setup: the same demo pod, a Service for it, an in-cluster load client --------------------------
step "setup: policies ($POLICY_SET), events from $EVENT_SOURCE, demo app, Service, load pod; ML-B model and envelopes from $PROVBIND_RUN"
swap_policy_set "$POLICY_SET"
for policy in $POLICIES; do kubectl apply -f "$policy" >/dev/null; done
mkdir -p "$OUT_RUN/envelopes"
cp -r "$PROVBIND_RUN/envelopes/." "$OUT_RUN/envelopes/"
if ! kubectl -n "$NAMESPACE" get deploy "$DEPLOY" >/dev/null 2>&1; then
  kubectl -n "$NAMESPACE" create deployment "$DEPLOY" --image="$DEMO_REF" --port=8080 >/dev/null
  kubectl -n "$NAMESPACE" patch deployment "$DEPLOY" --patch-file testbed/demo-app/volume-patch.yaml >/dev/null
fi
kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOY" --timeout=180s >/dev/null
kubectl -n "$NAMESPACE" get svc "$DEPLOY" >/dev/null 2>&1 \
  || kubectl -n "$NAMESPACE" expose deployment "$DEPLOY" --port 8080 >/dev/null
kubectl get ns "$LOADNS" >/dev/null 2>&1 || kubectl create ns "$LOADNS" >/dev/null
kubectl -n "$LOADNS" get pod loadgen >/dev/null 2>&1 \
  || kubectl -n "$LOADNS" run loadgen --image="$DEMO_REF" --restart=Never --command -- sleep infinity >/dev/null
kubectl -n "$LOADNS" wait --for=condition=Ready pod/loadgen --timeout=180s >/dev/null
client 5 mix > "$LOGS/connectivity.json" && echo "  client reaches $URL: $(cat "$LOGS/connectivity.json")"

# --- 1. the measurements ------------------------------------------------------------------------------
for rep in $(seq 1 "$REPS"); do
  order=$(python3 -c "import random,sys; c=sys.argv[2:]; random.Random(int(sys.argv[1])).shuffle(c); print(' '.join(c))" \
          "$rep" $CONFIGS)
  for cfg in $order; do
    step "rep $rep/$REPS: $cfg"
    configure "$cfg"
    client 10 mix > /dev/null || true                                   # warm the path, discarded
    python3 -m eval.overhead sample > "$LOGS/before.json"
    # A failed workload is recorded without numbers and the run goes on (the report skips it).
    { client "$MIX_S" mix || true; }      | python3 -m eval.overhead record --out "$ROWS" --config "$cfg" --rep "$rep" --kind mix
    { client "$CACHE_S" /cache || true; } | python3 -m eval.overhead record --out "$ROWS" --config "$cfg" --rep "$rep" --kind cache
    { micro || true; }                    | python3 -m eval.overhead record --out "$ROWS" --config "$cfg" --rep "$rep" --kind micro
    python3 -m eval.overhead sample > "$LOGS/after.json"
    python3 -m eval.overhead cpu --before "$LOGS/before.json" --after "$LOGS/after.json" \
      | python3 -m eval.overhead record --out "$ROWS" --config "$cfg" --rep "$rep" --kind cpu
    tail -n 4 "$ROWS" | python3 -c "import sys,json
for l in sys.stdin:
    d=json.loads(l); print('  ', d['kind'], {k: d[k] for k in ('p50_ms','p95_ms','rps','file_op_us','spawn_ms','monitor_cpu_pct') if k in d})"
  done
done

# --- 2. the report ----------------------------------------------------------------------------------
step "2. report"
restore
trap - EXIT
if [ "$SKIP_PREP" != 1 ]; then
  python3 -m eval.prep_time falco --ready-s "${FALCO_READY[@]}" --out "$PREP"
  python3 -m eval.prep_time report --prep "$PREP" --out "$RES"
  cp "$RES/PREP.json" "$PROVBIND_RUN/results/" 2>/dev/null || true    # figure 1 reads it from the run folder
fi
python3 -m eval.overhead report --dir "$RES" --threshold "$THRESHOLD" \
  --comparison "$PROVBIND_RUN/results/COMPARISON.json" --oh01 "$RES/OH-01.json"
kubectl -n "$LOADNS" delete pod loadgen --wait=false >/dev/null 2>&1 || true
echo "overhead run done: $RES/OVERHEAD.md, $RES/PREP.md and $RES/ZERODAY.md"
