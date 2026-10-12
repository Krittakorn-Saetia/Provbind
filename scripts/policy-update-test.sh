#!/usr/bin/env bash
# Her et al.'s policy enforcement benchmark [F] (IEEE Access 2025, Section V-C; enforcement_benchmark in
# their public ESST-eval repository): how long a new policy takes to act, for Falco and for PROVBIND.
# Runs on the demo VM after `make up`, about 30 minutes with the defaults (REPS=10, their count):
#   DEMO_REF=<registry>/demo-app@sha256:<hex> scripts/policy-update-test.sh
#
# Falco, as Her et al. measure it: start a timer, `helm upgrade` the Falco release with one extra rule that
# fires when /usr/bin/ls runs in the demo namespace, and poll the Falco pods' logs until that rule's output
# appears, while a loop in the demo pod runs ls every millisecond. Falco restarts its pods to load the rule.
# After every run the release is rolled back to its original revision (and at exit, whatever happened).
#
# PROVBIND: a new workload's policy is its envelope, compiled from the signed evidence when the pod is
# admitted. Each run scales the demo app to 0, starts PROVBIND's controller and node in a fresh run folder
# (nothing cached), scales the app back up, waits for envelope_ready, and stops the node, whose summary gives
# the cold-start window: from the new pod's first event, which the node holds, until its envelope is in force
# and the held events are checked. Tetragon runs with PROVBIND's policies (POLICY_SET, default opt).
#
# Report: $OUT/results/POLICY-UPDATE.md, beside Her et al.'s published times (eval/policy_update.py).
# SYSTEMS="falco" or "provbind" runs one part. Nothing here is an attack. Do not type in the terminal or
# run kubectl exec while it runs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

: "${DEMO_REF:?set DEMO_REF to the demo image ref@digest (the one the comparison ran)}"
: "${NAMESPACE:=demo}"
: "${DEPLOY:=demo-app}"
: "${PROVBIND_KEY:=pipeline/keys/cosign.pub}"
: "${TETRAGON_CONTAINER:=export-stdout}"
: "${POLICY_SET:=opt}"                      # the final configuration's policies (node/tetragon/opt/)
PDIR=node/tetragon; [ "$POLICY_SET" = opt ] && PDIR=node/tetragon/opt
: "${POLICIES:=$PDIR/write.yaml $PDIR/truncate.yaml $PDIR/cap.yaml $PDIR/load.yaml $PDIR/connect.yaml}"
: "${EGRESS:=testbed/egress.json}"
: "${REPS:=10}"
: "${SYSTEMS:=falco provbind}"
: "${OUT:=./run-policy}"
: "${TIMEOUT_S:=300}"
RES="$OUT/results"; LOGS="$OUT/logs"; ROWS="$RES/policy.jsonl"

if [ -e "$ROWS" ]; then
  echo "policy-update-test: $ROWS exists; move $OUT aside first" >&2; exit 1
fi
mkdir -p "$RES" "$LOGS"
step() { echo; echo "=== $(date -u +%H:%M:%S) $*"; }
now() { date +%s.%N; }
elapsed() { python3 -c "import sys; print(round(float(sys.argv[2]) - float(sys.argv[1]), 3))" "$1" "$2"; }
want() { case " $SYSTEMS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
REPLICAS0=$(kubectl -n "$NAMESPACE" get deploy "$DEPLOY" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo 1)
[ -n "$REPLICAS0" ] && [ "$REPLICAS0" != 0 ] || REPLICAS0=1

ds_on() {     # NS DS : schedule the DaemonSet again in case an interrupted overhead run left it off
  kubectl -n "$1" patch ds "$2" --type merge \
    -p '{"spec":{"template":{"spec":{"nodeSelector":{"provbind-overhead":null}}}}}' >/dev/null
  kubectl -n "$1" rollout status "ds/$2" --timeout=300s >/dev/null
}
REPEATER_PID=""
repeater_start() {   # SECONDS : ls every millisecond in the demo pod; the loop ends by itself after SECONDS
  kubectl -n "$NAMESPACE" exec "deploy/$DEPLOY" -- sh -c \
    "end=\$((\$(date +%s) + $1)); while [ \$(date +%s) -lt \$end ]; do /usr/bin/ls -l / >/dev/null; sleep 0.001; done" \
    >/dev/null 2>&1 &
  REPEATER_PID=$!
}
repeater_stop() {
  if [ -n "$REPEATER_PID" ]; then kill "$REPEATER_PID" 2>/dev/null || true; fi
  REPEATER_PID=""
}
PIDS=()
provbind_stop() {
  for p in "${PIDS[@]:-}"; do if [ -n "$p" ]; then kill "$p" 2>/dev/null || true; fi; done
  PIDS=()
  pkill -f "node.run --run $OUT/provbind-" 2>/dev/null || true
  pkill -f "controller.watch --run $OUT/provbind-" 2>/dev/null || true
  pkill -f "kubectl logs -n kube-system ds/tetragon -c $TETRAGON_CONTAINER -f --tail=0" 2>/dev/null || true
  sleep 1
}
FALCO_REV0=""
cleanup() {
  repeater_stop
  provbind_stop
  if [ -n "$FALCO_REV0" ]; then
    helm rollback falco "$FALCO_REV0" -n falco --wait --timeout 5m >> "$LOGS/helm.log" 2>&1 \
      || echo "policy-update-test: could not roll Falco back; run: helm rollback falco $FALCO_REV0 -n falco" >&2
  fi
  kubectl -n "$NAMESPACE" scale "deploy/$DEPLOY" --replicas="$REPLICAS0" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- Falco ------------------------------------------------------------------------------------------
if want falco; then
  step "Falco: helm upgrade with one new rule, until the rule fires (x$REPS)"
  ds_on falco falco
  cat > "$OUT/falco-probe-rule.yaml" <<EOF
customRules:
  provbind-policy-probe.yaml: |-
    - rule: PROVBIND policy-update probe
      desc: Her et al.'s policy enforcement benchmark, ls run in the ${NAMESPACE} namespace
      condition: evt.type in (execve, execveat) and evt.dir = < and container.id != host and k8s.ns.name = "${NAMESPACE}" and proc.exepath = "/usr/bin/ls"
      output: "PROVBIND-POLICY-PROBE ls in the ${NAMESPACE} namespace (cmdline=%proc.cmdline pod=%k8s.pod.name)"
      priority: WARNING
      tags: [provbind_probe]
EOF
  FALCO_REV0=$(helm history falco -n falco -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)[-1]["revision"])')
  CHART_VER=$(helm list -n falco -o json | python3 -c \
    'import json,sys; print([r for r in json.load(sys.stdin) if r["name"] == "falco"][0]["chart"].rsplit("-", 1)[1])')
  echo "  release falco at revision $FALCO_REV0 (chart $CHART_VER); rolled back to it after every run"
  for k in $(seq 1 "$REPS"); do
    repeater_start $((TIMEOUT_S + 60))
    sleep 2
    t0=$(now)
    helm upgrade falco falcosecurity/falco -n falco --version "$CHART_VER" --reuse-values \
      -f "$OUT/falco-probe-rule.yaml" >> "$LOGS/helm.log" 2>&1
    secs=""
    while [ -z "$secs" ]; do
      for pod in $(kubectl -n falco get pods -l app.kubernetes.io/name=falco \
                     -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        logs=$(kubectl -n falco logs "$pod" -c falco 2>/dev/null || true)
        case "$logs" in *PROVBIND-POLICY-PROBE*) secs=$(elapsed "$t0" "$(now)"); break ;; esac
      done
      [ -n "$secs" ] && break
      [ "$(elapsed "$t0" "$(now)" | cut -d. -f1)" -ge "$TIMEOUT_S" ] && break
      sleep 0.2
    done
    repeater_stop
    python3 -m eval.policy_update falco-row --rep "$k" --seconds "${secs:-timeout}" --out "$ROWS"
    helm rollback falco "$FALCO_REV0" -n falco --wait --timeout 5m >> "$LOGS/helm.log" 2>&1
    kubectl -n falco rollout status ds/falco --timeout=300s >/dev/null
    sleep 5
  done
  FALCO_REV0=""                     # every run was rolled back already
fi

# --- PROVBIND ---------------------------------------------------------------------------------------
if want provbind; then
  step "PROVBIND: a new pod's envelope, compiled at admission, until it is in force (x$REPS)"
  OTHER=node/tetragon/opt; [ "$POLICY_SET" = opt ] && OTHER=node/tetragon
  for f in write truncate cap load connect; do kubectl delete -f "$OTHER/$f.yaml" --ignore-not-found >/dev/null 2>&1 || true; done
  for policy in $POLICIES; do kubectl apply -f "$policy" >/dev/null; done
  ds_on kube-system tetragon
  for k in $(seq 1 "$REPS"); do
    R="$OUT/provbind-$k"; mkdir -p "$R"
    kubectl -n "$NAMESPACE" scale "deploy/$DEPLOY" --replicas=0 >/dev/null
    kubectl -n "$NAMESPACE" wait --for=delete pod -l app="$DEPLOY" --timeout=180s >/dev/null 2>&1 || true
    python3 -m controller.watch --run "$R" --namespace "$NAMESPACE" --key "$PROVBIND_KEY" \
      > "$LOGS/controller-$k.out" 2> "$LOGS/controller-$k.log" & PIDS+=($!)
    ( kubectl logs -n kube-system ds/tetragon -c "$TETRAGON_CONTAINER" -f --tail=0 \
        | python3 -m node.run --run "$R" --summary "$R/node-summary.json" ${EGRESS:+--egress "$EGRESS"} ) \
      > "$LOGS/node-$k.out" 2> "$LOGS/node-$k.log" & PIDS+=($!)
    sleep 5
    t0=$(now)
    kubectl -n "$NAMESPACE" scale "deploy/$DEPLOY" --replicas=1 >/dev/null
    ready=""
    if ( export PROVBIND_RUN="$R" NAMESPACE POD_PREFIX="$DEPLOY" ENVELOPE_TIMEOUT="$TIMEOUT_S"
         source testbed/scenarios/lib.sh; wait_for_envelope ); then
      ready=$(elapsed "$t0" "$(now)")
    fi
    sleep 5                         # the node releases and checks the held events on its next tick
    pkill -TERM -f "node.run --run $R " 2>/dev/null || true
    for _ in $(seq 1 40); do [ -s "$R/node-summary.json" ] && break; sleep 0.5; done
    provbind_stop
    python3 -m eval.policy_update provbind-row --rep "$k" --summary "$R/node-summary.json" \
      --ready-s "${ready:-}" --out "$ROWS"
  done
  kubectl -n "$NAMESPACE" scale "deploy/$DEPLOY" --replicas="$REPLICAS0" >/dev/null
  kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOY" --timeout=180s >/dev/null || true
fi

step "report"
python3 -m eval.policy_update report --rows "$ROWS" --out "$RES"
echo "policy update test done: $RES/POLICY-UPDATE.md"
