#!/usr/bin/env bash
# The Sprint Handoff §1.1 demo, in order, with waits between steps (Role 4's `make demo`).
#
# Runs on the demo PC after `make up` and `make demo-app`, with every role's code merged.
#   DEMO_REF=<registry>/demo-app@sha256:<hex> make demo      # the reference `make demo-app` printed
#
# It starts the controller, Role 3's node (fed by Tetragon), the alert engine, the trust loop and the
# Falco capture in the background (logs in $PROVBIND_RUN/logs/), then:
#   1. deploys the demo app by digest and waits for envelope_ready;
#   2. benign-1 (make benign): expects two Lows;
#   3. attack-1 (make attack): expects D_exec undeclared (90) and D_write (72) in one chain;
#   4. attack-2 (make attack2), only with MLB=--mlb and an ML-B model beside the envelope: expects D_beh;
#   5. trust-1 (make trust): expects one trust alert naming comp;
#   6. verify_log passes, tamper-1 (make tamper) edits one character, verify_log fails at that record;
#   7. make compare and make report.
# The "done when" checks of Sprint Handoff §8 are printed at the end; the exit status is 0 only if
# they all hold. Background processes are stopped on exit.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

: "${PROVBIND_RUN:=./run}"; export PROVBIND_RUN
: "${NAMESPACE:=demo}"; export NAMESPACE
: "${DEPLOY:=demo-app}"; export DEPLOY
: "${DEMO_REF:?set DEMO_REF to the ref@digest that make demo-app printed}"
: "${PROVBIND_KEY:=pipeline/keys/cosign.pub}"
: "${TETRAGON_CONTAINER:=export-stdout}"
: "${POLICIES:=node/tetragon/write.yaml node/tetragon/truncate.yaml}"
: "${MLB:=}"
: "${WAIT_S:=120}"

LOGS="$PROVBIND_RUN/logs"
mkdir -p "$LOGS"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

step() { echo; echo "=== $*"; }

# alerts_count CLASS [SUBCLASS]: how many alerts of that class are in alerts.jsonl
alerts_count() {
  python3 - "$@" <<'PY'
import json, os, sys
cls, sub = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else None)
n = 0
try:
    for line in open(os.path.join(os.environ["PROVBIND_RUN"], "alerts.jsonl"), encoding="utf-8"):
        try:
            a = json.loads(line)
        except ValueError:
            continue
        n += a.get("class") == cls and (sub is None or a.get("subclass") == sub)
except OSError:
    pass
print(n)
PY
}

wait_alerts() {   # seconds minimum class [subclass]
  local deadline=$(( $(date +%s) + $1 )) want=$2; shift 2
  until [ "$(alerts_count "$@")" -ge "$want" ]; do
    if [ "$(date +%s)" -ge "$deadline" ]; then echo "demo: no $* alert after waiting" >&2; return 1; fi
    sleep 2
  done
}

step "0. background: controller, node, alerts, trust loop, Falco"
kubectl apply -f $POLICIES >/dev/null
python3 -m controller.watch --run "$PROVBIND_RUN" --namespace "$NAMESPACE" --key "$PROVBIND_KEY" \
  > "$LOGS/controller.out" 2> "$LOGS/controller.log" & PIDS+=($!)
( kubectl logs -n kube-system ds/tetragon -c "$TETRAGON_CONTAINER" -f --tail=0 \
    | tee "$PROVBIND_RUN/rec.jsonl" \
    | python3 -m node.run --run "$PROVBIND_RUN" $MLB ) > "$LOGS/node.out" 2> "$LOGS/node.log" & PIDS+=($!)
python3 -m alerts.run --run "$PROVBIND_RUN" > "$LOGS/alerts.out" 2> "$LOGS/alerts.log" & PIDS+=($!)
python3 -m alerts.trust --run "$PROVBIND_RUN" --poll 2 > "$LOGS/trust.out" 2> "$LOGS/trust.log" & PIDS+=($!)
./eval/capture_falco.sh > "$LOGS/falco.out" 2> "$LOGS/falco.log" & PIDS+=($!)
sleep 3

step "1. deploy the signed demo app by digest; wait for envelope_ready"
kubectl -n "$NAMESPACE" create deployment "$DEPLOY" --image="$DEMO_REF" --port=8080 \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOY" --timeout="${WAIT_S}s"
( source testbed/scenarios/lib.sh; ENVELOPE_TIMEOUT="$WAIT_S" wait_for_envelope )
python3 -m alerts.attribute --run "$PROVBIND_RUN" \
  || echo "Neo4j is not reachable: attribution uses the envelope's layer field (Sprint Handoff §10)"
echo "envelope: $PROVBIND_RUN/envelopes/${DEMO_REF##*sha256:}.json; layer graph: http://localhost:7474"

step "2. benign-1: kubectl exec ... sh -c 'ls /' (expect two Lows)"
make --no-print-directory benign
wait_alerts "$WAIT_S" 2 D_exec outside_closure || true

step "3. attack-1: /update (expect D_exec undeclared 90 and D_write 72, one chain)"
make --no-print-directory attack
wait_alerts "$WAIT_S" 1 D_exec undeclared || true
wait_alerts "$WAIT_S" 1 D_write || true

if [ -n "$MLB" ]; then
  step "4. attack-2: /update2 (expect one D_beh, Medium at most)"
  make --no-print-directory attack2
  wait_alerts "$WAIT_S" 1 D_beh || true
else
  step "4. attack-2 skipped: set MLB=--mlb with an ML-B model beside the envelope"
fi

step "5. trust-1: mark requestz-helper malicious (expect one trust alert naming comp)"
make --no-print-directory trust
wait_alerts "$WAIT_S" 1 trust || true

step "alerts"
python3 -m alerts.show --run "$PROVBIND_RUN"

step "6. tamper-1: verify_log passes, one character changes, verify_log fails"
if [ -n "${PROVBIND_LOG_KEY:-}" ]; then python3 -m alerts.log checkpoint --run "$PROVBIND_RUN" || true; fi
python3 -m alerts.verify_log --run "$PROVBIND_RUN" && LOG_OK_BEFORE=1 || LOG_OK_BEFORE=0
make --no-print-directory tamper
python3 -m alerts.verify_log --run "$PROVBIND_RUN" && LOG_FAILS_AFTER=0 || LOG_FAILS_AFTER=1
echo "(the untampered log is at $PROVBIND_RUN/log/violations.jsonl.orig)"

step "7. compare and report"
make --no-print-directory compare || true
make --no-print-directory report || true

step "done when (Sprint Handoff §8)"
LOG_OK_BEFORE=$LOG_OK_BEFORE LOG_FAILS_AFTER=$LOG_FAILS_AFTER python3 - <<'PY'
import json, os, sys
alerts = []
for line in open(os.path.join(os.environ["PROVBIND_RUN"], "alerts.jsonl"), encoding="utf-8"):
    try:
        alerts.append(json.loads(line))
    except ValueError:
        pass
x9 = [a for a in alerts if a.get("class") == "D_exec" and a.get("subclass") == "undeclared"]
wr = [a for a in alerts if a.get("class") == "D_write"]
lows = [a for a in alerts if a.get("class") == "D_exec" and a.get("subclass") == "outside_closure" and a.get("bucket") == "low"]
chain = bool(x9) and bool(wr) and any(a["chain_id"] == b["chain_id"] for a in x9 for b in wr)
checks = {
    "D_exec undeclared scores 90": any(a.get("score") == 90 for a in x9),
    "D_write scores 72": any(a.get("score") == 72 for a in wr),
    "both in one chain": chain,
    "two benign Lows": len(lows) >= 2,
    "a trust alert": any(a.get("class") == "trust" for a in alerts),
    "verify_log passed before the edit": os.environ["LOG_OK_BEFORE"] == "1",
    "verify_log failed after the edit": os.environ["LOG_FAILS_AFTER"] == "1",
}
for name, ok in checks.items():
    print(f"  [{'x' if ok else ' '}] {name}")
sys.exit(0 if all(checks.values()) else 1)
PY
