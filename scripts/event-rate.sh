#!/usr/bin/env bash
# Events per request under one policy set: a few-minute check before a 1.5 h overhead run. The overhead
# test's cost is roughly (events per request) x (cost of moving one event to PROVBIND), so a policy set whose
# requests cause no events can only cost what the kernel hooks themselves cost.
#   scripts/event-rate.sh opt      # or orig
# Applies that set (and removes the other), restarts the app so Tetragon sees its process start, checks with
# scripts/probe-events.sh, then sends GET / and GET /cache for SECONDS_PER_PHASE each through a port-forward
# and counts the app pod's events per hook (eval/event_rate.py). Counts only. Leaves the chosen set applied.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
SET="${1:-opt}"
: "${NAMESPACE:=demo}"; : "${DEPLOY:=demo-app}"; : "${TETRAGON_CONTAINER:=export-stdout}"
: "${SECONDS_PER_PHASE:=15}"; : "${CONC:=4}"; : "${LOCAL_PORT:=18083}"
case "$SET" in
  orig) DIR=node/tetragon;     OTHER=node/tetragon/opt; PREFIX=provbind- ;;
  opt)  DIR=node/tetragon/opt; OTHER=node/tetragon;     PREFIX=provbind-opt- ;;
  *) echo "usage: $0 orig|opt" >&2; exit 2 ;;
esac
TMP=$(mktemp -d); PF=""; LP=""
trap 'kill $LP $PF 2>/dev/null; rm -rf "$TMP"' EXIT

for f in write truncate cap load connect; do kubectl delete -f "$OTHER/$f.yaml" --ignore-not-found >/dev/null 2>&1; done
for f in write truncate cap load connect; do kubectl apply -f "$DIR/$f.yaml" >/dev/null || exit 1; done
enabled=0
for _ in $(seq 1 30); do
  list=$(kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra tracingpolicy list 2>/dev/null)
  enabled=0
  for f in write truncate cap load connect; do
    echo "$list" | grep -Eq "[[:space:]]${PREFIX}${f}[[:space:]]+enabled" && enabled=$((enabled + 1))
  done
  [ "$enabled" = 5 ] && break
  sleep 2
done
if [ "$enabled" != 5 ]; then
  echo "event-rate: only $enabled of the 5 $SET policies are enabled in Tetragon:" >&2
  echo "$list" >&2
  exit 1
fi

# A fresh app process, started while Tetragon runs (and a fresh per-process rate limit).
kubectl -n "$NAMESPACE" rollout restart "deploy/$DEPLOY" >/dev/null
kubectl -n "$NAMESPACE" rollout status "deploy/$DEPLOY" --timeout=180s >/dev/null
for _ in $(seq 1 45); do
  [ "$(kubectl -n "$NAMESPACE" get pods --no-headers 2>/dev/null | grep -c "^$DEPLOY-")" -le 1 ] && break
  sleep 2
done
if ! scripts/probe-events.sh > "$TMP/probe.txt" 2>&1; then
  echo "event-rate: Tetragon does not report the app's process: $(grep RESULT "$TMP/probe.txt")" >&2
  exit 1
fi
echo "== policy set $SET: 5 policies enabled; app restarted and monitored ($(grep -o '[0-9]* app-cache write events' "$TMP/probe.txt"))"

kubectl port-forward -n "$NAMESPACE" "deploy/$DEPLOY" "$LOCAL_PORT:8080" >/dev/null 2>&1 & PF=$!
sleep 4
for path in / /cache; do
  kubectl logs -n kube-system ds/tetragon -c "$TETRAGON_CONTAINER" -f --tail=0 > "$TMP/events.jsonl" 2>/dev/null & LP=$!
  sleep 3
  python3 eval/overhead_client.py "http://127.0.0.1:$LOCAL_PORT" "$SECONDS_PER_PHASE" "$CONC" "$path" > "$TMP/client.json"
  sleep 5                                    # let the last events through the stream
  kill "$LP" 2>/dev/null; wait "$LP" 2>/dev/null; LP=""
  python3 -m eval.event_rate "$TMP/events.jsonl" "$TMP/client.json" --path "$path" \
    --namespace "$NAMESPACE" --pod-prefix "$DEPLOY" | sed 's/^/== /'
done
