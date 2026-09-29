#!/usr/bin/env bash
# Benign load for ML-B's dataset D2 (Test Plan §5; Role 3's ml/data/mlb/README.md). Runs on the demo PC
# while Role 3 records Tetragon. Requests arrive at random intervals: 60% `/`, 25% `/healthz` (the
# health checks) and 15% `/cache` (the app's own cache-file writes), all through kubectl port-forward,
# so the load itself executes nothing inside the app container.
#
#   make loadgen                    # first benign run: 4 hours (Role 3: 3 h gives too few windows)
#   DURATION=3600 make loadgen      # held-out run: 1 hour, starting at least 1 hour after the first ends
#
# It writes no ground-truth row: a benign training run is not a scenario, and keep the pod free of
# any other activity (kubectl exec, scenarios) while it runs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source testbed/scenarios/lib.sh

: "${DURATION:=14400}"
: "${MIN_GAP:=1}"
: "${MAX_GAP:=10}"

wait_for_envelope
start_port_forward
end=$(( $(date +%s) + DURATION ))
n=0; failed=0
echo "loadgen: benign load for ${DURATION}s, one request every ${MIN_GAP}-${MAX_GAP}s" >&2
while [ "$(date +%s)" -lt "$end" ]; do
  r=$(( RANDOM % 100 ))
  if [ "$r" -lt 60 ]; then path=/; elif [ "$r" -lt 85 ]; then path=/healthz; else path=/cache; fi
  if app_curl "$path"; then
    n=$(( n + 1 ))
  else
    failed=$(( failed + 1 ))                  # a port-forward can drop over hours: reopen it
    stop_port_forward
    start_port_forward || sleep 5
  fi
  sleep $(( MIN_GAP + RANDOM % (MAX_GAP - MIN_GAP + 1) ))
done
echo "loadgen: $n requests in ${DURATION}s, $failed failed" >&2
