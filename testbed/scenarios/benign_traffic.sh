#!/usr/bin/env bash
# benign-traffic (Role 1): ordinary use of the demo app through its own endpoints, with no kubectl exec:
# 20 requests alternating GET / and GET /cache (the app rewriting its own cache files under
# /tmp/app-cache, files in no image layer). Expected: nothing above Low from PROVBIND and no Falco rule.
# It balances trust-2 in `make scored` (3 malicious and 3 benign scenarios per round). Runs on the demo
# PC. Not the Test Plan's benign-2 (`pip install six`), which is a different case.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

wait_for_envelope
start_port_forward
START="$(now)"
for _ in $(seq 1 10); do app_curl /; app_curl /cache; sleep 0.5; done
sleep 5
END="$(now)"

record_gt benign-traffic benign "$START" "$END" "nothing above Low: the app's own requests and cache writes"
echo "benign-traffic recorded: $START .. $END"
