#!/usr/bin/env bash
# benign-1 (Test Plan §7, E2E-02): three curl calls, then a terminal shell in the container.
# Expected: nothing above Low from PROVBIND; Falco fires its "terminal shell" rule (recorded for
# comparison). Runs on the demo PC. `make benign` calls this.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

START="$(now)"
for _ in 1 2 3; do app_curl /; done
# Keep -it: Falco's shell rule looks for a terminal (Sprint Handoff §5 pitfall).
kubectl exec -it -n "$NAMESPACE" "deploy/$DEPLOY" -- sh -c 'ls /; cat /etc/hostname' || true
sleep 5
END="$(now)"

record_gt benign-1 benign "$START" "$END" "nothing above Low"
echo "benign-1 recorded: $START .. $END"
