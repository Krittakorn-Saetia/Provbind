#!/usr/bin/env bash
# B5 (docs/COMPARISON-RUN.md §3): benign writes under a mounted volume (/b5 writes and reads a
# file under /data, an emptyDir in no image layer). Expected: nothing above Low from PROVBIND and no
# Falco rule; a benign counterpart to the write scenarios. Needs the deployment to mount a volume at
# /data (testbed/demo-app/deploy.yaml). Runs on the demo PC. `make benign-vol` calls this.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

wait_for_envelope
start_port_forward
START="$(now)"
app_curl /b5
sleep 10
END="$(now)"

record_gt benign-4 benign "$START" "$END" "nothing above Low: mounted-volume writes"
echo "benign-4 recorded: $START .. $END"
