#!/usr/bin/env bash
# attack-1 (Test Plan §7, E2E-01): trigger the app's /update endpoint after the envelope is ready.
# The test package writes an embedded payload to /tmp/.x9 and runs it; the payload appends a line
# to /etc/passwd. Expected: D_exec undeclared (Critical) + D_write (High) in one chain. Harmless
# test code, throwaway container only. Runs on the demo PC. `make attack` calls this.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

wait_for_envelope
START="$(now)"
app_curl /update
sleep 30                     # let the exec and write events flow through the pipeline
END="$(now)"

record_gt attack-1 malicious "$START" "$END" "D_exec undeclared + D_write"
echo "attack-1 recorded: $START .. $END"
