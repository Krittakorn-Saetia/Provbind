#!/usr/bin/env bash
# R-U4 (comparison test plan section 3.2): binary tampering. /ru4 overwrites the declared /usr/bin/ls
# with /bin/cat's bytes, runs it, then restores the original bytes (so the pod stays usable). Expected:
# PROVBIND D_write on a declared file (no D_hash without runtime hashing). Harmless, throwaway
# container only. Runs on the demo PC. `make ru4` calls this.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

wait_for_envelope
start_port_forward
START="$(now)"
app_curl /ru4
sleep 30
END="$(now)"

record_gt ru-4 malicious "$START" "$END" "D_write on declared /usr/bin/ls"
echo "ru-4 recorded: $START .. $END"
