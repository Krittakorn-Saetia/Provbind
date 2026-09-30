#!/usr/bin/env bash
# R-K3 (docs/COMPARISON-RUN.md §3): library injection. /rk3 LD_PRELOADs an embedded harmless
# .so (built at image build like x9.c) into `python3 -c pass`; the loader maps a library that is in
# no image layer. Expected: PROVBIND D_load undeclared. Harmless, throwaway container only.
# Runs on the demo PC. `make rk3` calls this.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

wait_for_envelope
start_port_forward
START="$(now)"
app_curl /rk3
sleep 30
END="$(now)"

record_gt rk-3 malicious "$START" "$END" "D_load undeclared (injected .so)"
echo "rk-3 recorded: $START .. $END"
