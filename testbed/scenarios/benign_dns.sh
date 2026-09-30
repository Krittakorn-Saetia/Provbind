#!/usr/bin/env bash
# B4 (docs/COMPARISON-RUN.md §3): benign DNS lookups from the app (/b4). Expected: nothing
# above Low from PROVBIND and no Falco rule; a benign counterpart to R-U3 for the network-behaviour
# false-alarm check. Runs on the demo PC. `make benign-dns` calls this.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

wait_for_envelope
start_port_forward
START="$(now)"
app_curl /b4
sleep 10
END="$(now)"

record_gt benign-3 benign "$START" "$END" "nothing above Low: DNS lookups"
echo "benign-3 recorded: $START .. $END"
