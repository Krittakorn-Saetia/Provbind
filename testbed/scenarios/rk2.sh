#!/usr/bin/env bash
# R-K2 (comparison test plan section 3.2): replay a known kernel-CVE syscall SHAPE, no exploit.
# /rk2 issues waitid() and splice() harmlessly (the DeSFAM CVEs' calls) on a patched kernel.
# Expected: PROVBIND does not watch raw syscalls, so no PROVBIND detection; Confine-E blocks a call
# outside its static list; DeSFAM-E may flag the window. Harmless, throwaway container only.
# Runs on the demo PC. `make rk2` calls this.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

wait_for_envelope
start_port_forward
START="$(now)"
app_curl /rk2
sleep 15
END="$(now)"

record_gt rk-2 malicious "$START" "$END" "kernel-CVE syscall shape; no PROVBIND detection (complementary)"
echo "rk-2 recorded: $START .. $END"
