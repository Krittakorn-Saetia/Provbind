#!/usr/bin/env bash
# R-U3 (comparison test plan section 3.2): exfiltration shape, the most common Datadog behaviour.
# /ru3 opens a TCP connection to 203.0.113.9:4444 (RFC 5737 TEST-NET-3, never routed) and sends
# nothing. Expected: PROVBIND D_net (connect to an undeclared external address). No data leaves the
# container. Harmless, throwaway container only. Runs on the demo PC. `make ru3` calls this.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

wait_for_envelope
start_port_forward
START="$(now)"
app_curl /ru3
sleep 30
END="$(now)"

record_gt ru-3 malicious "$START" "$END" "D_net (connect to undeclared external address)"
echo "ru-3 recorded: $START .. $END"
