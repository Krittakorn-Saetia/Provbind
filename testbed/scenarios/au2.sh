#!/usr/bin/env bash
# A-U2 (docs/COMPARISON-RUN.md §3): install-time execution. /au2 runs /usr/local/bin/helperd, a
# harmless program that a build step wrote into the A-U2 image variant (Dockerfile.au2) without any
# package declaring it. Expected: PROVBIND raises only the weak outside_closure signal (the documented
# build-time limit), not an undeclared-exec, because the file is in a layer. Needs the au-2 variant
# image deployed (deploy-au2.sh); against the plain image /au2 returns "absent" and no row is useful.
# Harmless, throwaway container only. Runs on the demo PC. `make au2` calls this.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

wait_for_envelope
start_port_forward
START="$(now)"
app_curl /au2
sleep 30
END="$(now)"

record_gt au-2 malicious "$START" "$END" "outside_closure weak only (build-time program)"
echo "au-2 recorded: $START .. $END"
