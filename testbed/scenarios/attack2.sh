#!/usr/bin/env bash
# attack-2 (Test Plan §7, E2E-03): the in-envelope burst. /update2 writes 300 new files under
# /tmp/.cache in 20 s and reads them back, using only declared binaries. Expected: no deterministic
# detection; ML-B raises at least one D_beh (MLB-05). Harmless, throwaway container only.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

wait_for_envelope
start_port_forward
START="$(now)"
app_curl /update2             # returns after the ~20 s paced burst
sleep 40                      # Role 3 handoff §4: keep the row open >= 35 s (a D_beh is timed at its window's end)
END="$(now)"

record_gt attack-2 malicious "$START" "$END" "D_beh only"
echo "attack-2 recorded: $START .. $END"
