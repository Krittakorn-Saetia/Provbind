#!/usr/bin/env bash
# attack-2 (Test Plan §7, E2E-03): the in-envelope burst. /update2 writes 300 new files under
# /tmp/.cache in 20 s and reads them back, using only declared binaries. Expected: no deterministic
# detection; ML-B raises at least one D_beh (MLB-05). Harmless, throwaway container only.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

wait_for_envelope
START="$(now)"
app_curl /update2
sleep 30                     # 20 s of writes plus time for the ML-B window to close
END="$(now)"

record_gt attack-2 malicious "$START" "$END" "D_beh only"
echo "attack-2 recorded: $START .. $END"
