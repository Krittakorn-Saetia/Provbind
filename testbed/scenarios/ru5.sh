#!/usr/bin/env bash
# R-U5 (comparison test plan section 3.2): credential theft by mimicry, PROVBIND's documented blind
# spot. /ru5 reads the pod's service-account token but sends only its SHA-256 DIGEST (never the token)
# to an ALLOWED in-cluster address. Expected: nothing fires (a conforming read to an allowed sink) --
# the case the comparison uses to show the limit honestly. The secret is never transmitted or logged.
# Harmless, throwaway container only. Runs on the demo PC. `make ru5` calls this.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

wait_for_envelope
start_port_forward
START="$(now)"
app_curl /ru5
sleep 20
END="$(now)"

record_gt ru-5 malicious "$START" "$END" "none (PROVBIND blind spot: allowed sink, digest only)"
echo "ru-5 recorded: $START .. $END"
