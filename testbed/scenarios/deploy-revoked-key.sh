#!/usr/bin/env bash
# A-K3 (comparison test plan section 3.1): our signing key is marked revoked, THEN the signed image is
# deployed. Expected: rejected at admission (v_trust sees the revoked key), so the binding is not
# verified even though the signature itself is valid. Uses Role 4's `alerts.trust set-key`. Harmless.
# Runs on the demo PC with the controller and trust loop running; needs DEMO_REF (the signed image).
# `make ak3` calls this. The key is set back to active on exit.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/deploy_lib.sh

: "${DEMO_REF:?set DEMO_REF to the signed ref@digest that make demo-app printed}"
python3 -c 'import alerts.trust' 2>/dev/null \
  || { echo "ak-3: needs Role 4's alerts package (PR #17) merged" >&2; exit 1; }

NAME="demo-app-akrev"
restore() { python3 -m alerts.trust set-key --run "$PROVBIND_RUN" --state active >/dev/null 2>&1 || true; teardown_temp "$NAME"; }
trap restore EXIT

START="$(now)"
python3 -m alerts.trust set-key --run "$PROVBIND_RUN" --state revoked
deploy_temp "$NAME" "$DEMO_REF"
wait_binding "$NAME" || true
sleep 15
END="$(now)"

POD_PREFIX="$NAME" record_gt ak-3 malicious "$START" "$END" "rejected at admission (v_trust: key revoked)"
echo "ak-3 recorded: $START .. $END (key set back to active on exit)"
