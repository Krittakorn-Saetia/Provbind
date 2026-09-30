#!/usr/bin/env bash
# A-K2 (comparison test plan section 3.1): deploy an UNSIGNED copy of the demo image. We build a
# variant with a new digest (an extra label) and push it WITHOUT cosign sign/attest, then deploy it.
# Expected: the controller cannot verify it -> binding failure (verified:false), no envelope. Harmless:
# the image is our own demo app; only its signature is missing. Runs on the demo PC. `make ak2` calls
# this. Needs the local registry (localhost:5001) and the controller watching namespace demo.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/deploy_lib.sh

NAME="demo-app-unsigned"
IMG="$PROVBIND_REGISTRY/$NAME:latest"

echo "ak-2: building an unsigned variant image (new digest, no cosign)"
docker build --platform linux/amd64 --provenance=false --sbom=false \
  --label "provbind.test=unsigned-$(date +%s)" -t "$IMG" testbed/demo-app >&2
docker push "$IMG" >&2
REF="$PROVBIND_REGISTRY/$NAME@$(crane digest "$IMG")"
echo "ak-2: pushed unsigned $REF (not signed, not attested)"

START="$(now)"
trap 'teardown_temp "$NAME"' EXIT
deploy_temp "$NAME" "$REF"
wait_binding "$NAME" || true
sleep 15
END="$(now)"

POD_PREFIX="$NAME" record_gt ak-2 malicious "$START" "$END" "not verified: binding failure (unsigned image)"
echo "ak-2 recorded: $START .. $END"
