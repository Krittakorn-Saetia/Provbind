#!/usr/bin/env bash
# A-U2 (comparison test plan section 3.1): build and SIGN the A-U2 image variant (Dockerfile.au2 adds
# a harmless /usr/local/bin/helperd that no package declares), deploy it, then run it (/au2). The
# variant is validly signed and attested, so it passes admission; the build-time program shows up only
# as the weak outside_closure signal when the app runs it -- the documented build-time limit. Harmless.
# Runs on the demo PC; needs the local registry, the controller, and COSIGN_PASSWORD/the key (Role 1's
# env, same as `make demo-app`). `make au2-deploy` calls this. Deployment and temp context removed on exit.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/deploy_lib.sh

NAME="demo-app-au2"
TMPCTX="$(mktemp -d)"
cleanup() { teardown_temp "$NAME"; rm -rf "$TMPCTX"; }
trap cleanup EXIT

echo "au-2: building + signing the A-U2 variant (Dockerfile.au2)"
cp -r testbed/demo-app/. "$TMPCTX/"
cp testbed/demo-app/Dockerfile.au2 "$TMPCTX/Dockerfile"
REF="$(pipeline/build-and-attest.sh "$TMPCTX" "$NAME")"     # prints the signed ref@digest on stdout
echo "au-2: signed variant $REF"

deploy_temp "$NAME" "$REF"
# Hand off to au2.sh for the runtime trigger and the ground-truth row, pointed at this deployment.
DEPLOY="$NAME" POD_PREFIX="$NAME" LOCAL_PORT=18081 ./testbed/scenarios/au2.sh
