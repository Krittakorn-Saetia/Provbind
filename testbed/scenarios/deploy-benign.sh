#!/usr/bin/env bash
# A-B1 (benign admission, docs/COMPARISON-RUN.md §3): deploy a clean, validly signed variant of the demo
# image (no advisory, key active), exactly as A-K1 deploys its own, and watch it start. Expected: nothing
# above Low from any system. It is the admission cell's benign control: without it, an alert that fires
# on ANY pod start (the dry run, 1 October: Falco's "Drop and execute new binary in container" on ak-1,
# ak-2 and ak-3) would count only as detections, never as false positives. Same window as A-K1 (binding
# plus TRUST_SETTLE). Harmless. Needs COSIGN_PASSWORD/the key, like A-K1 and A-U2. `make ab1` calls this.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/deploy_lib.sh

: "${TRUST_SETTLE:=30}"

NAME="demo-app-abclean"
TMPCTX="$(mktemp -d)"
cleanup() { teardown_temp "$NAME"; rm -rf "$TMPCTX"; }
trap cleanup EXIT

echo "ab-1: building + signing this round's clean variant of the demo image"
cp -r testbed/demo-app/. "$TMPCTX/"
printf '\n# A-B1 variant: a marker that changes every round (a fresh, clean, signed digest)\nRUN echo "%s" > /app/.ab1-variant\n' \
  "ab1-$(date +%s%N)" >> "$TMPCTX/Dockerfile"
REF="$(pipeline/build-and-attest.sh "$TMPCTX" "$NAME")"     # prints the signed ref@digest on stdout
echo "ab-1: signed variant $REF"

START="$(now)"
deploy_temp "$NAME" "$REF"
wait_binding "$NAME" || true
sleep "$TRUST_SETTLE"
snapshot_binding "$NAME"
END="$(now)"

POD_PREFIX="$NAME" record_gt ab-1 benign "$START" "$END" "nothing above Low: a clean signed image deployed normally"
echo "ab-1 recorded: $START .. $END"
