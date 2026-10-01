#!/usr/bin/env bash
# The comparison run again, this time with attack-2 (R-U2): ML-B's dataset D2 and model for the demo
# image first (scripts/record-d2.sh, about 9 h), then scripts/comparison-run.sh with ATTACK2=1 (about
# 3.5 h). One command, unattended overnight, in a FRESH run folder (move the old one aside first):
#   export COSIGN_PASSWORD=...        # in your own terminal only; ak-1 and au-2 build signed images
#   DEMO_REF=<registry>/demo-app@sha256:<hex> scripts/redo-comparison.sh
# It asks for the sudo password once at the start (bpftrace) and keeps the ticket fresh for the
# comparison run, which starts hours later. Settings pass through (ROUNDS, TRAIN_SECONDS, ...).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
: "${PROVBIND_RUN:=./run}"; export PROVBIND_RUN
: "${DEMO_REF:?set DEMO_REF to the signed ref@digest that make demo-app printed}"; export DEMO_REF
: "${COSIGN_PASSWORD:?export COSIGN_PASSWORD first (ak-1 and au-2 sign their own images)}"

if [ -e "$PROVBIND_RUN/ground_truth.csv" ]; then
  echo "redo-comparison: $PROVBIND_RUN already has a ground_truth.csv; move it aside first" >&2
  exit 1
fi
echo "redo-comparison: bpftrace needs root later; sudo asks for your password once, now"
sudo -v
( while true; do sudo -n true 2>/dev/null; sleep 50; done ) & KEEP=$!
trap 'kill $KEEP 2>/dev/null || true' EXIT

mkdir -p "$PROVBIND_RUN"
scripts/record-d2.sh 2>&1 | tee "$PROVBIND_RUN/record-d2.log"
ATTACK2=1 scripts/comparison-run.sh 2>&1 | tee "$PROVBIND_RUN/comparison-run.log"
echo "redo-comparison done: $PROVBIND_RUN/results/COMPARISON.md"
