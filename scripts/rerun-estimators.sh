#!/usr/bin/env bash
# Re-run only the analysis of a finished comparison run (steps 5 and 6 of scripts/comparison-run.sh):
# Confine-E and DeSFAM-E over the saved traces, then the tables. Nothing is redeployed or re-recorded.
#   scripts/rerun-estimators.sh                 # PROVBIND_RUN=./run by default
# With EXPORT=1 it first re-exports the image's binaries from the running demo pod into
# $PROVBIND_RUN/traces/binaries (needs the cluster and DEMO_REF=<ref@digest>).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

: "${PROVBIND_RUN:=./run}"
: "${NAMESPACE:=demo}"
: "${DEPLOY:=demo-app}"
: "${EXPORT:=0}"
: "${DOCKER_SECCOMP:=eval/baselines/docker-seccomp.json}"
TRACES="$PROVBIND_RUN/traces"; BASE="$TRACES/baseline"; BIN="$TRACES/binaries"; RESULTS="$PROVBIND_RUN/results"

sudo -n chown -R "$(id -u):$(id -g)" "$TRACES" 2>/dev/null || true    # the recorder wrote as root
if [ "$EXPORT" = 1 ]; then
  : "${DEMO_REF:?set DEMO_REF to the demo app ref@digest to re-export the binaries}"
  rm -rf "$BIN"
  eval/baselines/export_binaries.sh --run "$PROVBIND_RUN" --namespace "$NAMESPACE" --deploy "$DEPLOY" \
    --digest "${DEMO_REF##*@}" --out "$BIN" --startup-trace "$BASE/startup.txt"
fi
[ -d "$BIN" ] || { echo "rerun-estimators: no $BIN (run with EXPORT=1)" >&2; exit 3; }

mapfile -t SCEN_TRACES < <(find "$TRACES" -maxdepth 1 -name '*.txt' | sort)
[ "${#SCEN_TRACES[@]}" -gt 0 ] || { echo "rerun-estimators: no traces in $TRACES" >&2; exit 3; }
ARGS=(); for t in "${SCEN_TRACES[@]}"; do ARGS+=(--trace "$t"); done
DES_SECCOMP=(); [ -f "$DOCKER_SECCOMP" ] && DES_SECCOMP=(--docker-seccomp "$DOCKER_SECCOMP")

python3 -m eval.baselines.confine_estimate --binaries "$BIN" "${ARGS[@]}" --out "$RESULTS/confine.json" >/dev/null
python3 -m eval.baselines.desfam_estimate --binaries "$BIN" "${DES_SECCOMP[@]}" \
  --benign "$BASE/benign-*.txt" "${ARGS[@]}" --out "$RESULTS/desfam.json" >/dev/null
python3 -m eval.baselines.aggregate --run "$PROVBIND_RUN" \
  --confine "$RESULTS/confine.json" --desfam "$RESULTS/desfam.json" --write
echo "rerun-estimators: $(find "$BIN" -type f | wc -l) binaries, ${#SCEN_TRACES[@]} traces; see $RESULTS/COMPARISON.md" >&2
