#!/usr/bin/env bash
# Phase 1 for one image: build, push, SBOM, provenance, sign, attest, self-verify.
# usage:  pipeline/build-and-attest.sh <context-dir> <name>
# stdout: the pushed reference <registry>/<name>@sha256:<digest>; all logs go to stderr.
# PROVBIND_OFFLINE=1 signs without Rekor (--tlog-upload=false, plus --use-signing-config=false on
# cosign v2.6+ and v3) and verifies with --insecure-ignore-tlog=true.
set -euo pipefail

if [ $# -ne 2 ]; then echo "usage: $0 <context-dir> <name>" >&2; exit 64; fi
if [ -z "${COSIGN_PASSWORD+x}" ]; then
  echo "export COSIGN_PASSWORD first (an empty string is fine)" >&2; exit 64
fi

CTX="$1"; NAME="$2"
REG="${PROVBIND_REGISTRY:-localhost:5001}"
RUN="${PROVBIND_RUN:-./run}"
KEY="${COSIGN_KEY:-pipeline/keys/cosign.key}"
PUB="${KEY%.key}.pub"
IMG="$REG/$NAME:latest"
OUT="$RUN/attest/$NAME"
mkdir -p "$OUT"
log() { echo "[build-and-attest] $*" >&2; }
trap 'log "FAILED. Last lines of $OUT/cosign.log:"; tail -n 20 "$OUT/cosign.log" >&2 2>/dev/null || true' ERR

# Offline mode (handoff Section 10): nothing goes to Rekor, so verification skips the tlog.
# Expand with ${A[@]+"${A[@]}"}: bash 3.2 (macOS) treats an empty array as unset under set -u.
SIGN_FLAGS=(); VERIFY_FLAGS=()
if [ "${PROVBIND_OFFLINE:-}" = "1" ]; then
  SIGN_FLAGS=(--tlog-upload=false); VERIFY_FLAGS=(--insecure-ignore-tlog=true)
  # cosign v3 signs through a signing config by default and then refuses --tlog-upload=false, so
  # turn the config off wherever cosign has the flag (v2.6 and later). The help is read into a
  # variable: piped into grep -q, cosign could die of SIGPIPE, which pipefail counts as a failure.
  SIGN_HELP="$(cosign sign --help 2>&1 || true)"
  case "$SIGN_HELP" in
    *--use-signing-config*) SIGN_FLAGS=(--use-signing-config=false "${SIGN_FLAGS[@]}") ;;
  esac
  log "PROVBIND_OFFLINE=1: signing without Rekor; tell the team the demo skips transparency"
fi

# 1. Build ONE single-platform manifest, for the demo PC's platform even on an Apple Silicon
#    Mac. Without --provenance/--sbom=false buildx adds a provenance attestation and pushes
#    an image index instead of a plain manifest.
log "building $IMG"
docker build --platform linux/amd64 --provenance=false --sbom=false -t "$IMG" "$CTX" >&2
docker push "$IMG" >&2
DIGEST="$(crane digest "$IMG")"      # localhost registries use plain HTTP automatically
REF="$REG/$NAME@$DIGEST"
log "pushed $REF"

# 2. Evidence. These files are debug copies; the compiler reads only verified attestations.
syft "docker:$IMG" -o cyclonedx-json > "$OUT/sbom.json"
DEPS="$(jq '(.dependencies // []) | length' "$OUT/sbom.json")"
[ "$DEPS" -gt 0 ] || log "WARNING: SBOM has no dependency edges; every depth will be null"
python3 pipeline/gen_provenance.py --context "$CTX" > "$OUT/provenance.json"

# 3. Sign the image and attest both documents with the same key.
: > "$OUT/cosign.log"
cosign sign   --yes --key "$KEY" ${SIGN_FLAGS[@]+"${SIGN_FLAGS[@]}"} "$REF" 2>> "$OUT/cosign.log"
cosign attest --yes --key "$KEY" ${SIGN_FLAGS[@]+"${SIGN_FLAGS[@]}"} --type cyclonedx       --predicate "$OUT/sbom.json"       "$REF" 2>> "$OUT/cosign.log"
cosign attest --yes --key "$KEY" ${SIGN_FLAGS[@]+"${SIGN_FLAGS[@]}"} --type slsaprovenance1 --predicate "$OUT/provenance.json" "$REF" 2>> "$OUT/cosign.log"

# 4. Self-check with the public key: the same checks the controller and compiler run.
cosign verify --key "$PUB" ${VERIFY_FLAGS[@]+"${VERIFY_FLAGS[@]}"} "$REF" > "$OUT/verify.json" 2>> "$OUT/cosign.log"
cosign verify-attestation --key "$PUB" ${VERIFY_FLAGS[@]+"${VERIFY_FLAGS[@]}"} --type cyclonedx       "$REF" > /dev/null 2>> "$OUT/cosign.log"
cosign verify-attestation --key "$PUB" ${VERIFY_FLAGS[@]+"${VERIFY_FLAGS[@]}"} --type slsaprovenance1 "$REF" > /dev/null 2>> "$OUT/cosign.log"
log "verified the signature and both attestations ($DEPS dependency entries in the SBOM)"

echo "$REF"
