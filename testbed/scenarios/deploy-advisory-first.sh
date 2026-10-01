#!/usr/bin/env bash
# A-K1 (docs/COMPARISON-RUN.md §3): a MAL- advisory for requestz-helper already exists BEFORE
# the signed image is deployed. Expected: the trust loop raises a trust alert naming the component
# within seconds of admission (Phase 6's first evaluation), while the pod itself is conforming. The
# advisory is reports only, no code (Test Plan section 12.5). Harmless. Runs on the demo PC with the
# controller and trust loop running, and COSIGN_PASSWORD/the key (like A-U2). `make ak1` calls this.
# The advisory, the deployment and the temporary build context are removed on exit.
#
# A-K1 deploys its OWN signed image (team decision, 1 October, option C): the demo app plus one marker
# file whose content changes every round, so each round has a fresh digest. The trust loop raises one
# alert per image, naming the first pod bound to it; with the demo image shared, that was the long-lived
# demo pod and the scorer saw a miss for ak-1's pod (dry run, 1 October). A fresh digest per round also
# means a fresh trust state, so every round withdraws trust anew.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/deploy_lib.sh

: "${PROVBIND_ADVISORY:=$PROVBIND_RUN/advisories/requestz-helper.json}"
: "${TRUST_SETTLE:=30}"

NAME="demo-app-akadv"
TMPCTX="$(mktemp -d)"
cleanup() { rm -f "$PROVBIND_ADVISORY"; teardown_temp "$NAME"; rm -rf "$TMPCTX"; }
trap cleanup EXIT

echo "ak-1: building + signing this round's own variant of the demo image"
cp -r testbed/demo-app/. "$TMPCTX/"
printf '\n# A-K1 variant: a marker that changes every round, so the image (and its digest) is ak-1 alone\nRUN echo "%s" > /app/.ak1-variant\n' \
  "ak1-$(date +%s%N)" >> "$TMPCTX/Dockerfile"
REF="$(pipeline/build-and-attest.sh "$TMPCTX" "$NAME")"     # prints the signed ref@digest on stdout
echo "ak-1: signed variant $REF"

mkdir -p "$(dirname "$PROVBIND_ADVISORY")"
cat > "$PROVBIND_ADVISORY" <<'JSON'
{
  "id": "MAL-2026-9001",
  "summary": "requestz-helper is malicious (PROVBIND test advisory)",
  "modified": "2026-09-28T00:00:00Z",
  "affected": [
    { "package": { "ecosystem": "PyPI", "name": "requestz-helper", "purl": "pkg:pypi/requestz-helper" },
      "versions": ["0.1.0"] }
  ],
  "database_specific": { "provbind_test": true }
}
JSON
# The advisory also names the long-lived demo pod's image: let that pod's trust alert pass before the row
# opens, so only ak-1's own image is judged inside it.
sleep 5

START="$(now)"
deploy_temp "$NAME" "$REF"
wait_binding "$NAME" || true
sleep "$TRUST_SETTLE"
snapshot_binding "$NAME"
END="$(now)"

POD_PREFIX="$NAME" record_gt ak-1 malicious "$START" "$END" "trust alert within seconds of admission"
echo "ak-1 recorded: $START .. $END (advisory removed on exit)"
