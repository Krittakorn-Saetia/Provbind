#!/usr/bin/env bash
# A-K1 (comparison test plan section 3.1): a MAL- advisory for requestz-helper already exists BEFORE
# the signed image is deployed. Expected: the trust loop raises a trust alert naming the component
# within seconds of admission (Phase 6's first evaluation), while the pod itself is conforming. The
# advisory is reports only, no code (Test Plan section 12.5). Harmless. Runs on the demo PC with the
# controller and trust loop running; needs DEMO_REF (the signed image). `make ak1` calls this. The
# advisory is removed on exit.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/deploy_lib.sh

: "${DEMO_REF:?set DEMO_REF to the signed ref@digest that make demo-app printed}"
: "${PROVBIND_ADVISORY:=$PROVBIND_RUN/advisories/requestz-helper.json}"
: "${TRUST_SETTLE:=30}"

NAME="demo-app-akadv"
cleanup() { rm -f "$PROVBIND_ADVISORY"; teardown_temp "$NAME"; }
trap cleanup EXIT

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

START="$(now)"
deploy_temp "$NAME" "$DEMO_REF"
wait_binding "$NAME" || true
sleep "$TRUST_SETTLE"
END="$(now)"

POD_PREFIX="$NAME" record_gt ak-1 malicious "$START" "$END" "trust alert within seconds of admission"
echo "ak-1 recorded: $START .. $END (advisory removed on exit)"
