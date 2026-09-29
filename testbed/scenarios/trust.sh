#!/usr/bin/env bash
# trust-1 (Test Plan §7, E2E-11, PH6-04): mark requestz-helper malicious in the local OSV advisory.
# Expected: Role 4's trust loop raises one trust alert naming the component, while the running pod
# stays conforming at runtime. The advisory is reports only, no code (Test Plan §12.5). Runs on the
# demo PC. The advisory path is Role 4's; override with PROVBIND_ADVISORY if theirs differs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

: "${PROVBIND_ADVISORY:=$PROVBIND_RUN/advisories/requestz-helper.json}"
: "${TRUST_SETTLE:=30}"      # seconds to let the trust loop re-evaluate (>= ΔR)

mkdir -p "$(dirname "$PROVBIND_ADVISORY")"
START="$(now)"
# A local advisory in OSV format, MAL- id (Test Plan §12.5). Copies the shape of a real report.
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
sleep "$TRUST_SETTLE"
END="$(now)"

record_gt trust-1 malicious "$START" "$END" "one trust alert; runtime still conforming"
echo "trust-1 recorded: advisory at $PROVBIND_ADVISORY, $START .. $END"
