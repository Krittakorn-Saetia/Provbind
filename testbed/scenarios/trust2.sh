#!/usr/bin/env bash
# trust-2 (Test Plan §7, PH6-02): mark our signing key revoked in run/keystatus.json, the stand-in for
# KMS key state (Test Plan §11). Expected: Role 4's trust loop raises one trust alert naming `key`,
# while the pod's runtime state is unchanged. Uses Role 4's `python -m alerts.trust set-key`, so the
# file keeps the format the trust loop reads. Runs on the demo PC with the trust loop running
# (`make trust-loop`). `RESTORE=1 make trust2` sets the key back to active afterwards.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

: "${TRUST_SETTLE:=30}"      # seconds to let the trust loop re-evaluate (it reacts to keystatus.json changes)

python3 -c 'import alerts.trust' 2>/dev/null \
  || { echo "trust2: needs Role 4's alerts package (PR #17) merged" >&2; exit 1; }

if [ "${RESTORE:-0}" = "1" ]; then
  python3 -m alerts.trust set-key --run "$PROVBIND_RUN" --state active >/dev/null
  echo "trust-2: key set back to active in $PROVBIND_RUN/keystatus.json"
  exit 0
fi

[ -f "$PROVBIND_RUN/keystatus.json" ] && cp "$PROVBIND_RUN/keystatus.json" "$PROVBIND_RUN/keystatus.json.orig"
START="$(now)"
python3 -m alerts.trust set-key --run "$PROVBIND_RUN" --state revoked
sleep "$TRUST_SETTLE"
END="$(now)"

record_gt trust-2 malicious "$START" "$END" "one trust alert naming key; runtime state unchanged"
echo "trust-2 recorded: $START .. $END (RESTORE=1 make trust2 undoes it)"
