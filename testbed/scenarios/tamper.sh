#!/usr/bin/env bash
# tamper-1 (Test Plan §7, E2E-12): change one character in the violation log, so verify_log fails
# at that record. A backup is written first. Runs on the demo PC after a run that produced a log.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source testbed/scenarios/lib.sh

LOG="${PROVBIND_LOG:-$PROVBIND_RUN/log/violations.jsonl}"
[ -s "$LOG" ] || { echo "tamper: no log at $LOG; run a scenario that alerts first" >&2; exit 1; }

cp "$LOG" "$LOG.orig"        # keep the untampered log so the run can be restored
START="$(now)"
# Flip one character inside a record's "record" object, leaving the JSON lines parseable so the
# break is caught by the hash chain, not by a parse error.
PROVBIND_LOG="$LOG" python3 - <<'PY'
import os, re
path = os.environ["PROVBIND_LOG"]
lines = open(path, encoding="utf-8").read().splitlines()
target = len(lines) // 2                      # a record in the middle of the chain
m = re.search(r'[a-z]', lines[target])
if not m:
    raise SystemExit("tamper: no lowercase character to flip")
i = m.start()
flip = "b" if lines[target][i] != "b" else "c"
lines[target] = lines[target][:i] + flip + lines[target][i + 1:]
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print(f"tamper: edited record line {target + 1}")
PY
END="$(now)"

record_gt tamper-1 malicious "$START" "$END" "verify_log fails at the edited record"
echo "tamper-1 recorded (backup at $LOG.orig)"
