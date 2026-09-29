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
# Change one character inside a record's content (the alert's clause text, else any letter after
# "record"), keeping the line valid JSON, so the break is caught by the hash chain and not by a parse
# error. Prints the edited record's k, which goes into the ground-truth row for E2E-12.
K="$(PROVBIND_LOG="$LOG" python3 - <<'PY2'
import json, os, re, sys
path = os.environ["PROVBIND_LOG"]
lines = open(path, encoding="utf-8").read().splitlines()
target = len(lines) // 2                      # a record in the middle of the chain
line = lines[target]
k = json.loads(line)["k"]
m = re.search(r'"violated_clause":\s*"[^a-z"]*([a-z])', line)
i = m.start(1) if m else None
if i is None:
    r = line.find('"record"')
    m2 = re.compile(r"[a-z]").search(line, r + len('"record"')) if r >= 0 else None
    if not m2:
        sys.exit("tamper: no letter inside the record to change")
    i = m2.start()
flip = "b" if line[i] != "b" else "c"
new = line[:i] + flip + line[i + 1:]
json.loads(new)                               # still valid JSON
lines[target] = new
open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print(k)
PY2
)"
END="$(now)"

record_gt tamper-1 malicious "$START" "$END" "verify_log fails at record k=$K"
echo "tamper-1 recorded: edited record k=$K (backup at $LOG.orig)"
