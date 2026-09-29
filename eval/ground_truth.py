"""Append one ground-truth row per scenario run (Role 1).

    python -m eval.ground_truth --run $PROVBIND_RUN \
        --scenario attack-1 --label malicious --namespace demo --pod-prefix demo-app \
        --start 2026-09-28T10:14:00Z --end now \
        --expected "D_exec undeclared + D_write"

Writes `$PROVBIND_RUN/ground_truth.csv` in the Sprint Handoff §4.7 format. The header is
written once; every call appends a row. A scenario runs at least three times (Test Plan §12.2,
dataset D4), so this never overwrites: it is one row per run. `--start now` / `--end now` fill
in the current UTC time, which is what the scenario scripts use around the triggered action.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import os

FIELDS = ("scenario", "label", "namespace", "pod_prefix", "start", "end", "expected")


def _now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_row(run_dir, scenario, label, namespace, pod_prefix, start, end, expected):
    """Append a row to run_dir/ground_truth.csv, creating it with a header if needed.
    'now' in start or end is replaced with the current UTC time. Returns the row written."""
    os.makedirs(run_dir, exist_ok=True)
    path = os.path.join(run_dir, "ground_truth.csv")
    row = {
        "scenario": scenario, "label": label, "namespace": namespace, "pod_prefix": pod_prefix,
        "start": _now() if start == "now" else start,
        "end": _now() if end == "now" else end,
        "expected": expected,
    }
    write_header = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if write_header:
            w.writeheader()
        w.writerow(row)
    return row


def main(argv=None):
    ap = argparse.ArgumentParser(description="append a ground-truth row")
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"))
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--label", required=True, choices=["benign", "malicious"])
    ap.add_argument("--namespace", default="demo")
    ap.add_argument("--pod-prefix", required=True)
    ap.add_argument("--start", required=True, help="ISO-8601 UTC, or 'now'")
    ap.add_argument("--end", required=True, help="ISO-8601 UTC, or 'now'")
    ap.add_argument("--expected", required=True)
    args = ap.parse_args(argv)
    row = append_row(args.run, args.scenario, args.label, args.namespace, args.pod_prefix,
                     args.start, args.end, args.expected)
    print(",".join(row[k] for k in FIELDS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
