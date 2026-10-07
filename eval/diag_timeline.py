"""When did Tetragon's events reach a run's recording? Per ground-truth scenario window, the demo
namespace's events in rec.jsonl by kind, plus the first and last event overall. Counts only.

    python -m eval.diag_timeline ./run-opt-cmp
"""
import collections
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def ts(text):
    return datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def short(kind, body):
    if kind == "process_kprobe":
        return {"security_file_permission": "write", "security_file_truncate": "trunc",
                "security_mmap_file": "load", "cap_capable": "cap", "tcp_connect": "conn"}.get(
                    body.get("function_name"), body.get("function_name"))
    return kind.replace("process_", "")


def events(path):
    for line in open(path, encoding="utf-8", errors="replace"):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        t = d.get("time")
        for kind, body in d.items():
            if isinstance(body, dict) and "process" in body and t:
                if ((body.get("process") or {}).get("pod") or {}).get("namespace") == "demo":
                    yield ts(t), short(kind, body)


def main(argv=None):
    run = Path((argv or sys.argv[1:])[0])
    evs = sorted(events(run / "rec.jsonl"))
    if not evs:
        print("no demo events in rec.jsonl")
        return 1
    print(f"first event {evs[0][0]:%Y-%m-%d %H:%M:%S}Z, last event {evs[-1][0]:%Y-%m-%d %H:%M:%S}Z, {len(evs)} events")
    rows = list(csv.DictReader(open(run / "ground_truth.csv")))
    print(f"first scenario {rows[0]['start']}, last scenario ends {rows[-1]['end']}")
    kinds = ("exec", "exit", "write", "trunc", "load", "cap", "conn")
    print(f"{'scenario':<16} {'start':<21} " + " ".join(f"{k:>5}" for k in kinds))
    for r in rows:
        a, b = ts(r["start"]), ts(r["end"])
        c = collections.Counter(k for t, k in evs if a <= t <= b)
        print(f"{r['scenario']:<16} {r['start']:<21} " + " ".join(f"{c.get(k, 0):>5}" for k in kinds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
