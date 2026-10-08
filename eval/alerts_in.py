"""Which PROVBIND alerts fell inside a scenario's ground-truth windows (the ones the scoring counted).

    python -m eval.alerts_in ./run-opt-cmp2 ph4-14
"""
import csv
import json
import sys
from pathlib import Path

from eval.compare import _in_window, _matches, alert_pod, parse_time

FIELDS = ("class", "subclass", "bucket", "score", "pid", "violated_clause")


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    run, scenario = Path(args[0]), args[1]
    rows = [r for r in csv.DictReader(open(run / "ground_truth.csv")) if r["scenario"] == scenario]
    alerts = [json.loads(l) for l in open(run / "alerts.jsonl") if l.strip()]
    for r in rows:
        start, end = parse_time(r["start"]), parse_time(r["end"])
        hits = [a for a in alerts if _matches(r, *alert_pod(a)) and _in_window(parse_time(a.get("time")), start, end)]
        print(f"{scenario} {r['start']}: {len(hits)} alert(s)")
        for a in hits:
            row = {k: a[k] for k in FIELDS if a.get(k) not in (None, "")}
            chain = (a.get("attribution") or {}).get("process_chain")
            if chain:
                row["process_chain"] = chain
            print("   ", row)
    return 0


if __name__ == "__main__":
    sys.exit(main())
