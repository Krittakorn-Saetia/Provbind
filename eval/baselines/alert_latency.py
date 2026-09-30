"""Measure time-to-alert for PROVBIND and Falco during a scored run (comparison table 5).

Time-to-alert = when the alert line appeared − the event's own timestamp. This watcher tails
`alerts.jsonl` (PROVBIND) and `falco.jsonl` (Falco), stamps each new line with its arrival wall-clock
time, and reports per-system count, p50, p99 and mean in seconds.

    python -m eval.baselines.alert_latency --run "$PROVBIND_RUN" --seconds 3600     # watch live
    python -m eval.baselines.alert_latency --run "$PROVBIND_RUN" --offline          # from files only

Live watching needs the two systems' clocks aligned (Role 1's finding: on a VM, stop the guest time
sync and restart Falco, or Falco's timestamps drift and the latency is wrong). `--offline` skips
wall-clock timing and reports only what each record already carries: PROVBIND trust alerts include
their own `latency_s` (input change → alert), and every alert carries its event `time`.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from eval.compare import parse_time


def _event_time(system: str, obj: dict):
    if system == "provbind":
        return parse_time(obj.get("time"))
    return parse_time(obj.get("time") or (obj.get("output_fields") or {}).get("evt.time"))


def _percentile(values, q):
    ordered = sorted(values)
    if not ordered:
        return None
    return round(ordered[min(len(ordered) - 1, int(round(q / 100 * (len(ordered) - 1))))], 3)


def _summary(latencies: dict) -> dict:
    out = {}
    for system, xs in latencies.items():
        out[system] = {"alerts": len(xs), "p50_s": _percentile(xs, 50), "p99_s": _percentile(xs, 99),
                       "mean_s": round(sum(xs) / len(xs), 3) if xs else None}
    return out


def watch(run: str | os.PathLike, seconds: float, poll: float = 0.2) -> dict:
    run = Path(run)
    files = {"provbind": run / "alerts.jsonl", "falco": run / "falco.jsonl"}
    handles, latencies = {}, {"provbind": [], "falco": []}
    for system, path in files.items():
        try:
            fh = open(path, encoding="utf-8")
            fh.seek(0, os.SEEK_END)                          # only lines that arrive from now on
            handles[system] = fh
        except OSError:
            pass
    deadline = time.time() + seconds
    try:
        while time.time() < deadline:
            idle = True
            for system, fh in handles.items():
                for line in fh:
                    if not line.strip():
                        continue
                    idle = False
                    arrival = time.time()
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue
                    et = _event_time(system, obj)
                    if et is not None:
                        latencies[system].append(round(arrival - et.timestamp(), 3))
            if idle:
                time.sleep(poll)
    except KeyboardInterrupt:
        pass
    finally:
        for fh in handles.values():
            fh.close()
    return _summary(latencies)


def offline(run: str | os.PathLike) -> dict:
    run = Path(run)
    out = {}
    alerts = run / "alerts.jsonl"
    if alerts.exists():
        trust = []
        for line in alerts.read_text(encoding="utf-8").splitlines():
            try:
                a = json.loads(line)
            except ValueError:
                continue
            if a.get("class") == "trust" and isinstance(a.get("latency_s"), (int, float)):
                trust.append(float(a["latency_s"]))
        out["provbind_trust_latency_s"] = {"alerts": len(trust), "p50_s": _percentile(trust, 50),
                                           "mean_s": round(sum(trust) / len(trust), 3) if trust else None}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.baselines.alert_latency", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"))
    ap.add_argument("--seconds", type=float, default=600, help="how long to watch live (default 600)")
    ap.add_argument("--offline", action="store_true", help="report only what the records already carry")
    ap.add_argument("--out", help="write the JSON summary here as well as to stdout")
    args = ap.parse_args(argv)
    report = offline(args.run) if args.offline else watch(args.run, args.seconds)
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
