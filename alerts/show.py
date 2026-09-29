"""A readable alert view for the demo screen (Sprint Handoff §3.3, §8 Day 3).

    python -m alerts.show --run $PROVBIND_RUN [--follow] [--no-color]

One line per alert, coloured by bucket, with its clause and attribution. Trust alerts (class
"trust") show the failed checks. Colour is on only when stdout is a terminal.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

COLOURS = {"critical": "\033[1;91m", "high": "\033[1;93m", "medium": "\033[94m", "low": "\033[92m"}
RESET = "\033[0m"


def short(value, n=12):
    if not value:
        return "none"
    s = str(value)
    return s.split(":", 1)[1][:n] if s.startswith("sha256:") else s


def format_alert(a: dict, colour: bool = False) -> str:
    bucket = str(a.get("bucket") or "low").lower()
    head = f"{a.get('alert_id', '?'):<9} {bucket.upper():<8} {a.get('score', ''):>3}"
    if colour:
        head = COLOURS.get(bucket, "") + head + RESET
    attr = a.get("attribution") or {}
    sign = a.get("signing_identity") or {}
    what = f"{a.get('class')}/{a.get('subclass')}"
    where = a.get("container", "")
    if a.get("class") == "trust":
        detail = f"trust withdrawn ({', '.join(a.get('trust_reason') or [])}): {a.get('violated_clause', '')}"
    else:
        detail = a.get("violated_clause", "")
    return (f"{head}  {what:<26} {a.get('chain_id') or '-':<11} {where}  |  {detail}  |  "
            f"layer {short(attr.get('layer'))}, package {attr.get('package') or 'none'}, depth {attr.get('depth')}  |  "
            f"builder {sign.get('builder_id') or 'unknown'}, commit {short(sign.get('source_commit'), 8)}, "
            f"rekor {sign.get('rekor_log_index')}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m alerts.show", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"), help="run folder (default $PROVBIND_RUN or ./run)")
    ap.add_argument("--follow", action="store_true", help="keep printing new alerts")
    ap.add_argument("--no-color", action="store_true", help="plain text")
    args = ap.parse_args(argv)
    colour = sys.stdout.isatty() and not args.no_color
    path = Path(args.run) / "alerts.jsonl"
    while not path.exists():
        if not args.follow:
            print(f"no alerts yet ({path})", file=sys.stderr)
            return 0
        time.sleep(0.5)
    buf = ""
    with open(path, encoding="utf-8") as f:
        while True:
            chunk = f.read(65536)
            if chunk:
                buf += chunk
                *lines, buf = buf.split("\n")
                for line in lines:
                    if line.strip():
                        try:
                            print(format_alert(json.loads(line), colour), flush=True)
                        except ValueError:
                            continue
                continue
            if not args.follow:
                return 0
            time.sleep(0.5)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
