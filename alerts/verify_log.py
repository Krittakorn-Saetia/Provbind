"""Recompute the violation log's hash chain and report the first broken record (PH5-10, PH5-11).

    python -m alerts.verify_log --run $PROVBIND_RUN        # Sprint Handoff §3.3

stdout: one JSON line, {"ok": ..., "first_bad": k or null, "records": n, "reason": ...}.
Exit codes: 0 the chain verifies; 1 a record is broken (first_bad says which); 2 no log to verify.

A record is broken when its line is not JSON, its k is not the next number, its prev is not the
previous record's hash, or its hash does not match its record. Checking k matters: Role 1's
tamper-1 flips the first lowercase letter of a line, which is the "k" key itself.

Role 1's E2E-12 calls verify(run) and reads .ok and .first_bad.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from .log import ZERO, chain_hash


@dataclass
class Result:
    ok: bool
    first_bad: int | None
    records: int
    reason: str


def verify_file(path: str | Path) -> Result:
    try:
        with open(path, encoding="utf-8") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
    except OSError as e:
        return Result(False, None, 0, f"no log: {e.strerror or e}")
    if not lines:
        return Result(False, None, 0, "the log is empty")
    prev = ZERO
    for k, line in enumerate(lines, 1):
        try:
            entry = json.loads(line)
        except ValueError as e:
            return Result(False, k, k - 1, f"record {k} is not JSON ({e.msg})")
        if not isinstance(entry, dict):
            return Result(False, k, k - 1, f"record {k} is not an object")
        if entry.get("k") != k:
            return Result(False, k, k - 1, f"record {k} says k={entry.get('k')!r}")
        if entry.get("prev") != prev:
            return Result(False, k, k - 1, f"record {k}: prev is not the hash of record {k - 1}")
        try:
            h = chain_hash(prev, entry.get("record"))
        except (TypeError, ValueError) as e:
            return Result(False, k, k - 1, f"record {k} cannot be hashed ({e})")
        if entry.get("hash") != h:
            return Result(False, k, k - 1, f"record {k}: hash does not match its record")
        prev = h
    return Result(True, None, len(lines), "the chain verifies")


def verify(run: str | Path) -> Result:
    return verify_file(Path(run) / "log" / "violations.jsonl")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m alerts.verify_log", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"), help="run folder (default $PROVBIND_RUN or ./run)")
    ap.add_argument("run_dir", nargs="?", help=argparse.SUPPRESS)          # the old positional form
    args = ap.parse_args(argv)
    result = verify(args.run_dir or args.run)
    print(json.dumps(asdict(result)))
    if result.ok:
        print(f"[verify_log] OK: {result.records} records", file=sys.stderr)
        return 0
    if result.first_bad is None:
        print(f"[verify_log] {result.reason}", file=sys.stderr)
        return 2
    print(f"[verify_log] BROKEN at record k={result.first_bad}: {result.reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
