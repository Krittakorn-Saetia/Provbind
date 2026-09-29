"""Recompute the violation log's hash chain and report the first broken record (PH5-10, PH5-11).

    python -m alerts.verify_log --run $PROVBIND_RUN        # Sprint Handoff §3.3
    python -m alerts.verify_log --run $PROVBIND_RUN --pub log.pub [--every 100]     # PH5-12

stdout: one JSON line, {"ok": ..., "first_bad": k or null, "records": n, "reason": ..., "checkpoints": n or null}.
Exit codes: 0 the chain verifies; 1 a record is broken (first_bad says which); 2 no log to verify.

A record is broken when its line is not JSON, its k is not the next number, its prev is not the
previous record's hash, or its hash does not match its record. Checking k matters: Role 1's
tamper-1 flips the first lowercase letter of a line, which is the "k" key itself.

The plain chain cannot catch a rewrite that recomputes every later hash (M6). With `--pub` (or
PROVBIND_LOG_PUB), the signed checkpoints of `log/checkpoints.jsonl` are checked too (alerts.log):
each signature must verify with the log's public key, record k's recomputed hash must equal the
signed one, and every k that is a multiple of `--every` must have a checkpoint, so deleting the
checkpoints file does not help. A mismatch at checkpoint k gives first_bad = the record after the
last good checkpoint: the rewrite is somewhere from there to k.

Role 1's E2E-12 calls verify(run) and reads .ok and .first_bad.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from .log import CHECKPOINT_EVERY, ZERO, CosignBlob, chain_hash, checkpoint_message, read_checkpoints


@dataclass
class Result:
    ok: bool
    first_bad: int | None
    records: int
    reason: str
    checkpoints: int | None = None                # signed checkpoints verified (with a public key)


def hashes_of(path: str | Path) -> list[str]:
    """The stored hash of each record, in order (after verify_file has passed)."""
    with open(path, encoding="utf-8") as f:
        return [json.loads(ln)["hash"] for ln in f.read().splitlines() if ln.strip()]


def verify_checkpoints(log_path: str | Path, checkpoints_path: str | Path, pub: str,
                       every: int = CHECKPOINT_EVERY, verifier=None) -> Result:
    verifier = verifier or CosignBlob()
    hashes = hashes_of(log_path)
    n = len(hashes)
    good, last_good = 0, 0
    signed: set[int] = set()
    for cp in read_checkpoints(checkpoints_path):
        k, h, bundle = cp.get("k"), cp.get("hash"), cp.get("bundle")
        if not isinstance(k, int) or not isinstance(h, str) or not isinstance(bundle, dict):
            return Result(False, last_good + 1, n, "a checkpoint line is unreadable", good)
        if not verifier.verify(pub, checkpoint_message(k, h), bundle):
            return Result(False, last_good + 1, n, f"the checkpoint for record {k} has no valid signature "
                                                   f"from the log key", good)
        if k > n:
            return Result(False, n + 1, n, f"a signed checkpoint names record {k}, but the log has {n}: "
                                           f"records were removed", good)
        if hashes[k - 1] != h:
            return Result(False, last_good + 1, n, f"record {k}'s hash differs from its signed checkpoint: a record "
                                                   f"from {last_good + 1} to {k} was rewritten", good)
        good, last_good = good + 1, max(last_good, k)
        signed.add(k)
    missing = [k for k in range(every, n + 1, every) if k not in signed]
    if missing:
        return Result(False, max((k for k in signed if k < missing[0]), default=0) + 1, n,
                      f"no signed checkpoint for record {missing[0]} (one is written every {every})", good)
    return Result(True, None, n, f"the chain verifies; {good} signed checkpoint(s) verify"
                                 + (f", records {last_good + 1}-{n} are not signed yet" if last_good < n else ""), good)


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


def verify(run: str | Path, pub: str | None = None, every: int = CHECKPOINT_EVERY, verifier=None) -> Result:
    log_path = Path(run) / "log" / "violations.jsonl"
    result = verify_file(log_path)
    if not result.ok or not pub:
        return result
    return verify_checkpoints(log_path, Path(run) / "log" / "checkpoints.jsonl", pub, every, verifier)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m alerts.verify_log", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"), help="run folder (default $PROVBIND_RUN or ./run)")
    ap.add_argument("run_dir", nargs="?", help=argparse.SUPPRESS)          # the old positional form
    ap.add_argument("--pub", default=os.environ.get("PROVBIND_LOG_PUB"),
                    help="the log key's public key: also check the signed checkpoints (default $PROVBIND_LOG_PUB)")
    ap.add_argument("--every", type=int, default=int(os.environ.get("PROVBIND_CHECKPOINT_EVERY", CHECKPOINT_EVERY)),
                    help="records between checkpoints (default $PROVBIND_CHECKPOINT_EVERY or 100)")
    args = ap.parse_args(argv)
    result = verify(args.run_dir or args.run, args.pub, args.every)
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
