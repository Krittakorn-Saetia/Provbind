"""Phase 5 Step 5: the hash-chained violation log, `<run>/log/violations.jsonl` (Sprint Handoff §4.6).

Each line is {"k": k, "prev": H(k-1), "hash": H(k), "record": <the alert>}, with exactly this rule:

    canon = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    h = hashlib.sha256(bytes.fromhex(prev) + hashlib.sha256(canon).digest()).hexdigest()
    # prev for k = 1 is 64 zeros; prev for k > 1 is the hash of record k - 1

It is a plain hash chain (Eq. 79), not a Merkle tree: anyone who can rewrite the file can recompute
every later hash (M6; signed checkpoints are PH5-12, P1).

ViolationLog.append() is the only writer of both the log and `alerts.jsonl`. Under one lock it
numbers the alert (log_k = k, alert_id = alr-<k>), appends the log entry, then the alert line, so
the logged record is exactly the alert in alerts.jsonl, and two writers (alerts.run and
alerts.trust) never break the chain or reuse an ID, across restarts too.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .common import locked

ZERO = "0" * 64


def canonical(record) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def chain_hash(prev: str, record) -> str:
    return hashlib.sha256(bytes.fromhex(prev) + hashlib.sha256(canonical(record)).digest()).hexdigest()


def _append_line(path: Path, line: str) -> None:
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


class ViolationLog:
    def __init__(self, run: str | Path):
        self.run = Path(run)
        self.path = self.run / "log" / "violations.jsonl"
        self.alerts_path = self.run / "alerts.jsonl"
        self.lock_path = self.run / "log" / ".append.lock"

    def entries(self) -> list[dict]:
        """Every parseable entry, in file order (verify_log checks the file itself)."""
        out = []
        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            out.append(json.loads(line))
                        except ValueError:
                            continue
        except OSError:
            pass
        return out

    def _head(self) -> tuple[int, str]:
        entries = self.entries()
        if not entries:
            return 0, ZERO
        last = entries[-1]
        return int(last.get("k", len(entries))), str(last.get("hash", ZERO))

    def append(self, alert: dict) -> dict:
        """Number `alert`, log it and write it to alerts.jsonl. Returns the alert as written."""
        with locked(self.lock_path):
            k, prev = self._head()
            k += 1
            alert = {"alert_id": f"alr-{k:04d}",
                     **{key: v for key, v in alert.items() if key not in ("alert_id", "log_k")}, "log_k": k}
            entry = {"k": k, "prev": prev, "hash": chain_hash(prev, alert), "record": alert}
            _append_line(self.path, json.dumps(entry, ensure_ascii=False))
            _append_line(self.alerts_path, json.dumps(alert, ensure_ascii=False))
        return alert

    def detection_ids(self) -> set[str]:
        """Detections already alerted, so a restart never alerts one twice."""
        return {e["record"]["detection_id"] for e in self.entries()
                if isinstance(e.get("record"), dict) and e["record"].get("detection_id")}
