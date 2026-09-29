#!/usr/bin/env python3
"""
alerts/log.py
Tamper-evident Merkle violation logger for PROVBIND.
Appends alert records to log/violations.jsonl using RFC 6962 leaf hashing and hash chaining.
"""

import os
import json
import hashlib

class ViolationLogger:
    def __init__(self, run_dir="./run"):
        self.log_dir = os.path.join(run_dir, "log")
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_path = os.path.join(self.log_dir, "violations.jsonl")
        self.k, self.last_hash = self._get_last_state()

    def _get_last_state(self):
        """Reads the last k index and hash from log/violations.jsonl."""
        if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
            return 0, "0" * 64

        last_line = None
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line

        if last_line:
            data = json.loads(last_line)
            return data["k"], data["hash"]
        return 0, "0" * 64

    def append_alert(self, alert_record):
        """
        Appends an alert record with RFC 6962 leaf hash and prev link.
        Rule:
        canon = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        h = hashlib.sha256(bytes.fromhex(prev) + hashlib.sha256(canon).digest()).hexdigest()
        """
        self.k += 1
        prev = self.last_hash

        canon = json.dumps(alert_record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        leaf_hash = hashlib.sha256(canon).digest()
        h = hashlib.sha256(bytes.fromhex(prev) + leaf_hash).hexdigest()

        entry = {
            "k": self.k,
            "prev": prev,
            "hash": h,
            "record": alert_record
        }

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        self.last_hash = h
        print(f"🔒 [ViolationLogger] Appended alert to Merkle log (k={self.k}, hash={h[:12]}...)")
        return self.k, h

if __name__ == "__main__":
    logger = ViolationLogger(run_dir="/tmp/test_run")
    sample_alert = {"alert_id": "alr-0001", "class": "D_exec", "subclass": "undeclared"}
    k, h = logger.append_alert(sample_alert)
    print(f"Logged sample alert at k={k}, hash={h}")
