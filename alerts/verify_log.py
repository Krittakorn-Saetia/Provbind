#!/usr/bin/env python3
"""
alerts/verify_log.py
Merkle violation log integrity checker for PROVBIND.
Recomputes RFC 6962 hash chain in log/violations.jsonl and reports the first broken record if tampered.
"""

import os
import sys
import json
import hashlib

def verify_log(run_dir="./run"):
    log_path = os.path.join(run_dir, "log", "violations.jsonl")
    if not os.path.exists(log_path):
        print(f"⚠️ [Log Verifier] {log_path} does not exist.")
        return True

    expected_prev = "0" * 64
    entry_count = 0

    with open(log_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            entry_count += 1
            entry = json.loads(line)
            k = entry.get("k")
            prev = entry.get("prev")
            stored_hash = entry.get("hash")
            record = entry.get("record")

            # Check previous hash link
            if prev != expected_prev:
                print(f"❌ [Log Verifier] TAMPER DETECTED at record k={k} (line {line_num}): 'prev' mismatch!")
                print(f"   Expected prev: {expected_prev}")
                print(f"   Found prev:    {prev}")
                return False

            # Recompute canonical leaf hash and chain hash
            canon = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            leaf_hash = hashlib.sha256(canon).digest()
            computed_hash = hashlib.sha256(bytes.fromhex(prev) + leaf_hash).hexdigest()

            # Check computed record hash
            if stored_hash != computed_hash:
                print(f"❌ [Log Verifier] TAMPER DETECTED at record k={k} (line {line_num}): record content or hash modified!")
                print(f"   Stored hash:   {stored_hash}")
                print(f"   Computed hash: {computed_hash}")
                return False

            expected_prev = stored_hash

    print(f"✅ [Log Verifier] Merkle violation log integrity verified OK ({entry_count} records processed).")
    return True

if __name__ == "__main__":
    run_dir = sys.argv[1] if len(sys.argv) > 1 else "./run"
    success = verify_log(run_dir)
    sys.exit(0 if success else 1)
