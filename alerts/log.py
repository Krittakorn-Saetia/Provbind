"""Phase 5 Step 5: the hash-chained violation log, `<run>/log/violations.jsonl` (Sprint Handoff §4.6).

Each line is {"k": k, "prev": H(k-1), "hash": H(k), "record": <the alert>}, with exactly this rule:

    canon = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    h = hashlib.sha256(bytes.fromhex(prev) + hashlib.sha256(canon).digest()).hexdigest()
    # prev for k = 1 is 64 zeros; prev for k > 1 is the hash of record k - 1

It is a plain hash chain (Eq. 79), not a Merkle tree: anyone who can rewrite the file can recompute
every later hash (M6). **Signed checkpoints** close that gap (PH5-12, opt-in): with PROVBIND_LOG_KEY
set to a cosign private key used only for the log (never the build key; its password in
COSIGN_PASSWORD, as cosign reads it), every PROVBIND_CHECKPOINT_EVERY-th record (default 100) is
signed, and `python -m alerts.log checkpoint` signs the current head on demand (at the end of a
demo). Each signature covers "provbind-log-checkpoint k=<k> hash=<H(k)>" and is kept, as a cosign
bundle, in `log/checkpoints.jsonl`, a new file beside the log. `verify_log --pub <log key .pub>`
checks them. Where the log key lives is the team's choice; nothing here needs it to be anywhere.
Signing runs `cosign sign-blob` offline (no transparency log upload), under the append lock; a
failed signature is logged and never stops an alert.

ViolationLog.append() is the only writer of both the log and `alerts.jsonl`. Under one lock it
numbers the alert (log_k = k, alert_id = alr-<k>), appends the log entry, then the alert line, so
the logged record is exactly the alert in alerts.jsonl, and two writers (alerts.run and
alerts.trust) never break the chain or reuse an ID, across restarts too.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .common import locked, logger, now_iso

log = logger("log")

ZERO = "0" * 64
CHECKPOINT_EVERY = 100
SIGN_TIMEOUT_S = 60


def canonical(record) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def chain_hash(prev: str, record) -> str:
    return hashlib.sha256(bytes.fromhex(prev) + hashlib.sha256(canonical(record)).digest()).hexdigest()


def _append_line(path: Path, line: str) -> None:
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


def checkpoint_message(k: int, h: str) -> bytes:
    return f"provbind-log-checkpoint k={k} hash={h}\n".encode("ascii")


class CosignBlob:
    """Signs and verifies checkpoint messages with `cosign sign-blob` / `verify-blob`, offline.
    Tests pass another object with the same two methods."""

    def __init__(self, binary: str = "cosign"):
        self.binary = binary

    def _with_message(self, message: bytes, fn):
        with tempfile.TemporaryDirectory(prefix="provbind-ckpt-") as d:
            msg = Path(d) / "msg"
            msg.write_bytes(message)
            return fn(Path(d), msg)

    def sign(self, key: str, message: bytes) -> dict:
        def run(d, msg):
            bundle = d / "bundle.json"
            out = subprocess.run([self.binary, "sign-blob", "--key", str(key), "--use-signing-config=false",
                                  "--tlog-upload=false", "--bundle", str(bundle), "--yes", str(msg)],
                                 capture_output=True, text=True, timeout=SIGN_TIMEOUT_S, stdin=subprocess.DEVNULL)
            if out.returncode != 0:
                raise RuntimeError((out.stderr.strip().splitlines() or ["cosign sign-blob failed"])[-1])
            return json.loads(bundle.read_text())
        return self._with_message(message, run)

    def verify(self, pub: str, message: bytes, bundle: dict) -> bool:
        def run(d, msg):
            b = d / "bundle.json"
            b.write_text(json.dumps(bundle))
            out = subprocess.run([self.binary, "verify-blob", "--key", str(pub), "--bundle", str(b),
                                  "--insecure-ignore-tlog=true", str(msg)],
                                 capture_output=True, text=True, timeout=SIGN_TIMEOUT_S, stdin=subprocess.DEVNULL)
            return out.returncode == 0
        return self._with_message(message, run)


class Checkpointer:
    def __init__(self, key: str, every: int = CHECKPOINT_EVERY, signer=None):
        self.key, self.every, self.signer = key, max(1, int(every)), signer or CosignBlob()

    @classmethod
    def from_env(cls) -> "Checkpointer | None":
        key = os.environ.get("PROVBIND_LOG_KEY")
        if not key:
            return None
        return cls(key, int(os.environ.get("PROVBIND_CHECKPOINT_EVERY", CHECKPOINT_EVERY)))

    def sign(self, k: int, h: str) -> dict:
        return {"k": k, "hash": h, "time": now_iso(), "bundle": self.signer.sign(self.key, checkpoint_message(k, h))}


class ViolationLog:
    def __init__(self, run: str | Path, checkpointer: Checkpointer | None = None):
        self.run = Path(run)
        self.path = self.run / "log" / "violations.jsonl"
        self.alerts_path = self.run / "alerts.jsonl"
        self.lock_path = self.run / "log" / ".append.lock"
        self.checkpoints_path = self.run / "log" / "checkpoints.jsonl"
        self.checkpointer = checkpointer if checkpointer is not None else Checkpointer.from_env()

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
            if self.checkpointer is not None and k % self.checkpointer.every == 0:
                self._checkpoint(k, entry["hash"])
        return alert

    def _checkpoint(self, k: int, h: str) -> dict | None:
        try:
            cp = self.checkpointer.sign(k, h)
        except Exception as e:                   # never lose an alert over a signature
            log.error("checkpoint k=%d not signed: %s", k, e)
            return None
        _append_line(self.checkpoints_path, json.dumps(cp, ensure_ascii=False))
        log.info("checkpoint k=%d signed", k)
        return cp

    def checkpoint(self) -> dict | None:
        """Sign the current head now (the end of a demo), unless it is signed already."""
        if self.checkpointer is None:
            raise RuntimeError("no log key: set PROVBIND_LOG_KEY")
        with locked(self.lock_path):
            k, h = self._head()
            if k == 0:
                return None
            last = read_checkpoints(self.checkpoints_path)
            if last and last[-1].get("k") == k and last[-1].get("hash") == h:
                return last[-1]
            return self._checkpoint(k, h)

    def detection_ids(self) -> set[str]:
        """Detections already alerted, so a restart never alerts one twice."""
        return {e["record"]["detection_id"] for e in self.entries()
                if isinstance(e.get("record"), dict) and e["record"].get("detection_id")}


def read_checkpoints(path: str | Path) -> list[dict]:
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        out.append({})                  # counted, and fails verification
    except OSError:
        pass
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m alerts.log", description="Sign the violation log's head now.")
    ap.add_argument("command", choices=["checkpoint"])
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"), help="run folder (default $PROVBIND_RUN or ./run)")
    args = ap.parse_args(argv)
    cp = ViolationLog(args.run).checkpoint()
    print(json.dumps({"k": cp["k"], "hash": cp["hash"]} if cp else {"k": 0}))
    return 0 if cp else 1


if __name__ == "__main__":
    sys.exit(main())
