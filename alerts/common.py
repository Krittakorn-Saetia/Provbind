"""Helpers shared by Role 4's controller and alert modules (Sprint Handoff §3.2, §4).

- Envelopes live at `<run>/envelopes/<hex>.json`, where <hex> is the digest without `sha256:`:
  the compiler writes that name and Role 3's node reads it.
- `bindings.json` and other whole-file outputs are written to a temp file and renamed, so a reader
  never sees half a file. The temp name does not end in `.json`.
- JSONL outputs are append-only; several processes append to `alerts.jsonl` and the violation
  log (alerts.run and alerts.trust), so appends happen under a lock file.
- Logs go to stderr; stdout is for machine-readable output (CLAUDE.md).
"""
from __future__ import annotations

import contextlib
import datetime as dt
import json
import logging
import os
import secrets
import sys
from pathlib import Path
from typing import Any, Iterator

try:
    import fcntl                                   # POSIX; the demo PC and WSL
except ImportError:                                # Windows: one writer at a time is assumed
    fcntl = None

DEFAULT_RUN = os.environ.get("PROVBIND_RUN", "./run")


def hex_of(digest: str) -> str:
    """'sha256:<hex>' -> '<hex>'; a bare hex is returned unchanged."""
    return digest.split(":", 1)[1] if ":" in digest else digest


def envelope_path(run: str | Path, digest: str) -> Path:
    return Path(run) / "envelopes" / f"{hex_of(digest)}.json"


def load_json(path: str | Path, default: Any = None) -> Any:
    """The JSON document at `path`, or `default` if it is missing or not JSON."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def load_envelope(run: str | Path, digest: str) -> dict | None:
    env = load_json(envelope_path(run, digest))
    return env if isinstance(env, dict) else None


def atomic_write_json(path: str | Path, obj: Any) -> None:
    """Write `obj` to a temp file beside `path`, fsync, then rename over `path`."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        with open(tmp, "x", encoding="utf-8", newline="\n") as f:
            json.dump(obj, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


@contextlib.contextmanager
def locked(lock_path: str | Path) -> Iterator[None]:
    """An exclusive advisory lock on `lock_path` for the duration of the block (POSIX)."""
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a") as f:
        if fcntl is not None:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_time(value: Any) -> float | None:
    """An ISO 8601 time as seconds since the epoch, or None."""
    if not isinstance(value, str) or not value:
        return None
    s = value.strip().replace("Z", "+00:00").replace("z", "+00:00")
    # Python 3.10 accepts only 3 or 6 fraction digits.
    if "." in s:
        head, rest = s.split(".", 1)
        digits = "".join(c for c in rest if c.isdigit())
        tail = rest[len(digits):]
        s = f"{head}.{(digits + '000000')[:6]}{tail}"
    try:
        t = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t.timestamp()


def logger(name: str) -> logging.Logger:
    """A logger that writes `[name] message` to stderr, set up once."""
    log = logging.getLogger(f"provbind.{name}")
    if not log.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(f"[{name}] %(levelname)s %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        log.propagate = False
    return log


def container_label(binding_or_detection: dict) -> str:
    """'namespace/pod/container' (Sprint Handoff §4.5)."""
    d = binding_or_detection
    return f"{d.get('namespace') or ''}/{d.get('pod') or ''}/{d.get('container') or ''}"
