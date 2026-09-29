"""PH2-10 (R3, P1): the cold-start window between admission and the envelope (C4, Test Plan §3.2).

Pass: the window is reported in seconds for each container, and no held event is lost.

- **Real:** PROVBIND_NODE_SUMMARY names the JSON summary `python -m node.run --summary FILE` wrote on
  the demo PC during a run that deployed a pod (its `cold_start_s` and `held` counts).
- **Otherwise:** `node.run` runs live on a synthetic stream that starts before its binding exists,
  as the controller would write it half a second later. The result is not_run: the numbers show
  the mechanism, not the demo PC's window.

Written by Role 2 for Role 3, at Korn's request (the test file was outside Role 3's session scope, Q2).
"""
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from node.store import hex_of
from node.synth import DIGEST, library

ROOT = Path(__file__).resolve().parents[2]


def synthetic_summary(tmp_path) -> dict:
    lib = library(attack2_files=30, start=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    (tmp_path / "envelopes").mkdir()
    (tmp_path / "envelopes" / f"{hex_of(DIGEST)}.json").write_text(json.dumps(lib.envelope))
    child = subprocess.Popen([sys.executable, "-m", "node.run", "--run", str(tmp_path), "--tick", "0.05",
                              "--grace", "3600"], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    child.stdin.write("\n".join(lib.lines[:40]) + "\n")
    child.stdin.flush()
    time.sleep(0.5)                                      # the controller writes the binding late
    (tmp_path / "bindings.json").write_text(json.dumps(lib.bindings))
    time.sleep(0.5)
    child.stdin.write("\n".join(lib.lines[40:]) + "\n")
    out, err = child.communicate(timeout=120)
    assert child.returncode == 0, err
    return json.loads(out)


def test_ph2_10_cold_start_window(tmp_path, record_result):
    path = os.environ.get("PROVBIND_NODE_SUMMARY")
    real = bool(path)
    summary = json.loads(Path(path).read_text()) if real else synthetic_summary(tmp_path)
    windows, held = summary.get("cold_start_s") or {}, summary.get("held") or {}
    lost = held.get("lost", 0)
    ok = bool(windows) and lost == 0
    worst = max(windows.values()) if windows else None
    notes = (f"{path if real else 'synthetic stream, binding written 0.5 s after the first events'}: "
             f"{len(windows)} container(s) held; longest window {worst} s; {held.get('held', 0)} events held, "
             f"{held.get('released', 0)} released, {lost} lost")
    status = ("pass" if ok else "fail") if real else ("not_run" if ok else "fail")
    if not real:
        notes += "; synthetic, so set PROVBIND_NODE_SUMMARY to a demo-PC run's summary"
    record_result("PH2-10", status, metrics={"windows_s": windows, "held": held}, notes=notes,
                  artifacts=[path] if real else [])
    assert ok, notes
