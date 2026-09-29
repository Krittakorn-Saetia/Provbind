"""MLB-01 and MLB-02 (P0): ML-B's gate and its windows (Test Plan §3.7 and §5).

- MLB-01: only conforming events enter a window (Algorithm 2, lines 2-4). A mix of conforming
  and contradicting events is fed through the whole pipeline. Every event that entered a window
  must have been conforming, and some must have entered.
- MLB-02: windows and features Ψ_I are deterministic (Eq. 57). The same events are replayed in
  this process and in fresh processes with fixed hash seeds 0-5. Every window record must be
  identical.

Both are properties of the code, so the result counts on synthetic input, as MLA-02 does. The
input is node/synth.py's scenario library plus an hour of synthetic benign load, and also
PROVBIND_RECORDING with the run folder when set.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

from node.mlb import Behaviour
from node.scenarios import replay
from node.store import Store
from node.synth import benign_session, library
from node.verify import SUPPRESSED, Egress

ROOT = Path(__file__).resolve().parents[2]
RUN = Path(os.environ.get("PROVBIND_RUN", "./run"))
SEEDS = ("0", "1", "2", "3", "4", "5")


def streams():
    """(name, lines, store factory, egress) for every stream MLB-01 and MLB-02 look at."""
    lib = library()
    out = [("synthetic library", lib.lines, lambda: Store.static([lib.envelope], lib.bindings), Egress(lib.egress)),
           ("synthetic benign hour", benign_session(3600, seed=7),
            lambda: Store.static([lib.envelope], lib.bindings), None)]
    rec = os.environ.get("PROVBIND_RECORDING")
    if rec:
        def run_store():
            s = Store(RUN)
            s.refresh()
            return s
        lines = Path(rec).read_text(encoding="utf-8", errors="replace").splitlines()
        egress = Egress.load(os.environ["PROVBIND_EGRESS"]) if os.environ.get("PROVBIND_EGRESS") else None
        out.append((rec, lines, run_store, egress))
    return out


class Spy(Behaviour):
    """The real stage, checking each event's verdict at the moment it enters a window."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.current, self.contradicting, self.entered_n, self.leaked = None, Counter(), 0, 0

    def observe(self, ev, det, env, binding):
        self.current = det
        if det is not None:
            self.contradicting["suppressed" if det is SUPPRESSED else f"{det['class']}/{det['subclass']}"] += 1
        return super().observe(ev, det, env, binding)

    def _add(self, p, ev):
        self.entered_n += 1
        self.leaked += self.current is not None
        return super()._add(p, ev)


def test_mlb_01_only_conforming_events_enter_a_window(record_result):
    per_stream, leaked, entered_total, contradicting_total = {}, 0, 0, 0
    for name, lines, store, egress in streams():
        spy = Spy()
        replay(lines, store(), egress=egress, behaviour=spy, keep=lambda e: False)
        contradicting = sum(spy.contradicting.values())
        per_stream[name] = {"entered": spy.entered_n, "contradicting_seen": dict(spy.contradicting),
                            "contradicting_entered": spy.leaked}
        leaked, entered_total, contradicting_total = leaked + spy.leaked, entered_total + spy.entered_n, \
            contradicting_total + contradicting
    ok = leaked == 0 and entered_total > 0 and contradicting_total > 0
    notes = (f"{contradicting_total} contradicting events fed, {leaked} reached a window; "
             f"{entered_total} conforming events entered windows; streams: {', '.join(per_stream)}")
    record_result("MLB-01", "pass" if ok else "fail", metrics={"streams": per_stream, "leaked": leaked},
                  notes=notes)
    assert ok, notes


CHILD = """
import json, sys
from node.mlb import Behaviour
from node.scenarios import replay
from node.store import Store
from node.synth import benign_session, library
lib = library()
out = []
for lines in (lib.lines, benign_session(3600, seed=7)):
    replay(lines, Store.static([lib.envelope], lib.bindings), behaviour=Behaviour(on_window=out.append),
           keep=lambda e: False)
print(json.dumps(out, sort_keys=True))
"""


def windows_here() -> list:
    out = []
    for name, lines, store, egress in streams()[:2]:
        replay(lines, store(), egress=None, behaviour=Behaviour(on_window=out.append), keep=lambda e: False)
    return out


def test_mlb_02_windows_and_features_are_deterministic(record_result):
    first = json.loads(json.dumps(windows_here(), sort_keys=True))
    second = json.loads(json.dumps(windows_here(), sort_keys=True))
    runs, errors = [first, second], []
    for seed in SEEDS:
        child = subprocess.run([sys.executable, "-c", CHILD], cwd=ROOT, capture_output=True, text=True, timeout=300,
                               env={**os.environ, "PYTHONHASHSEED": seed})
        if child.returncode:
            errors.append(f"seed {seed}: {child.stderr.strip()[-200:]}")
        else:
            runs.append(json.loads(child.stdout))
    recorded = ""
    rec = os.environ.get("PROVBIND_RECORDING")
    if rec:
        name, lines, store, egress = streams()[2]
        again = []
        for _ in range(2):
            out = []
            replay(lines, store(), egress=egress, behaviour=Behaviour(on_window=out.append), keep=lambda e: False)
            again.append(json.dumps(out, sort_keys=True))
        recorded = f"; {rec} twice: {'identical' if again[0] == again[1] else 'DIFFERENT'}"
        errors += [] if again[0] == again[1] else [f"{rec}: two replays differ"]
    identical = not errors and all(r == first for r in runs)
    ok = identical and len(first) > 0
    notes = (f"{len(first)} windows from the synthetic library and a benign hour, replayed {len(runs)} times "
             f"(this process twice, hash seeds 0-5): {'identical' if identical else 'they differ'}{recorded}")
    if errors:
        notes += "; " + " | ".join(errors)
    record_result("MLB-02", "pass" if ok else "fail",
                  metrics={"windows": len(first), "replays": len(runs), "identical": identical}, notes=notes)
    assert ok, notes
