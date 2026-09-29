"""MLA-07 (R3, P1): false positives from capabilities, ML-A envelope against the allowlist envelope.

The plan: run the benign scenarios with each envelope and report the D_cap count per scenario, per
method. It is a measurement, so a real run records pass.

- **Real:** PROVBIND_RECORDING (a Tetragon recording with `cap.yaml` applied, of the benign scenarios),
  PROVBIND_MLA07_ENVELOPES="<ML-A envelope>,<allowlist envelope>" (two compiles of the demo image:
  with the model, and with PROVBIND_CAPS_MODEL=none), and the run folder's bindings.json and
  ground_truth.csv.
- **Otherwise:** the synthetic library with its sample envelope, and the same envelope with no
  capabilities (what the allowlist gives the demo app). Recorded not_run.

Written by Role 2 for Role 3, at Korn's request (the test file was outside Role 3's session scope, Q2).
"""
import copy
import json
import os
from pathlib import Path

from node.scenarios import Row, read_ground_truth, replay
from node.store import Store
from node.synth import library

RUN = Path(os.environ.get("PROVBIND_RUN", "./run"))
BENIGN = ("benign-1", "benign-2", "benign-3", "benign-4", "benign-5", "benign-6")


def inputs():
    rec, envs = os.environ.get("PROVBIND_RECORDING"), os.environ.get("PROVBIND_MLA07_ENVELOPES")
    if rec and envs:
        paths = [p.strip() for p in envs.split(",")]
        methods = {"ml_a": json.loads(Path(paths[0]).read_text()), "allowlist": json.loads(Path(paths[1]).read_text())}
        lines = Path(rec).read_text(encoding="utf-8", errors="replace").splitlines()
        bindings = json.loads((RUN / "bindings.json").read_text())
        rows = [r for r in read_ground_truth(RUN / "ground_truth.csv") if r.scenario in BENIGN]
        return methods, lines, bindings, rows, f"{rec} with {paths[0]} and {paths[1]}", True
    lib = library(attack2_files=30)
    no_caps = copy.deepcopy(lib.envelope)
    no_caps["capabilities"] = []
    rows = [Row.of(d) for d in lib.ground_truth if d["scenario"] in BENIGN]
    return ({"sample_capabilities": lib.envelope, "no_capabilities": no_caps}, lib.lines, lib.bindings, rows,
            "synthetic library, its sample envelope and the same envelope with no capabilities", False)


def test_mla_07_d_cap_per_benign_scenario(record_result):
    methods, lines, bindings, rows, source, real = inputs()
    counts = {}
    for method, envelope in methods.items():
        r = replay(lines, Store.static([envelope], bindings))
        counts[method] = {row.scenario: sum(1 for d in r.within(row)[1] if d.get("class") == "D_cap") for row in rows}
    ok = bool(rows)
    notes = f"{source}: D_cap per benign scenario, per method: {counts}"
    status = ("pass" if ok else "fail") if real else ("not_run" if ok else "fail")
    if not real:
        notes += "; synthetic, so run on the demo PC with PROVBIND_RECORDING and PROVBIND_MLA07_ENVELOPES"
    record_result("MLA-07", status, metrics={"d_cap": counts, "scenarios": [r.scenario for r in rows]}, notes=notes)
    assert ok, notes
