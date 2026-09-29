"""PH4-17 (P0): detection records have every field (Eq. 60; Test Plan §3.5).

Every detection is checked against node/detection.schema.json, which encodes Sprint Handoff
§4.4: all sixteen fields, with class, clause, origin and time present. That covers the
detections of the replay in test_ph4_scenarios.py (the demo-PC recording, or the synthetic
library) and, if PROVBIND_DETECTIONS is set, a live node's detections.jsonl as well.

Pass: every detection is valid, on real evidence. On the synthetic library: not_run. This test
also runs the whole node unit suite (node/tests/) in a fresh pytest process.
"""
import json
import os
from pathlib import Path

from jsonschema import Draft202012Validator

from .test_ph4_01_02_events import run_suite
from .test_ph4_scenarios import evidence

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "node" / "detection.schema.json").read_text(encoding="utf-8"))
REQUIRED = ("class", "clause", "origin", "time")


def problems(dets) -> list[str]:
    validator = Draft202012Validator(SCHEMA)
    out = []
    for d in dets:
        missing = [k for k in REQUIRED if not d.get(k)]
        errors = sorted(e.message for e in validator.iter_errors(d))
        if missing or errors:
            out.append(f"{d.get('id')}: " + "; ".join([f"no {m}" for m in missing] + errors[:3]))
    return out


def test_ph4_17_detection_records_are_complete(record_result):
    kit = run_suite("PH4-17", ("node/tests",))
    ev = evidence()
    dets = list(ev.main.detections) + list(ev.path_only.detections)
    sources = [ev.source]
    live = os.environ.get("PROVBIND_DETECTIONS")
    if live:
        dets += [json.loads(line) for line in Path(live).read_text(encoding="utf-8").splitlines() if line.strip()]
        sources.append(live)
    bad = problems(dets)
    classes = sorted({f"{d['class']}/{d['subclass']}" for d in dets if "class" in d and "subclass" in d})
    real = ev.real or bool(live)
    ok = bool(dets) and not bad and kit["ok"]
    status = ("pass" if ok else "fail") if real else ("not_run" if ok else "fail")
    notes = f"{' and '.join(sources)}: {len(dets)} detections, {len(bad)} incomplete; classes: {', '.join(classes)}"
    if bad:
        notes += "; first problems: " + " | ".join(bad[:3])
    notes += f"; node unit tests: {kit['metrics']['passed']} passed, {kit['metrics']['failed']} failed"
    if not real:
        notes += "; synthetic library, so not a project result: set PROVBIND_RECORDING or PROVBIND_DETECTIONS"
    record_result("PH4-17", status, metrics={"detections": len(dets), "incomplete": len(bad),
                                             "classes": classes, "unit_tests": kit["metrics"]},
                  notes=notes, artifacts=ev.artifacts + ([live] if live else []) + [kit["junit"]])
    assert kit["ok"], kit["output"]
    assert status != "fail", notes
