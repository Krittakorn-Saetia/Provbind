"""node/detection.schema.json: every detection Role 3 emits is valid, and bad ones are refused."""
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from node.normalize import Event, parse_time
from node.pipeline import Pipeline
from node.scenarios import synthetic_evidence
from node.store import Store
from node.synth import DEMO_CID
from node.verify import FIELDS, Verifier, binding_failure

SCHEMA = json.loads((Path(__file__).resolve().parents[1] / "detection.schema.json").read_text(encoding="utf-8"))
V = Draft202012Validator(SCHEMA)


@pytest.fixture(scope="module")
def dets():
    ev = synthetic_evidence()
    return ev.main.detections + ev.path_only.detections


def test_schema_is_valid_and_lists_exactly_the_contract_fields():
    Draft202012Validator.check_schema(SCHEMA)
    assert tuple(SCHEMA["required"]) == FIELDS and set(SCHEMA["properties"]) == set(FIELDS)


def test_every_detection_of_the_library_is_valid(dets):
    assert len({(d["class"], d["subclass"]) for d in dets}) >= 11
    for d in dets:
        assert not list(V.iter_errors(d)), d


def test_no_envelope_and_unknown_container_are_valid():
    store = Store.static([], {DEMO_CID: {"image_digest": "sha256:" + "11" * 32, "verified": True}})
    out = []
    p = Pipeline(store, Verifier(), on_detection=out.append, envelope_timeout=1)
    t = parse_time("2026-09-28T10:00:00Z")
    p.feed(Event(time="2026-09-28T10:00:00Z", t=t, kind="exec", container_id=DEMO_CID, namespace="demo",
                 pod="p", container="c", pid=1, ppid=0, exe="/x", parent_exe=None))
    p.tick(t + 2_000_000_000)
    det = out[0]
    det["id"] = "det-0001"
    assert det["subclass"] == "no_envelope" and not list(V.iter_errors(det))


@pytest.mark.parametrize("change", [
    lambda d: d.pop("origin"), lambda d: d.pop("time"), lambda d: d.pop("clause"), lambda d: d.pop("context"),
    lambda d: d.update(origin="SIGNED"), lambda d: d.update(subclass="relocated"),
    lambda d: d.update({"class": "D_teleport"}), lambda d: d.update(time="2026-09-28 10:00:00"),
    lambda d: d["clause"].pop("detail"), lambda d: d["clause"].update(kind="vibes"),
    lambda d: d["context"].update(depth=-1), lambda d: d.update(id="alr-0001"),
    lambda d: d.update(image_digest="sha256:short"), lambda d: d.update(pid="4471"),
])
def test_broken_detections_are_refused(dets, change):
    d = copy.deepcopy(next(x for x in dets if x["class"] == "D_exec" and x["subclass"] == "undeclared"))
    change(d)
    assert list(V.iter_errors(d))


def test_binding_failure_with_null_declared_is_valid():
    ev = Event(time="2026-09-28T10:00:00Z", t=0, kind="exec", container_id=DEMO_CID, namespace="demo", pod="p",
               container="c", pid=1, ppid=0, exe="/x", parent_exe=None)
    d = binding_failure(ev, None, "unknown_container", "no binding")
    d["id"] = "det-0001"
    assert not list(V.iter_errors(d))
