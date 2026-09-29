"""node/scenarios.py and node/synth.py's library: replay per scenario, and ground truth (§4.7)."""
import pytest

from node.scenarios import Row, read_ground_truth, replay, rows_of
from node.store import Store
from node.synth import library
from node.verify import Egress, is_weak

WITH_HASHES = {
    "benign-1": [("D_exec", "outside_closure", "/usr/bin/dash"), ("D_exec", "outside_closure", "/usr/bin/ls")],
    "attack-1": [("D_exec", "undeclared", "/tmp/.x9"), ("D_write", "declared_file", "/etc/passwd")],
    "ph4-14": [],
    "attack-2": [],
    "attack-3": [("D_hash", "relocated", "/tmp/.l")],
    "attack-4": [("D_write", "declared_file", "/usr/bin/ls"), ("D_hash", "modified", "/usr/bin/ls")],
    "attack-5": [("D_load", "undeclared", "/tmp/libx.so")],
    "attack-6": [("D_cap", "not_in_envelope", "/usr/local/bin/python3.11")],
    "attack-7": [("D_net", "not_allowed", "/usr/local/bin/python3.11")],
    "benign-3": [("D_load", "outside_closure", "/usr/lib/x86_64-linux-gnu/libnss_dns.so.2")],
    "benign-4": [],
    "attack-9": [("binding", "unverified", "/usr/bin/sleep"), ("binding", "unknown_container", "/usr/bin/sleep")],
}
PATH_ONLY = {**WITH_HASHES,
             "attack-3": [("D_exec", "undeclared", "/tmp/.l")],
             "attack-4": [("D_write", "declared_file", "/usr/bin/ls"), ("D_exec", "outside_closure", "/usr/bin/ls")]}


@pytest.fixture(scope="module")
def lib():
    return library()


def run(lib, hashes: bool):
    hasher = (lambda e: lib.hashes.get((e.container_id, e.pid))) if hashes else None
    return replay(lib.lines, Store.static([lib.envelope], lib.bindings), egress=Egress(lib.egress), hasher=hasher)


@pytest.mark.parametrize("hashes,expected", [(True, WITH_HASHES), (False, PATH_ONLY)])
def test_every_scenario_gives_exactly_its_expected_detections(lib, hashes, expected):
    r = run(lib, hashes)
    rows = [Row.of(d) for d in lib.ground_truth]
    got = {row.scenario: [(d["class"], d["subclass"], d["clause"]["path"]) for d in r.within(row)[1]] for row in rows}
    assert got == expected
    assert all(any(row.holds(d) for row in rows) for d in r.detections)       # nothing outside a scenario


def test_benign_scenarios_have_only_weak_detections(lib):
    r = run(lib, hashes=False)
    for row in (Row.of(d) for d in lib.ground_truth if d["label"] == "benign"):
        assert all(is_weak(d) for d in r.within(row)[1]), row.scenario


def test_replay_is_deterministic(lib):
    a, b = run(lib, True), run(lib, True)
    assert a.detections == b.detections and [e.record() for e in a.events] == [e.record() for e in b.events]


def test_attack_2_is_300_new_files_and_nothing_deterministic(lib):
    r = run(lib, False)
    row = rows_of([Row.of(d) for d in lib.ground_truth], "attack-2")[0]
    events, dets = r.within(row)
    assert len({e.path for e in events if e.kind == "write"}) == 300 and dets == []


def test_ground_truth_csv(tmp_path, lib):
    p = tmp_path / "ground_truth.csv"
    p.write_text("scenario,label,namespace,pod_prefix,start,end,expected\n"
                 "benign-1,benign,demo,demo-app,2026-09-28T10:20:00Z,2026-09-28T10:21:00Z,nothing above Low\n"
                 "attack-1,malicious,demo,demo-app,2026-09-28T10:14:00Z,2026-09-28T10:15:00Z,D_exec undeclared + D_write\n")
    rows = read_ground_truth(p)
    assert [r.scenario for r in rows] == ["benign-1", "attack-1"] and rows[1].expected == "D_exec undeclared + D_write"
    det = {"namespace": "demo", "pod": "demo-app-7d9f", "time": "2026-09-28T10:14:22.123Z"}
    assert rows[1].holds(det) and not rows[0].holds(det)
    assert not rows[1].holds({**det, "pod": "other"}) and not rows[1].holds({**det, "namespace": "x"})
    assert not rows[1].holds({**det, "time": "not a time"})


def test_ground_truth_row_needs_times():
    with pytest.raises(ValueError):
        Row.of({"scenario": "x", "start": "yesterday", "end": "2026-09-28T10:15:00Z"})
