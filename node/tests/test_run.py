"""node/run.py and node/output.py: `python -m node.run` end to end, in replay and live mode."""
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from node.output import Collector, DetectionWriter, EventWriter, last_detection_number
from node.store import hex_of
from node.synth import DIGEST, library

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = {("D_exec", "outside_closure"): 3, ("D_exec", "undeclared"): 2, ("D_write", "declared_file"): 2,
            ("D_load", "undeclared"): 1, ("D_cap", "not_in_envelope"): 1, ("D_load", "outside_closure"): 1,
            ("binding", "unverified"): 1, ("binding", "unknown_container"): 1}    # path-only; D_net needs --egress


@pytest.fixture(scope="module")
def lib():
    return library(attack2_files=30)


@pytest.fixture
def run(tmp_path, lib):
    (tmp_path / "envelopes").mkdir()
    (tmp_path / "envelopes" / f"{hex_of(DIGEST)}.json").write_text(json.dumps(lib.envelope))
    (tmp_path / "bindings.json").write_text(json.dumps(lib.bindings))
    (tmp_path / "rec.jsonl").write_text("\n".join(lib.lines) + "\n")
    (tmp_path / "egress.json").write_text(json.dumps({"allow": lib.egress}))
    return tmp_path


def node_run(*args, stdin=None):
    return subprocess.run([sys.executable, "-m", "node.run", *args], cwd=ROOT, capture_output=True, text=True,
                          input=stdin, timeout=120)


def jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def counts(dets):
    out = {}
    for d in dets:
        out[(d["class"], d["subclass"])] = out.get((d["class"], d["subclass"]), 0) + 1
    return out


def test_replay_writes_events_and_detections(run, lib):
    proc = node_run("--run", str(run), "--replay", str(run / "rec.jsonl"))
    assert proc.returncode == 0, proc.stderr
    dets = jsonl(run / "detections.jsonl")
    assert counts(dets) == EXPECTED
    assert [d["id"] for d in dets] == [f"det-{i:04d}" for i in range(1, len(dets) + 1)]
    events = jsonl(run / "events.jsonl")
    assert {e["kind"] for e in events} == {"exec", "write", "load", "exit"}      # cap, connect: Q1
    assert all(list(e)[:10] == ["time", "kind", "container_id", "namespace", "pod", "container", "pid", "ppid",
                                "exe", "parent_exe"] for e in events)
    summary = json.loads(proc.stdout)
    assert summary["detections"] == len(dets) and summary["events"] == len(lib.lines)
    assert summary["envelopes"]["cached"] == [DIGEST] and summary["held"]["unbound_events"] == 1


def test_detection_ids_continue_after_a_restart(run):
    assert node_run("--run", str(run), "--replay", str(run / "rec.jsonl")).returncode == 0
    first = len(jsonl(run / "detections.jsonl"))
    assert node_run("--run", str(run), "--replay", str(run / "rec.jsonl"), "--no-events").returncode == 0
    ids = [d["id"] for d in jsonl(run / "detections.jsonl")]
    assert len(ids) == 2 * first and len(set(ids)) == len(ids) and ids[-1] == f"det-{2 * first:04d}"


def test_egress_list_turns_on_d_net(run):
    assert node_run("--run", str(run), "--replay", str(run / "rec.jsonl"), "--egress", str(run / "egress.json"),
                    "--no-events").returncode == 0
    assert counts(jsonl(run / "detections.jsonl")) == {**EXPECTED, ("D_net", "not_allowed"): 1}


def test_no_events_writes_no_events_file(run):
    assert node_run("--run", str(run), "--replay", str(run / "rec.jsonl"), "--no-events").returncode == 0
    assert not (run / "events.jsonl").exists()


def test_replaying_events_jsonl_loses_what_it_cannot_carry(run):
    """Q1: events.jsonl has no fields for cap and connect, so a replay of it has no D_cap or D_net."""
    assert node_run("--run", str(run), "--replay", str(run / "rec.jsonl")).returncode == 0
    (run / "detections.jsonl").rename(run / "first.jsonl")
    (run / "events.jsonl").rename(run / "copy.jsonl")
    assert node_run("--run", str(run), "--replay", str(run / "copy.jsonl"), "--no-events").returncode == 0
    expected = dict(EXPECTED)
    del expected[("D_cap", "not_in_envelope")]
    assert counts(jsonl(run / "detections.jsonl")) == expected


@pytest.mark.parametrize("problem", ["missing", "same"])
def test_bad_replay_input_exits_3(run, problem):
    if problem == "missing":
        proc = node_run("--run", str(run), "--replay", str(run / "nope.jsonl"))
    else:
        (run / "events.jsonl").write_text("")
        proc = node_run("--run", str(run), "--replay", str(run / "events.jsonl"))
    assert proc.returncode == 3 and proc.stdout == ""


def test_live_mode_reads_stdin_until_eof(run, lib):
    proc = node_run("--run", str(run), "--tick", "0.05", stdin="\n".join(lib.lines) + "\n")
    assert proc.returncode == 0, proc.stderr
    assert counts(jsonl(run / "detections.jsonl")) == EXPECTED
    assert json.loads(proc.stdout)["events"] == len(lib.lines)


def test_live_mode_picks_up_bindings_written_later(run, tmp_path):
    """The controller writes the binding after the container starts: nothing is lost or misreported.

    Live mode measures the grace period on the wall clock, so the stream starts now: a fixed date
    would be more than --grace in the past on any later day, and every held event would become
    binding / unknown_container."""
    lib = library(attack2_files=30, start=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    (run / "bindings.json").unlink()
    child = subprocess.Popen([sys.executable, "-m", "node.run", "--run", str(run), "--tick", "0.05",
                              "--grace", "3600"], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    head, tail = lib.lines[:40], lib.lines[40:]
    child.stdin.write("\n".join(head) + "\n")
    child.stdin.flush()
    time.sleep(0.5)
    (run / "bindings.json").write_text(json.dumps(lib.bindings))
    time.sleep(0.5)
    child.stdin.write("\n".join(tail) + "\n")
    out, err = child.communicate(timeout=60)
    assert child.returncode == 0, err
    dets = jsonl(run / "detections.jsonl")
    assert counts(dets) == EXPECTED
    assert json.loads(out)["cold_start_s"]                          # the held window was measured


def test_summary_file(run):
    assert node_run("--run", str(run), "--replay", str(run / "rec.jsonl"), "--summary", str(run / "s.json")).returncode == 0
    assert json.loads((run / "s.json").read_text())["detections"] == sum(EXPECTED.values())


# output.py ----------------------------------------------------------------------------------------

def test_last_detection_number(tmp_path):
    p = tmp_path / "d.jsonl"
    assert last_detection_number(p) == 0
    p.write_text('{"id":"det-0007"}\n{"id": "det-0012", "x": 1}\n{"id":"alr-0099"}\n')
    assert last_detection_number(p) == 12


def test_writers(tmp_path):
    from node.normalize import Event
    w = DetectionWriter(tmp_path / "d.jsonl")
    w({"id": None, "class": "D_exec"})
    w({"id": None, "class": "D_write"})
    w.close()
    assert [d["id"] for d in jsonl(tmp_path / "d.jsonl")] == ["det-0001", "det-0002"]
    e = EventWriter(tmp_path / "e.jsonl")
    base = dict(time="2026-09-28T10:00:00Z", t=0, container_id="c", namespace="demo", pod="p", container="app",
                pid=1, ppid=0, exe="/x", parent_exe=None)
    e(Event(kind="exec", **base))
    e(Event(kind="cap", cap="CAP_KILL", granted=True, **base))
    e.close()
    assert [r["kind"] for r in jsonl(tmp_path / "e.jsonl")] == ["exec"]
    assert (tmp_path / "e.jsonl").read_text().startswith('{"time":"2026-09-28T10:00:00Z","kind":"exec"')


def test_collector_numbers_detections():
    c = Collector()
    c({"id": None})
    c({"id": None})
    c("an event")
    assert [x["id"] for x in c.items[:2]] == ["det-0001", "det-0002"] and c.items[2] == "an event"


def test_a_line_with_bad_bytes_is_one_dropped_line(run, lib):
    bad = b'{"bad": "\xff\xfe"}\n{"half": "\xff\n'           # valid JSON apart from the bytes; broken JSON
    data = ("\n".join(lib.lines[:5]) + "\n").encode() + bad + ("\n".join(lib.lines[5:]) + "\n").encode()
    (run / "rec.jsonl").write_bytes(data)
    proc = node_run("--run", str(run), "--replay", str(run / "rec.jsonl"), "--no-events")
    assert proc.returncode == 0, proc.stderr
    summary = json.loads(proc.stdout)
    assert summary["events"] == len(lib.lines) and summary["dropped"] == {"other_event": 1, "bad_json": 1}
