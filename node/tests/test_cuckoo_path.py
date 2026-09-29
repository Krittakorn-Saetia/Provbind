"""The reference Cuckoo filter on the event path (Eq. 52, CF-05): it may save time, never change a verdict."""
import json

import pytest

import node.store as store_module
from node.ref_cuckoo import CuckooFilter
from node.scenarios import replay
from node.store import Envelope, Store
from node.synth import DIGEST, SAMPLE, benign_session, demo_bindings, demo_envelope, library
from node.verify import Egress


def test_the_filter_holds_every_declared_path():
    env = Envelope.prepare(demo_envelope(), cuckoo=True)
    assert env.filter is not None and not env.filter_full
    assert all(p in env.filter for p in env.j.path)                          # CF-01 on the node's filter


@pytest.mark.parametrize("path", ["/usr/bin/ls", "/bin/sh", "/usr/local/bin/python", "/tmp/.x9", "/etc/passwd",
                                  "/app/data/seed.json", "", None, "relative"])
def test_lookups_agree_with_and_without_the_filter(path):
    doc = demo_envelope()
    assert Envelope.prepare(doc, cuckoo=True).lookup(path) == Envelope.prepare(doc).lookup(path)


def test_a_false_positive_only_costs_a_lookup(monkeypatch):
    env = Envelope.prepare(demo_envelope(), cuckoo=True)

    class Yes:
        def __contains__(self, key):
            return True                                                  # every answer "maybe"
    env.filter = Yes()
    assert env.lookup("/tmp/.x9") == (None, None) and env.lookup("/usr/bin/ls")[0] == "/usr/bin/ls"


@pytest.mark.parametrize("hashes", [True, False])
def test_detections_are_identical_with_the_filter_on_and_off(hashes):
    lib = library()
    hasher = (lambda e: lib.hashes.get((e.container_id, e.pid))) if hashes else None
    lines = lib.lines + benign_session(600, seed=3, start="2026-09-28T10:05:00Z")
    runs = [replay(lines, Store.static([lib.envelope], lib.bindings, cuckoo=c), egress=Egress(lib.egress),
                   hasher=hasher).detections for c in (False, True)]
    assert runs[0] == runs[1] and len(runs[0]) >= 13


def test_a_full_filter_is_dropped_loudly_not_silently(monkeypatch):
    class Tiny(CuckooFilter):
        def add(self, key):
            return self.count < 3 and super().add(key)
    monkeypatch.setattr(store_module, "CuckooFilter", Tiny)
    doc = json.loads(SAMPLE.read_text(encoding="utf-8"))
    env = Envelope.prepare(doc, cuckoo=True)
    assert env.filter is None and env.filter_full
    assert env.lookup("/usr/bin/ls")[0] == "/usr/bin/ls"                     # the index still answers
    s = Store.static([doc], {k: v for k, v in demo_bindings().items() if v["verified"]}, cuckoo=True)
    assert s.envelope(DIGEST) is not None and s.stats["filter_full"] == 1


def test_node_run_with_the_filter_gives_the_same_detections(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    lib = library(attack2_files=20)
    (tmp_path / "envelopes").mkdir()
    (tmp_path / "envelopes" / f"{DIGEST[7:]}.json").write_text(json.dumps(lib.envelope))
    (tmp_path / "bindings.json").write_text(json.dumps(lib.bindings))
    (tmp_path / "rec.jsonl").write_text("\n".join(lib.lines) + "\n")
    out = []
    for flag in ([], ["--cuckoo"]):
        det = tmp_path / "detections.jsonl"
        if det.exists():
            det.unlink()
        proc = subprocess.run([sys.executable, "-m", "node.run", "--run", str(tmp_path), "--replay",
                               str(tmp_path / "rec.jsonl"), "--no-events", *flag],
                              cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stderr
        out.append(det.read_text())
    assert out[0] == out[1]
