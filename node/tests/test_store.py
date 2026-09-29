"""node/store.py: bindings and envelopes from the run folder; one cached envelope per digest (Eq. 52)."""
import hashlib
import json
import os

import pytest

from node.store import Binding, Envelope, Store, bare_id, hex_of, under
from node.synth import DEMO_CID, DIGEST, SAMPLE, UNSIGNED_CID, demo_bindings, demo_envelope

OTHER = "sha256:" + "22" * 32


def sample_doc():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def binding_doc(digest=DIGEST, verified=True, mounts=("/etc/hosts",)):
    return {"namespace": "demo", "pod": "demo-app-7d9f", "container": "app", "image_digest": digest,
            "verified": verified, "run_as_root": True, "privileged": False, "mounts": list(mounts),
            "envelope_ready": True}


def cid(n):
    return "containerd://" + hashlib.sha256(str(n).encode()).hexdigest()


class RunDir:
    """A run folder that a test changes as the controller and compiler would."""

    def __init__(self, path):
        self.path = path
        (path / "envelopes").mkdir(parents=True)

    def bindings(self, doc):
        tmp = self.path / "bindings.json.tmp"
        tmp.write_text(json.dumps(doc), encoding="utf-8")
        os.replace(tmp, self.path / "bindings.json")          # atomic, as §3.2 asks

    def envelope(self, doc, name=None):
        p = self.path / "envelopes" / (name or f"{hex_of(doc['image']['digest'])}.json")
        p.write_text(json.dumps(doc), encoding="utf-8")
        return p


@pytest.fixture
def run(tmp_path):
    return RunDir(tmp_path)


# Envelope --------------------------------------------------------------------------------------

def test_prepare_builds_the_indices_and_sets():
    env = Envelope.prepare(sample_doc())
    assert env.digest == DIGEST
    assert env.closure == frozenset(sample_doc()["closure"])
    assert env.j.path["/usr/bin/ls"][1] == 0 and len(env.j.path) == len(sample_doc()["files"])
    assert env.caps == {} and env.cap_origin == "INFERRED"


@pytest.mark.parametrize("key", ["image", "files", "symlinks", "closure", "capabilities", "layers", "packages"])
def test_prepare_refuses_an_envelope_without_a_section(key):
    doc = sample_doc()
    del doc[key]
    with pytest.raises(ValueError):
        Envelope.prepare(doc)


def test_prepare_refuses_a_file_in_an_unknown_layer():
    doc = sample_doc()
    doc["files"]["/x"] = {"sha256": "0" * 64, "layer": 99, "package": None, "mode": "0644"}
    with pytest.raises(ValueError):
        Envelope.prepare(doc)


def test_unknown_capability_origin_is_treated_as_inferred():
    doc = sample_doc()
    doc["capabilities"] = [{"cap": "CAP_KILL", "origin": "SIGNED?"}, {"cap": 5}]
    assert Envelope.prepare(doc).caps == {"CAP_KILL": "INFERRED"}


def test_lookup_and_context():
    env = Envelope.prepare(sample_doc())
    assert env.lookup("/usr/bin/ls")[0] == "/usr/bin/ls"
    assert env.lookup("/bin/sh")[0] == "/usr/bin/dash"
    assert env.lookup("/tmp/.x9") == (None, None) and env.lookup(None) == (None, None)
    assert env.context(None) == {"declared": False, "package": None, "depth": None, "layer": None}
    assert env.context("/usr/local/lib/python3.11/site-packages/requests/__init__.py") == \
           {"declared": True, "package": "pkg:pypi/requests@2.32.3", "depth": 1, "layer": 4}
    assert env.context("/etc/passwd") == {"declared": True, "package": None, "depth": None, "layer": 0}


# Binding and mounts ------------------------------------------------------------------------------

def test_binding_parse_is_strict_about_types():
    b = Binding.parse("containerd://a", {"image_digest": 5, "verified": "yes", "mounts": ["/ok", "rel", 3, "/b/"],
                                          "envelope_ready": 1, "run_as_root": "true"})
    assert (b.image_digest, b.verified, b.mounts, b.envelope_ready, b.run_as_root) == \
           (None, False, ("/ok", "/b/"), False, None)


@pytest.mark.parametrize("path,mounts,expected", [
    ("/etc/hosts", ["/etc/hosts"], True), ("/etc/hostsx", ["/etc/hosts"], False),
    ("/app/data/a/b", ["/app/data/"], True), ("/app/database", ["/app/data"], False),
    ("/anything", ["/"], True), ("/etc/passwd", [], False),
])
def test_under(path, mounts, expected):
    assert under(path, mounts) is expected


def test_mounts_include_the_real_path_in_the_image():
    doc = sample_doc()
    doc["symlinks"]["/var/run"] = "/run"
    env = Envelope.prepare(doc)
    s = Store.static([doc], {DEMO_CID: binding_doc(mounts=["/var/run/secrets/kubernetes.io/serviceaccount/"])})
    mounts = s.mounts(s.binding(DEMO_CID), env)
    assert mounts == ("/var/run/secrets/kubernetes.io/serviceaccount", "/run/secrets/kubernetes.io/serviceaccount")


def test_ids():
    assert bare_id("containerd://abc") == "abc" and bare_id("abc") == "abc" and hex_of(DIGEST) == DIGEST[7:]


# static store: lookups and references -------------------------------------------------------------

def test_binding_lookup_by_full_bare_and_unique_prefix():
    twin_a, twin_b = "containerd://" + "ab" * 10 + "0" * 44, "containerd://" + "ab" * 10 + "1" * 44
    s = Store.static([], {cid(1): binding_doc(), cid(2): binding_doc(), twin_a: binding_doc(), twin_b: binding_doc()})
    full = cid(1)
    assert s.binding(full).container_id == full
    assert s.binding(bare_id(full)).container_id == full                     # no runtime prefix
    assert s.binding(bare_id(full)[:31]).container_id == full               # Tetragon's docker field
    assert s.binding(bare_id(full)[:11]) is None                            # too short to trust
    assert s.binding("ab" * 10) is None                                     # ambiguous: two start so
    assert s.binding("containerd://" + "f" * 64) is None


def test_envelope_is_served_only_for_verified_bound_digests():
    s = Store.static([sample_doc()], {UNSIGNED_CID: binding_doc(verified=False)})
    assert s.envelope(DIGEST) is None                                       # bound, but not verified
    s.set_bindings({DEMO_CID: binding_doc()})
    assert s.envelope(DIGEST).digest == DIGEST
    assert s.envelope(OTHER) is None and s.envelope(None) is None


def test_five_replicas_share_one_envelope_and_it_is_evicted_at_zero():
    """PH4-04's logic: scale to 5, then to 0."""
    s = Store.static([sample_doc()], {})
    s.set_bindings({cid(i): binding_doc() for i in range(1, 6)})
    envs = {id(s.envelope(DIGEST)) for _ in range(5)}
    assert len(envs) == 1 and s.refs[DIGEST] == 5 and s.stats["loads"] == 1 and list(s.cache) == [DIGEST]
    s.set_bindings({cid(1): binding_doc()})
    assert s.refs[DIGEST] == 1 and list(s.cache) == [DIGEST]
    s.set_bindings({})
    assert s.cache == {} and s.stats["evictions"] == 1 and s.envelope(DIGEST) is None


def test_was_bound_remembers_containers_that_left():
    s = Store.static([sample_doc()], {DEMO_CID: binding_doc()})
    s.set_bindings({})
    assert s.binding(DEMO_CID) is None and s.was_bound(DEMO_CID) and s.was_bound(bare_id(DEMO_CID)[:20])
    assert not s.was_bound(cid(9))


# file-backed store --------------------------------------------------------------------------------

def test_empty_run_folder(run):
    s = Store(run.path)
    assert s.refresh() is True and s.bindings == {} and s.refresh() is False


def test_envelope_appears_after_its_binding(run):
    run.bindings({DEMO_CID: binding_doc()})
    s = Store(run.path)
    s.refresh()
    assert s.envelope(DIGEST) is None                                       # compiler still running
    run.envelope(sample_doc())
    assert s.refresh() is True
    assert s.envelope(DIGEST).digest == DIGEST and s.stats["loads"] == 1


def test_envelope_named_by_the_full_digest_is_found(run):
    run.envelope(sample_doc(), name=f"{DIGEST}.json")
    run.bindings({DEMO_CID: binding_doc()})
    s = Store(run.path)
    s.refresh()
    assert s.envelope(DIGEST) is not None


def test_bindings_reload_on_change_and_evict(run):
    run.envelope(sample_doc())
    run.bindings({DEMO_CID: binding_doc()})
    s = Store(run.path)
    s.refresh()
    assert s.envelope(DIGEST) is not None
    run.bindings({})
    assert s.refresh() is True and s.cache == {} and s.stats["evictions"] == 1
    assert s.was_bound(DEMO_CID)


def test_unreadable_bindings_keep_the_previous_ones(run):
    run.bindings({DEMO_CID: binding_doc()})
    s = Store(run.path)
    s.refresh()
    (run.path / "bindings.json").write_text("{half a file", encoding="utf-8")
    assert s.refresh() is False and s.binding(DEMO_CID) is not None and s.stats["bad_bindings"] == 1


def test_bad_envelope_is_counted_and_retried_only_when_it_changes(run):
    run.bindings({DEMO_CID: binding_doc()})
    p = run.path / "envelopes" / f"{hex_of(DIGEST)}.json"
    p.write_text("{not json", encoding="utf-8")
    s = Store(run.path)
    s.refresh()
    assert s.envelope(DIGEST) is None and s.stats["bad_envelopes"] == 1
    s.refresh()
    s.envelope(DIGEST)
    assert s.stats["bad_envelopes"] == 1                                   # same file: not re-read
    run.envelope(sample_doc())
    s.refresh()
    assert s.envelope(DIGEST) is not None


def test_envelope_filed_under_another_digest_is_refused(run):
    doc = sample_doc()
    run.envelope(doc, name=f"{hex_of(OTHER)}.json")
    run.bindings({DEMO_CID: binding_doc(digest=OTHER)})
    s = Store(run.path)
    s.refresh()
    assert s.envelope(OTHER) is None and s.stats["bad_envelopes"] == 1     # never checked against it


def test_recompiled_envelope_is_reloaded(run):
    run.bindings({DEMO_CID: binding_doc()})
    run.envelope(sample_doc())
    s = Store(run.path)
    s.refresh()
    assert "/usr/bin/cat" not in s.envelope(DIGEST).j.path
    doc = demo_envelope()
    p = run.envelope(doc)
    os.utime(p, ns=(1, 1))                                               # a different stamp, surely
    assert s.refresh() is True
    assert "/usr/bin/cat" in s.envelope(DIGEST).j.path and s.stats["reloads"] == 1


def test_hits_and_misses_are_counted():
    s = Store.static([sample_doc()], {DEMO_CID: binding_doc()})
    s.envelope(DIGEST)
    s.envelope(DIGEST)
    s.envelope(OTHER)
    assert (s.stats["hits"], s.stats["misses"]) == (2, 1)


def test_demo_bindings_fixture_is_consistent():
    s = Store.static([demo_envelope()], demo_bindings())
    assert s.binding(DEMO_CID).verified and not s.binding(UNSIGNED_CID).verified
    assert s.envelope(DIGEST) is not None
