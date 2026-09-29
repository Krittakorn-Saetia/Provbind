"""node/verify.py: the decision order (Eqs. 53-56, M12), detection records (§4.4) and the egress list.

Envelope: contracts/envelope.sample.json exactly, or node/synth.py's demo_envelope() (the sample
plus the files the scenarios touch). Bindings: Sprint Handoff §4.2's mounts."""
import json

import pytest

from node.normalize import Event, parse_time
from node.store import Binding, Envelope
from node.synth import DEMO_CID, DEMO_POD, DIGEST, SAMPLE, demo_bindings, demo_envelope, fake_sha
from node.verify import FIELDS, PATH_ONLY, SUPPRESSED, WEAK, Egress, Verifier, binding_failure, detection, is_weak

PY = "/usr/local/bin/python3.11"
MOUNTS = ("/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/dev/termination-log",
          "/var/run/secrets/kubernetes.io/serviceaccount", "/app/data")


def ev(kind="exec", **kw):
    base = dict(time="2026-09-28T10:14:22.123Z", t=parse_time("2026-09-28T10:14:22.123Z"), kind=kind,
                container_id=DEMO_CID, namespace="demo", pod=DEMO_POD, container="app", pid=4471, ppid=4402,
                exe=PY, parent_exe=None)
    base.update(kw)
    return Event(**base)


def sample():
    return Envelope.prepare(json.loads(SAMPLE.read_text(encoding="utf-8")))


@pytest.fixture
def env():
    return Envelope.prepare(demo_envelope())


@pytest.fixture
def b():
    return Binding.parse(DEMO_CID, demo_bindings()[DEMO_CID])


def check(env, binding, event, mounts=MOUNTS, egress=None):
    return Verifier(egress).verify(event, env, binding, mounts)


def kind_of(det):
    return None if det is None else (det["class"], det["subclass"])


# Sprint Handoff §7, Day 2: the replay table, on the contract's sample envelope --------------------

@pytest.mark.parametrize("event,expected", [
    (ev("exec", exe="/tmp/.x9", parent_exe=PY), ("D_exec", "undeclared")),
    (ev("exec", exe="/usr/bin/ls"), ("D_exec", "outside_closure")),
    (ev("exec", exe=PY), None),
    (ev("write", exe="/tmp/.x9", path="/etc/passwd"), ("D_write", "declared_file")),
    (ev("write", path="/etc/hosts"), None),
    (ev("write", path="/tmp/cache.json"), None),
])
def test_handoff_replay_table(b, event, expected):
    assert kind_of(check(sample(), b, event)) == expected


def test_etc_hosts_is_spared_by_the_mount_rule_even_when_declared(env, b):
    assert "/etc/hosts" in env.j.path
    assert check(env, b, ev("write", path="/etc/hosts")) is None
    assert kind_of(check(env, b, ev("write", path="/etc/hosts"), mounts=())) == ("D_write", "declared_file")


# the §4.4 record ---------------------------------------------------------------------------------

def test_record_matches_the_handoff_example(b):
    example = {"id": "det-0001", "time": "2026-09-28T10:14:22.123Z", "container_id": "containerd://4b1c…",
               "namespace": "demo", "pod": "demo-app-7d9f", "container": "app", "image_digest": "sha256:1111…",
               "pid": 4471, "ppid": 4402, "exe": "/tmp/.x9", "parent_exe": "/usr/local/bin/python3.11",
               "class": "D_exec", "subclass": "undeclared",
               "clause": {"kind": "file_set", "path": "/tmp/.x9", "detail": "path is in no layer of the attested image"},
               "origin": "AUTHENTICATED",
               "context": {"declared": False, "package": None, "depth": None, "layer": None}}
    det = check(sample(), b, ev("exec", exe="/tmp/.x9", parent_exe=PY, hash=fake_sha("x9 payload")))
    det["id"] = "det-0001"
    assert list(det) == list(example) == list(FIELDS)
    assert list(det["clause"]) == list(example["clause"]) and list(det["context"]) == list(example["context"])
    assert {k: type(v) for k, v in det.items() if k != "image_digest"} == \
           {k: type(v) for k, v in example.items() if k != "image_digest"}
    assert (det["clause"], det["origin"], det["context"]) == (example["clause"], example["origin"], example["context"])
    assert (det["image_digest"], det["pid"], det["ppid"], det["exe"]) == (DIGEST, 4471, 4402, "/tmp/.x9")


def test_path_only_undeclared_says_so(b):
    det = check(sample(), b, ev("exec", exe="/tmp/.x9"))
    assert det["clause"]["detail"] == "path is in no layer of the attested image" + PATH_ONLY


def test_context_names_the_owning_package_and_its_depth(env, b):
    det = check(env, b, ev("exec", exe="/usr/bin/ls"))
    assert det["context"] == {"declared": True, "package": "pkg:deb/debian/coreutils@9.1-1?arch=amd64&distro=debian-12",
                              "depth": None, "layer": 0}
    det = check(env, b, ev("write", path="/usr/local/lib/python3.11/site-packages/requests/__init__.py"))
    assert det["context"] == {"declared": True, "package": "pkg:pypi/requests@2.32.3", "depth": 1, "layer": 4}


# exec ------------------------------------------------------------------------------------------

def test_modified_declared_binary_is_d_hash_even_outside_the_closure(env, b):
    det = check(env, b, ev("exec", exe="/usr/bin/ls", hash=env.j.path["/usr/bin/cat"][0]))
    assert kind_of(det) == ("D_hash", "modified") and det["clause"]["path"] == "/usr/bin/ls"


def test_declared_binary_with_its_own_hash_in_the_closure_conforms(env, b):
    assert check(env, b, ev("exec", exe=PY, hash=env.j.path[PY][0])) is None


def test_relocated_binary_is_one_d_hash_not_also_d_exec(env, b):
    """M12: an exec at a new path with declared content fits D_exec and D_hash; the order picks one."""
    det = check(env, b, ev("exec", exe="/tmp/.l", hash=env.j.path["/usr/bin/ls"][0]))
    assert kind_of(det) == ("D_hash", "relocated")
    assert det["clause"] == {"kind": "file_hash", "path": "/tmp/.l",
                             "detail": "in no layer, but its content is the declared /usr/bin/ls"}
    assert det["context"]["declared"] is False


def test_relocated_names_every_declared_copy(b):
    doc = demo_envelope()
    doc["files"]["/usr/bin/ls2"] = dict(doc["files"]["/usr/bin/ls"])
    env = Envelope.prepare(doc)
    det = check(env, b, ev("exec", exe="/tmp/.l", hash=doc["files"]["/usr/bin/ls"]["sha256"]))
    assert det["clause"]["detail"].endswith("/usr/bin/ls and 1 more")


def test_undeclared_with_an_unknown_hash_has_no_path_only_note(env, b):
    det = check(env, b, ev("exec", exe="/tmp/.x9", hash=fake_sha("new")))
    assert kind_of(det) == ("D_exec", "undeclared") and PATH_ONLY not in det["clause"]["detail"]


@pytest.mark.parametrize("name,real,expected", [
    ("/bin/sh", "/usr/bin/dash", ("D_exec", "outside_closure")),       # /bin -> /usr/bin, sh -> dash
    ("/usr/local/bin/python", PY, None),                             # python -> python3.11, in the closure
    ("/bin/ls", "/usr/bin/ls", ("D_exec", "outside_closure")),
])
def test_names_through_image_symlinks_are_resolved_when_the_raw_path_misses(env, b, name, real, expected):
    det = check(env, b, ev("exec", exe=name))
    assert kind_of(det) == expected
    if det:
        assert det["clause"]["path"] == real


def test_a_symlink_loop_is_undeclared(b):
    doc = demo_envelope()
    doc["symlinks"].update({"/a": "/b", "/b": "/a"})
    assert kind_of(check(Envelope.prepare(doc), b, ev("exec", exe="/a/x"))) == ("D_exec", "undeclared")


def test_relative_exe_is_undeclared(env, b):
    assert kind_of(check(env, b, ev("exec", exe="x9"))) == ("D_exec", "undeclared")


# load ------------------------------------------------------------------------------------------

def test_mapping_of_the_process_own_executable_is_skipped(env, b):
    assert check(env, b, ev("load", exe="/tmp/.x9", path="/tmp/.x9")) is None


def test_closure_library_conforms(env, b):
    assert check(env, b, ev("load", path="/usr/lib/x86_64-linux-gnu/libc.so.6")) is None


def test_library_in_no_layer_is_d_load_undeclared_whoever_maps_it(env, b):
    for exe in (PY, "/usr/bin/ls", "/tmp/.x9"):
        det = check(env, b, ev("load", exe=exe, path="/tmp/libx.so"))
        assert kind_of(det) == ("D_load", "undeclared") and det["clause"]["path"] == "/tmp/libx.so"


def test_declared_library_outside_the_closure_is_weak_once_per_container(env, b):
    v = Verifier()
    nss = "/usr/lib/x86_64-linux-gnu/libnss_dns.so.2"
    first = v.verify(ev("load", path=nss), env, b, MOUNTS)
    assert kind_of(first) == ("D_load", "outside_closure") and is_weak(first)
    assert v.verify(ev("load", path=nss, pid=5000), env, b, MOUNTS) is SUPPRESSED
    other = ev("load", path=nss, container_id="containerd://" + "ab" * 32)
    assert kind_of(v.verify(other, env, b, MOUNTS)) == ("D_load", "outside_closure")


def test_libraries_of_a_process_outside_the_closure_are_not_judged(env, b):
    assert check(env, b, ev("load", exe="/usr/bin/ls", path="/usr/lib/x86_64-linux-gnu/libselinux.so.1")) is SUPPRESSED


def test_suppressed_is_counted_apart_from_conforming(env, b):
    v = Verifier()
    v.verify(ev("load", exe="/usr/bin/ls", path="/usr/lib/x86_64-linux-gnu/libselinux.so.1"), env, b, MOUNTS)
    assert v.stats == {"suppressed": 1} and repr(SUPPRESSED) == "SUPPRESSED"


def test_modified_library_is_d_hash(env, b):
    det = check(env, b, ev("load", path="/usr/lib/x86_64-linux-gnu/libc.so.6", hash=fake_sha("evil libc")))
    assert kind_of(det) == ("D_hash", "modified")


# write -----------------------------------------------------------------------------------------

def test_write_to_a_new_file_conforms(env, b):
    assert check(env, b, ev("write", path="/tmp/new.txt")) is None


@pytest.mark.parametrize("path", ["/app/data/seed.json", "/app/data", "/etc/hosts"])
def test_write_under_a_mount_conforms(env, b, path):
    assert check(env, b, ev("write", path=path)) is None


def test_mount_prefix_is_a_directory_not_a_string_prefix(b):
    doc = demo_envelope()
    doc["files"]["/app/database.db"] = {"sha256": fake_sha("db"), "layer": 5, "package": None, "mode": "0644"}
    det = check(Envelope.prepare(doc), b, ev("write", path="/app/database.db"))
    assert kind_of(det) == ("D_write", "declared_file")                  # /app/data does not cover it


def test_write_without_a_path_conforms(env, b):
    assert check(env, b, ev("write", path=None)) is None


# cap -------------------------------------------------------------------------------------------

def test_denied_capability_check_conforms(env, b):
    assert check(env, b, ev("cap", cap="CAP_SYS_ADMIN", granted=False)) is None


def test_capability_outside_an_inferred_set_is_d_cap_inferred(env, b):
    det = check(env, b, ev("cap", cap="CAP_CHOWN", granted=True))
    assert kind_of(det) == ("D_cap", "not_in_envelope") and det["origin"] == "INFERRED"
    assert det["clause"]["kind"] == "capabilities" and det["clause"]["path"] == PY
    assert det["clause"]["detail"] == "CAP_CHOWN used; the envelope's capabilities: none"
    assert det["context"]["declared"] is True


@pytest.mark.parametrize("origins,expected", [
    (["AUTHENTICATED"], "AUTHENTICATED"), (["AUTHENTICATED", "INFERRED"], "INFERRED"),
    (["CONFIGURED"], "CONFIGURED"), (["AUTHENTICATED", "CONFIGURED"], "CONFIGURED"), ([], "INFERRED"),
])
def test_d_cap_origin_follows_the_capability_set(b, origins, expected):
    doc = demo_envelope()
    doc["capabilities"] = [{"cap": f"CAP_X{i}", "origin": o} for i, o in enumerate(origins)]
    det = check(Envelope.prepare(doc), b, ev("cap", cap="CAP_CHOWN", granted=True))
    assert det["origin"] == expected


def test_capability_in_the_envelope_conforms(b):
    doc = demo_envelope()
    doc["capabilities"] = [{"cap": "CAP_NET_BIND_SERVICE", "origin": "INFERRED"}]
    assert check(Envelope.prepare(doc), b, ev("cap", cap="CAP_NET_BIND_SERVICE", granted=True)) is None


def test_capability_check_without_a_return_value_counts_as_used(env, b):
    det = check(env, b, ev("cap", cap="CAP_CHOWN", granted=None))
    assert "return value unknown" in det["clause"]["detail"]


# connect ---------------------------------------------------------------------------------------

def test_connect_without_an_egress_list_conforms(env, b):
    assert check(env, b, ev("connect", daddr="203.0.113.9", dport=4444, protocol="tcp")) is None


def test_connect_outside_the_egress_list_is_d_net(env, b):
    egress = Egress(["10.96.0.0/12", "127.0.0.0/8"])
    assert check(env, b, ev("connect", daddr="10.96.0.10", dport=53), egress=egress) is None
    det = check(env, b, ev("connect", daddr="203.0.113.9", dport=4444, protocol="tcp"), egress=egress)
    assert kind_of(det) == ("D_net", "not_allowed") and det["origin"] == "CONFIGURED"
    assert det["clause"]["detail"] == "203.0.113.9:4444/tcp is not in the egress allow list"


@pytest.mark.parametrize("entry,daddr,dport,allowed", [
    ("10.96.0.0/12", "10.96.0.10", 53, True), ("10.96.0.0/12", "10.112.0.1", 53, False),
    ("10.96.0.10/32:53", "10.96.0.10", 53, True), ("10.96.0.10/32:53", "10.96.0.10", 80, False),
    ("127.0.0.1:8080", "127.0.0.1", 8080, True), ("*:443", "198.51.100.7", 443, True),
    ("*:443", "198.51.100.7", 80, False), ("[::1]:8080", "::1", 8080, True), ("fd00::/8", "fd12::1", 1, True),
    ("fd00::/8", "10.0.0.1", 1, False), ("10.0.0.0/8", "not-an-ip", 1, False),
])
def test_egress_entries(entry, daddr, dport, allowed):
    assert Egress([entry]).allows(daddr, dport) is allowed


@pytest.mark.parametrize("entry", ["", "  ", "10.0.0.0/33", "host.example:443", 7])
def test_bad_egress_entries_are_refused(entry):
    with pytest.raises((ValueError, TypeError)):
        Egress([entry])


def test_egress_file(tmp_path):
    (tmp_path / "a.json").write_text('{"allow": ["127.0.0.0/8"]}')
    (tmp_path / "b.json").write_text('["127.0.0.0/8"]')
    (tmp_path / "c.json").write_text('{"deny": []}')
    assert Egress.load(tmp_path / "a.json").allows("127.0.0.1", 1)
    assert Egress.load(tmp_path / "b.json").allows("127.0.0.1", 1)
    with pytest.raises(ValueError):
        Egress.load(tmp_path / "c.json")


# other kinds, stats, helpers ---------------------------------------------------------------------

def test_exit_conforms(env, b):
    assert check(env, b, ev("exit")) is None


def test_stats_count_every_outcome(env, b):
    v = Verifier()
    for e in (ev("exec", exe="/tmp/.x9"), ev("exec", exe=PY), ev("write", path="/etc/passwd"), ev("exit")):
        v.verify(e, env, b, MOUNTS)
    assert v.stats == {"D_exec/undeclared": 1, "conforming": 2, "D_write/declared_file": 1}


def test_binding_failure_record(b):
    det = binding_failure(ev("exec", exe="/usr/bin/sleep"), None, "unknown_container", "no binding")
    assert list(det) == list(FIELDS)
    assert (det["class"], det["subclass"], det["origin"], det["image_digest"]) == \
           ("binding", "unknown_container", "AUTHENTICATED", None)
    assert det["clause"] == {"kind": "binding", "path": "/usr/bin/sleep", "detail": "no binding"}
    assert det["context"] == {"declared": None, "package": None, "depth": None, "layer": None}


def test_weak_classes():
    assert WEAK == {("D_exec", "outside_closure"), ("D_load", "outside_closure")}
    det = detection(ev(), None, "D_exec", "undeclared", ("file_set", "/x", ""), "AUTHENTICATED", {})
    assert not is_weak(det)
