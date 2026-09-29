"""node/normalize.py: Tetragon JSON -> §4.3 events (Eq. 50). Synthetic Tetragon lines (node/synth.py)."""
import copy
import json

import pytest

from node.normalize import (BASE_FIELDS, CAPABILITIES, KPROBE_KINDS, RECORD_FIELDS, Event, Normalizer,
                            format_time, iter_events, normalise_hash, parse_time)
from node.synth import DEMO_CID, DEMO_POD, Proc, Session


@pytest.fixture
def s():
    return Session(start="2026-09-28T10:14:22.123456789Z")


@pytest.fixture
def app(s):
    return s.proc("/usr/local/bin/python3.11", pid=4402)


def one(line, **kw):
    n = Normalizer(**kw)
    ev = n(line)
    return ev, n.stats


# exec -------------------------------------------------------------------------------------------

def test_exec_gives_every_contract_field(s, app):
    x9 = s.proc("/tmp/.x9", pid=4471, parent=app)
    ev, stats = one(s.exec(x9))
    assert (ev.kind, ev.exe, ev.parent_exe, ev.pid, ev.ppid) == ("exec", "/tmp/.x9", "/usr/local/bin/python3.11",
                                                                4471, 4402)
    assert (ev.container_id, ev.namespace, ev.pod, ev.container) == (DEMO_CID, "demo", DEMO_POD, "app")
    assert ev.time == "2026-09-28T10:14:22.123456789Z" and ev.hash is None
    assert stats == {"kind:exec": 1}


def test_exec_record_has_exactly_the_contract_fields_in_order(s, app):
    rec = one(s.exec(app))[0].record()
    assert list(rec) == ["time", "kind", "container_id", "namespace", "pod", "container", "pid", "ppid",
                         "exe", "parent_exe", "hash"]
    assert rec["ppid"] is None and rec["parent_exe"] is None          # no parent in the event


def test_exec_record_matches_the_handoff_example_shape(s, app):
    """Sprint Handoff §4.3's exec line, field for field."""
    example = json.loads('{"time":"2026-09-28T10:14:22.123Z","kind":"exec","container_id":"containerd://4b1c",'
                         '"namespace":"demo","pod":"demo-app-7d9f","container":"app","pid":4471,"ppid":4402,'
                         '"exe":"/tmp/.x9","parent_exe":"/usr/local/bin/python3.11","hash":null}')
    x9 = s.proc("/tmp/.x9", pid=4471, parent=app)
    rec = one(s.exec(x9))[0].record()
    assert list(rec) == list(example)
    assert {k: type(v) for k, v in rec.items()} == {k: type(v) for k, v in example.items()}


def test_relative_exe_is_joined_to_the_cwd(s, app):
    x9 = s.proc("./.x9", pid=4471, parent=app, cwd="/tmp")
    assert one(s.exec(x9))[0].exe == "/tmp/.x9"


def test_relative_exe_without_a_cwd_is_kept_as_reported(s, app):
    x9 = s.proc("x9", pid=4471, parent=app, cwd="")
    assert one(s.exec(x9))[0].exe == "x9"          # never guessed: the verifier sees it undeclared


def test_deleted_suffix_is_not_stripped(s, app):
    """A file can be named '/usr/bin/ls (deleted)' on purpose; stripping would declare it."""
    x = s.proc("/usr/bin/ls (deleted)", pid=4471, parent=app)
    assert one(s.exec(x))[0].exe == "/usr/bin/ls (deleted)"


def test_numbers_sent_as_strings_are_read(s, app):
    doc = s.exec(s.proc("/usr/bin/ls", pid=4471, parent=app))
    doc["process_exec"]["process"]["pid"] = "4471"
    doc["process_exec"]["parent"]["pid"] = "4402"
    ev = one(doc)[0]
    assert (ev.pid, ev.ppid) == (4471, 4402)


def test_container_id_falls_back_to_the_docker_field(s, app):
    doc = s.exec(app)
    del doc["process_exec"]["process"]["pod"]["container"]["id"]
    assert one(doc)[0].container_id == ("4b1c" * 16)[:31]


def test_time_falls_back_to_the_process_start_time(s, app):
    doc = s.exec(app)
    start = doc["process_exec"]["process"]["start_time"]
    del doc["time"]
    ev = one(doc)[0]
    assert ev.time == start and ev.t == parse_time(start)


# exit -------------------------------------------------------------------------------------------

def test_exit(s, app):
    ev = one(s.exit(app))[0]
    assert ev.kind == "exit" and list(ev.record()) == list(BASE_FIELDS)


# write ------------------------------------------------------------------------------------------

def test_write_with_may_write(s, app):
    x9 = s.proc("/tmp/.x9", pid=4471, parent=app)
    ev = one(s.write(x9, "/etc/passwd"))[0]
    assert (ev.kind, ev.path, ev.exe, ev.pid) == ("write", "/etc/passwd", "/tmp/.x9", 4471)
    assert list(ev.record()) == list(RECORD_FIELDS["write"]) and list(ev.record())[-1] == "path"


def test_write_record_matches_the_handoff_example_shape(s, app):
    example = json.loads('{"time":"2026-09-28T10:14:22.140Z","kind":"write","container_id":"containerd://4b1c",'
                         '"namespace":"demo","pod":"demo-app-7d9f","container":"app","pid":4471,"ppid":4402,'
                         '"exe":"/tmp/.x9","parent_exe":"/usr/local/bin/python3.11","path":"/etc/passwd"}')
    rec = one(s.write(s.proc("/tmp/.x9", pid=4471, parent=app), "/etc/passwd"))[0].record()
    assert list(rec) == list(example)
    assert {k: type(v) for k, v in rec.items()} == {k: type(v) for k, v in example.items()}


@pytest.mark.parametrize("mask", [0x02, 0x02 | 0x08, 0x06])
def test_any_mask_with_may_write_is_a_write(s, app, mask):
    assert one(s.write(app, "/tmp/a", mask=mask))[0].kind == "write"


def test_a_read_is_dropped(s, app):
    ev, stats = one(s.write(app, "/etc/passwd", mask=0x04))
    assert ev is None and stats == {"drop:not_a_write": 1}


def test_a_refused_write_is_dropped(s, app):
    ev, stats = one(s.write(app, "/etc/passwd", ret=-13))
    assert ev is None and stats == {"drop:denied": 1}


def test_a_write_without_a_return_value_is_kept(s, app):
    assert one(s.write(app, "/etc/passwd", ret=None))[0].path == "/etc/passwd"


@pytest.mark.parametrize("path", ["pipe:[40213]", "socket:[91]", "anon_inode:[eventfd]", ""])
def test_writes_to_things_that_are_not_files_are_dropped(s, app, path):
    ev, stats = one(s.write(app, path))
    assert ev is None and stats == {"drop:not_a_file": 1}


@pytest.mark.parametrize("via_file", [True, False])
def test_truncation_is_a_write(s, app, via_file):
    ev = one(s.truncate(app, "/etc/passwd", via_file=via_file))[0]
    assert (ev.kind, ev.path) == ("write", "/etc/passwd")


def test_arguments_are_found_by_type_not_position(s, app):
    doc = s.write(app, "/etc/passwd")
    doc["process_kprobe"]["args"].reverse()
    doc["process_kprobe"]["args"].insert(0, {})              # a nop argument left in the output
    assert one(doc)[0].path == "/etc/passwd"


# load -------------------------------------------------------------------------------------------

def test_executable_mapping_is_a_load(s, app):
    ev = one(s.mmap(app, "/tmp/libx.so", prot=0x05))[0]
    assert (ev.kind, ev.path, ev.hash) == ("load", "/tmp/libx.so", None)
    assert list(ev.record()) == list(RECORD_FIELDS["load"])


def test_a_mapping_without_prot_exec_is_dropped(s, app):
    ev, stats = one(s.mmap(app, "/usr/lib/x86_64-linux-gnu/libc.so.6", prot=0x01))
    assert ev is None and stats == {"drop:not_executable": 1}


def test_prot_given_as_int_arg_is_read(s, app):
    doc = s.mmap(app, "/tmp/libx.so")
    doc["process_kprobe"]["args"][1] = {"int_arg": 5}
    assert one(doc)[0].kind == "load"


def test_an_anonymous_mapping_is_dropped(s, app):
    doc = s.mmap(app, "/x")
    doc["process_kprobe"]["args"][0] = {"file_arg": {}}
    assert one(doc)[1] == {"drop:not_a_file": 1}


# cap --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("granted", [True, False, None])
def test_capability_checks(s, app, granted):
    ev = one(s.cap(app, "CAP_CHOWN", granted=granted))[0]
    assert (ev.kind, ev.cap, ev.granted) == ("cap", "CAP_CHOWN", granted)
    assert ev.record() is None                             # no contract field for the capability yet


def test_capability_number_without_a_name(s, app):
    doc = s.cap(app, "CAP_NET_RAW")
    del doc["process_kprobe"]["args"][1]["capability_arg"]["name"]
    assert one(doc)[0].cap == "CAP_NET_RAW"


def test_capability_table_matches_the_kernel_numbers():
    assert (CAPABILITIES.index("CAP_CHOWN"), CAPABILITIES.index("CAP_NET_BIND_SERVICE"),
            CAPABILITIES.index("CAP_SYS_ADMIN"), CAPABILITIES.index("CAP_CHECKPOINT_RESTORE")) == (0, 10, 21, 40)


def test_capability_event_without_a_capability_is_dropped(s, app):
    doc = s.cap(app, "CAP_CHOWN")
    doc["process_kprobe"]["args"][1]["capability_arg"] = {"value": 99}
    assert one(doc)[1] == {"drop:no_capability": 1}


# connect ----------------------------------------------------------------------------------------

def test_connect(s, app):
    ev = one(s.connect(app, "203.0.113.9", 4444))[0]
    assert (ev.kind, ev.daddr, ev.dport, ev.protocol) == ("connect", "203.0.113.9", 4444, "tcp")
    assert ev.record() is None


def test_connect_without_a_destination_is_dropped(s, app):
    doc = s.connect(app, "203.0.113.9", 4444)
    doc["process_kprobe"]["args"] = [{"sock_arg": {"family": "AF_INET"}}]
    assert one(doc)[1] == {"drop:no_destination": 1}


# scope and bad input ----------------------------------------------------------------------------

def test_other_namespaces_are_dropped(s):
    kube = s.proc("/usr/local/bin/coredns", namespace="kube-system", pod="coredns-5d78")
    ev, stats = one(s.exec(kube))
    assert ev is None and stats == {"drop:other_namespace": 1}


def test_namespaces_none_keeps_every_namespace(s):
    kube = s.proc("/usr/local/bin/coredns", namespace="kube-system", pod="coredns-5d78")
    assert one(s.exec(kube), namespaces=None)[0].namespace == "kube-system"


def test_host_processes_are_dropped(s):
    host = s.proc("/usr/bin/containerd", pod=None)
    assert one(s.exec(host))[1] == {"drop:no_pod": 1}


@pytest.mark.parametrize("line,reason", [
    ("{not json", "bad_json"),
    ("[1, 2]", "bad_json"),
    ('{"process_exec": 7, "time": "2026-09-28T10:00:00Z"}', "bad_json"),
    ('{"process_tracepoint": {}, "time": "2026-09-28T10:00:00Z"}', "other_event"),
    ('{"process_exec": {"parent": {}}, "time": "2026-09-28T10:00:00Z"}', "no_process"),
])
def test_bad_lines_are_counted_not_raised(line, reason):
    ev, stats = one(line)
    assert ev is None and stats == {"drop:" + reason: 1}


def test_unknown_kprobe_functions_are_dropped(s, app):
    doc = s.write(app, "/tmp/a")
    doc["process_kprobe"]["function_name"] = "security_inode_unlink"
    assert one(doc)[1] == {"drop:other_function": 1}


def test_event_without_any_time_is_dropped(s, app):
    doc = s.exec(app)
    del doc["time"]
    doc["process_exec"]["process"]["start_time"] = "yesterday"
    assert one(doc)[1] == {"drop:no_time": 1}


def test_bytes_lines_are_read(s, app):
    assert one(json.dumps(s.exec(app)).encode())[0].kind == "exec"


def test_stats_count_kinds_and_drops(s, app):
    n = Normalizer()
    for doc in (s.exec(app), s.write(app, "/tmp/a"), s.write(app, "/tmp/a", mask=4), s.cap(app, "CAP_KILL")):
        n(doc)
    assert n.stats == {"kind:exec": 1, "kind:write": 1, "drop:not_a_write": 1, "kind:cap": 1}


def test_iter_events_skips_blank_lines_and_keeps_order(s, app):
    s.exec(app)
    s.write(app, "/tmp/a")
    lines = ["", s.lines()[0], "   ", s.lines()[1], "\n"]
    assert [e.kind for e in iter_events(lines)] == ["exec", "write"]


def test_every_hooked_function_has_a_kind():
    assert set(KPROBE_KINDS.values()) <= set(RECORD_FIELDS) | {"cap", "connect"}


# events.jsonl round trip ------------------------------------------------------------------------

def test_records_read_back_to_the_same_event(s, app):
    x9 = s.proc("/tmp/.x9", pid=4471, parent=app)
    for doc in (s.exec(x9), s.write(x9, "/etc/passwd"), s.mmap(x9, "/tmp/libx.so"), s.exit(x9)):
        ev = one(doc)[0]
        back = Normalizer()(json.dumps(ev.record()))
        assert back == ev


def test_in_memory_fields_never_reach_a_record(s, app):
    ev = one(s.exec(app))[0]
    ev.cap, ev.daddr = "CAP_CHOWN", "10.0.0.1"
    assert set(ev.record()) == set(RECORD_FIELDS["exec"])


@pytest.mark.parametrize("rec", [
    {"kind": "exec", "time": "2026-09-28T10:00:00Z"},                                   # no container
    {"kind": "teleport", "time": "2026-09-28T10:00:00Z", "container_id": "containerd://a"},
    {"kind": "exec", "time": "noon", "container_id": "containerd://a"},
])
def test_bad_records_are_dropped(rec):
    assert one(json.dumps(rec))[1] == {"drop:bad_record": 1}


def test_records_from_other_namespaces_are_dropped():
    rec = {"kind": "exec", "time": "2026-09-28T10:00:00Z", "container_id": "containerd://a", "namespace": "x"}
    assert one(json.dumps(rec))[1] == {"drop:other_namespace": 1}


def test_record_hash_is_normalised():
    rec = {"kind": "exec", "time": "2026-09-28T10:00:00Z", "container_id": "c", "namespace": "demo",
           "hash": "SHA256:" + "AB" * 32}
    assert Event.from_record(rec).hash == "ab" * 32


# time and hash helpers --------------------------------------------------------------------------

@pytest.mark.parametrize("text,ns", [
    ("1970-01-01T00:00:00Z", 0),
    ("1970-01-01T00:00:01.5Z", 1_500_000_000),
    ("1970-01-01T00:00:00.000000001Z", 1),
    ("1970-01-01T01:00:00+01:00", 0),
    ("1969-12-31T23:00:00-01:00", 0),
])
def test_parse_time(text, ns):
    assert parse_time(text) == ns


@pytest.mark.parametrize("text", ["2026-13-01T00:00:00Z", "2026-09-28 10:00:00Z", "2026-09-28T10:00:00",
                                  "", None, 5, "2026-09-28T10:00:00.1234567890Z"])
def test_parse_time_rejects(text):
    assert parse_time(text) is None


def test_format_time_round_trips():
    for text in ("2026-09-28T10:14:22.123456789Z", "2026-09-28T10:14:22.100Z", "2026-09-28T10:14:22.000Z"):
        assert format_time(parse_time(text)) == text
    assert format_time(parse_time("2026-09-28T10:14:22Z")) == "2026-09-28T10:14:22.000Z"


@pytest.mark.parametrize("value,expected", [
    ("ab" * 32, "ab" * 32), ("sha256:" + "ab" * 32, "ab" * 32), ("AB" * 32, "ab" * 32),
    ("ab" * 31, None), ("zz" * 32, None), (None, None), (7, None),
])
def test_normalise_hash(value, expected):
    assert normalise_hash(value) == expected


def test_synthetic_proc_without_parent_has_no_parent_fields():
    doc = Proc("/usr/bin/ls", pid=1).json()
    assert "parent_exec_id" not in doc and doc["pod"]["namespace"] == "demo"


def test_session_does_not_mutate_emitted_events(s, app):
    doc = s.exec(app)
    before = copy.deepcopy(doc)
    Normalizer()(doc)
    assert doc == before


# the container runtime's init step (runc re-executing from a memfd for `kubectl exec`) ----------

def test_runc_init_from_memfd_is_dropped(s):
    runc = s.proc("/usr/local/sbin/runc", pid=900, arguments="--root /run/containerd/runc/k8s.io exec")
    init = s.proc("/proc/self/fd/7", pid=901, parent=runc, arguments="init")
    ev, stats = one(s.exec(init))
    assert ev is None and stats == {"drop:runtime_init": 1}


def test_memfd_exec_from_a_container_process_is_kept(s, app):
    """Fileless malware runs a memfd too: with a container parent it must still reach the verifier."""
    ev, _ = one(s.exec(s.proc("/proc/self/fd/7", pid=4471, parent=app, arguments="init")))
    assert ev is not None and ev.exe == "/proc/self/fd/7"


@pytest.mark.parametrize("binary,args,parent", [
    ("/proc/self/fd/7", "", "/usr/local/sbin/runc"),             # not the init step
    ("/proc/self/fd/7", "init --evil", "/usr/local/sbin/runc"),
    ("/tmp/.x9", "init", "/usr/local/sbin/runc"),                # not a memfd path
    ("/proc/self/fd/x", "init", "/usr/local/sbin/runc"),
    ("/proc/self/fd/7", "init", "/usr/local/sbin/runc-helper"),  # parent is not the runtime
])
def test_runtime_init_needs_the_exact_shape(s, binary, args, parent):
    p = s.proc(parent, pid=900)
    ev, _ = one(s.exec(s.proc(binary, pid=901, parent=p, arguments=args)))
    assert ev is not None
