"""Unit tests for testbed/profiling/labels.py (MLA-03 label maths, Role 1)."""
import json

from testbed.profiling import labels
from testbed.profiling.labels import CapCheck


# --- capability_name ----------------------------------------------------------------------

def test_capability_name_from_index():
    assert labels.capability_name(0) == "CAP_CHOWN"
    assert labels.capability_name(13) == "CAP_NET_RAW"
    assert labels.capability_name(40) == "CAP_CHECKPOINT_RESTORE"


def test_capability_name_from_digit_string():
    assert labels.capability_name("10") == "CAP_NET_BIND_SERVICE"


def test_capability_name_from_names():
    assert labels.capability_name("net_admin") == "CAP_NET_ADMIN"
    assert labels.capability_name("CAP_NET_ADMIN") == "CAP_NET_ADMIN"


def test_capability_name_rejects_bad():
    assert labels.capability_name(999) is None
    assert labels.capability_name("CAP_NOT_REAL") is None
    assert labels.capability_name(True) is None      # bool is not a capability index
    assert labels.capability_name(None) is None


# --- parse_tetragon_cap_events ------------------------------------------------------------

def _kprobe(cap_name=None, cap_value=None, ret=0, ns="demo", pod="nginx-1", fn="cap_capable"):
    arg = {}
    if cap_name is not None:
        arg["name"] = cap_name
    if cap_value is not None:
        arg["value"] = cap_value
    return {"time": "2026-09-28T10:00:00Z", "process_kprobe": {
        "function_name": fn,
        "process": {"pid": 42, "binary": "/usr/sbin/nginx", "pod": {"namespace": ns, "name": pod}},
        "args": [{"capability_arg": arg}],
        "return": {"int_arg": ret}}}


def test_parse_granted_and_denied():
    events = [_kprobe(cap_name="CAP_NET_BIND_SERVICE", ret=0),
              _kprobe(cap_name="CAP_SYS_ADMIN", ret=-1)]
    checks = list(labels.parse_tetragon_cap_events(events))
    got = {(c.capability, c.granted) for c in checks}
    assert got == {("CAP_NET_BIND_SERVICE", True), ("CAP_SYS_ADMIN", False)}


def test_parse_capability_by_value_index():
    checks = list(labels.parse_tetragon_cap_events([_kprobe(cap_value=13, ret=0)]))
    assert checks[0].capability == "CAP_NET_RAW"


def test_parse_reads_json_lines():
    line = json.dumps(_kprobe(cap_name="CAP_CHOWN", ret=0))
    checks = list(labels.parse_tetragon_cap_events([line, "", "not json"]))
    assert [c.capability for c in checks] == ["CAP_CHOWN"]


def test_parse_skips_non_cap_capable():
    assert list(labels.parse_tetragon_cap_events([_kprobe(fn="security_file_permission")])) == []


def test_parse_namespace_and_pod_filter():
    events = [_kprobe(cap_name="CAP_CHOWN", ns="demo", pod="nginx-1"),
              _kprobe(cap_name="CAP_KILL", ns="kube-system", pod="coredns-9"),
              _kprobe(cap_name="CAP_SETUID", ns="demo", pod="other-2")]
    got = {c.capability for c in labels.parse_tetragon_cap_events(events, namespace="demo")}
    assert got == {"CAP_CHOWN", "CAP_SETUID"}
    got2 = {c.capability for c in labels.parse_tetragon_cap_events(events, namespace="demo", pod_prefix="nginx")}
    assert got2 == {"CAP_CHOWN"}


def test_parse_skips_missing_return():
    ev = _kprobe(cap_name="CAP_CHOWN")
    del ev["process_kprobe"]["return"]
    assert list(labels.parse_tetragon_cap_events([ev])) == []


# --- labels_for_run / union_runs ----------------------------------------------------------

def test_labels_for_run_splits_granted_and_denied():
    checks = [CapCheck("CAP_CHOWN", True), CapCheck("CAP_SYS_ADMIN", False), CapCheck("CAP_SETUID", True)]
    out = labels.labels_for_run(checks)
    assert out["granted"] == {"CAP_CHOWN", "CAP_SETUID"} and out["denied"] == {"CAP_SYS_ADMIN"}


def test_labels_for_run_granted_wins_over_denied():
    # A capability granted at least once is a label, even if also denied elsewhere.
    checks = [CapCheck("CAP_CHOWN", False), CapCheck("CAP_CHOWN", True)]
    out = labels.labels_for_run(checks)
    assert out["granted"] == {"CAP_CHOWN"} and out["denied"] == set()


def test_union_runs_agreement():
    r = {"granted": {"CAP_CHOWN", "CAP_SETUID"}, "denied": set()}
    merged = labels.union_runs([r, dict(r)])
    assert merged["labels"] == ["CAP_CHOWN", "CAP_SETUID"]
    assert merged["disagreement_count"] == 0 and merged["disagreement_fraction"] == 0.0


def test_union_runs_disagreement():
    merged = labels.union_runs([
        {"granted": {"CAP_CHOWN", "CAP_SETUID"}, "denied": set()},
        {"granted": {"CAP_CHOWN"}, "denied": {"CAP_NET_RAW"}}])
    assert merged["labels"] == ["CAP_CHOWN", "CAP_SETUID"]      # union
    assert merged["disagreement_caps"] == ["CAP_SETUID"]        # not granted in both runs
    assert merged["disagreement_count"] == 1
    assert merged["disagreement_fraction"] == 0.5
    assert merged["denied"] == ["CAP_NET_RAW"]                  # denied and never granted


def test_build_label_row():
    row = labels.build_label_row("nginx:1.27", "sha256:abc", [
        {"granted": {"CAP_NET_BIND_SERVICE"}, "denied": set()},
        {"granted": {"CAP_NET_BIND_SERVICE", "CAP_SETUID"}, "denied": set()}], workload="curl")
    assert row["image"] == "nginx:1.27" and row["digest"] == "sha256:abc"
    assert row["labels"] == ["CAP_NET_BIND_SERVICE", "CAP_SETUID"]
    assert row["runs"] == 2 and row["run_disagreement"] == 1 and row["workload"] == "curl"


def test_rare_labels():
    rows = [
        {"labels": ["CAP_CHOWN", "CAP_SETUID"]},
        {"labels": ["CAP_CHOWN", "CAP_SETUID"]},
        {"labels": ["CAP_CHOWN", "CAP_NET_RAW"]},   # CAP_CHOWN x3, CAP_SETUID x2, CAP_NET_RAW x1
    ]
    rare = labels.rare_labels(rows, min_positive=3)
    assert rare == {"CAP_NET_RAW": 1, "CAP_SETUID": 2}     # CAP_CHOWN (3) is not rare
