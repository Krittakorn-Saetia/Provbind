"""node/tetragon/*.yaml: the TracingPolicies parse, stay in namespace demo, and agree with the
normaliser (every hooked function has a kind, and every kind the normaliser expects is hooked).

These are static checks; whether Tetragon accepts a policy is checked on the demo PC (PH4-02a/b)."""
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")      # in requirements.txt, not requirements-role2.txt

from node.normalize import KPROBE_KINDS

POLICIES = Path(__file__).resolve().parents[1] / "tetragon"
FILES = ("write.yaml", "truncate.yaml", "cap.yaml", "load.yaml", "connect.yaml")


def load(name):
    return yaml.safe_load((POLICIES / name).read_text(encoding="utf-8"))


def kprobes(name):
    return {k["call"]: k for k in load(name)["spec"]["kprobes"]}


def mask_values(kp, index):
    return [v for sel in kp.get("selectors", []) for m in sel.get("matchArgs", [])
            if m["index"] == index and m["operator"] == "Mask" for v in m["values"]]


@pytest.mark.parametrize("name", FILES)
def test_policy_is_namespaced_to_demo(name):
    doc = load(name)
    assert doc["apiVersion"] == "cilium.io/v1alpha1"
    assert doc["kind"] == "TracingPolicyNamespaced"
    assert doc["metadata"]["namespace"] == "demo"
    assert doc["metadata"]["name"].startswith("provbind-")


@pytest.mark.parametrize("name", FILES)
def test_every_hook_is_a_plain_kprobe_with_indexed_args(name):
    for call, kp in kprobes(name).items():
        assert kp["syscall"] is False, call
        assert [a["index"] for a in kp["args"]] == list(range(len(kp["args"]))), call


def test_the_policies_hook_exactly_what_the_normaliser_reads():
    hooked = {call for name in FILES for call in kprobes(name)}
    assert hooked == set(KPROBE_KINDS)


def test_names_are_unique():
    assert len({load(n)["metadata"]["name"] for n in FILES}) == len(FILES)


def test_write_hook_keeps_writes_on_every_path():
    kp = kprobes("write.yaml")["security_file_permission"]
    assert [a["type"] for a in kp["args"]] == ["file", "int"]
    assert mask_values(kp, 1) == ["2"]                                     # MAY_WRITE only
    prefixes = [m for sel in kp["selectors"] for m in sel["matchArgs"] if m["operator"] in ("Prefix", "Equal")]
    assert prefixes == []                                                   # all paths, for ML-B


@pytest.mark.parametrize("name,call", [("write.yaml", "security_file_permission"),
                                       ("truncate.yaml", "security_path_truncate"),
                                       ("truncate.yaml", "security_file_truncate"),
                                       ("load.yaml", "security_mmap_file"),
                                       ("cap.yaml", "cap_capable")])
def test_hooks_that_can_be_refused_report_their_return_value(name, call):
    kp = kprobes(name)[call]
    assert kp["return"] is True
    assert kp["returnArg"] == {"index": 0, "type": "int"}
    # Tetragon 1.7 rejects returnArgAction "Post" (only TrackSock/UntrackSock), failing the whole policy;
    # without it the return event is still posted, with the value in return.int_arg.
    assert "returnArgAction" not in kp


def test_load_hook_keeps_executable_mappings_only():
    kp = kprobes("load.yaml")["security_mmap_file"]
    assert [a["type"] for a in kp["args"]][:2] == ["file", "uint32"]
    assert mask_values(kp, 1) == ["4"]                                     # PROT_EXEC


def test_cap_hook_reads_the_capability():
    kp = kprobes("cap.yaml")["cap_capable"]
    assert {a["index"]: a["type"] for a in kp["args"]}[2] == "capability"
    assert "selectors" not in kp                                            # granted and denied both kept


def test_connect_hook_reads_the_socket():
    kp = kprobes("connect.yaml")["tcp_connect"]
    assert kp["args"] == [{"index": 0, "type": "sock"}]


def test_truncate_hooks_read_a_path():
    kps = kprobes("truncate.yaml")
    assert kps["security_path_truncate"]["args"][0]["type"] == "path"
    assert kps["security_file_truncate"]["args"][0]["type"] == "file"


def test_helm_values_limit_the_export_to_demo():
    import json
    values = load("values.yaml")["tetragon"]
    allow = [json.loads(line) for line in values["exportAllowList"].splitlines() if line.strip()]
    assert allow and all(f["namespace"] == ["demo"] for f in allow)
    assert {"PROCESS_EXEC", "PROCESS_EXIT", "PROCESS_KPROBE"} <= set(allow[0]["event_set"])
    assert values["enablePolicyFilter"] is True
