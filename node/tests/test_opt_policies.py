"""The optimised policy variant (node/tetragon/opt/): same hooks as the originals, cheaper, never clashing."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ORIG, OPT = ROOT / "node" / "tetragon", ROOT / "node" / "tetragon" / "opt"


def load(path):
    return yaml.safe_load(path.read_text())


def test_same_hooks_different_names():
    for name in ("write", "truncate", "cap", "load", "connect"):
        o, p = load(ORIG / f"{name}.yaml"), load(OPT / f"{name}.yaml")
        assert [k["call"] for k in o["spec"]["kprobes"]] == [k["call"] for k in p["spec"]["kprobes"]]
        assert p["metadata"]["name"] == o["metadata"]["name"].replace("provbind-", "provbind-opt-")


def test_hot_hooks_are_rate_limited_in_the_kernel():
    for name, scope in (("write", "process"), ("cap", "process"), ("load", "global")):
        kp = load(OPT / f"{name}.yaml")["spec"]["kprobes"][0]
        actions = [a for sel in kp["selectors"] for a in sel.get("matchActions", [])]
        assert actions == [{"action": "Post", "rateLimit": "1m", "rateLimitScope": scope}]
    for name in ("write", "load"):                       # the return probe is dropped where unused
        assert not load(OPT / f"{name}.yaml")["spec"]["kprobes"][0].get("return")


def test_truncate_hooks_are_rate_limited_without_return_probes():
    # open(path, "w") on an existing file passes security_file_truncate: one event per rewrite otherwise
    for kp in load(OPT / "truncate.yaml")["spec"]["kprobes"]:
        actions = [a for sel in kp["selectors"] for a in sel.get("matchActions", [])]
        assert actions == [{"action": "Post", "rateLimit": "1m", "rateLimitScope": "process"}]
        assert not kp.get("return") and "returnArg" not in kp


def test_an_event_without_return_value_is_kept():
    from node.normalize import Normalizer
    line = ('{"process_kprobe":{"function_name":"security_file_permission","process":{"pod":{"namespace":"demo"},'
            '"binary":"/usr/local/bin/python3.11","pid":1},"args":[{"file_arg":{"path":"/etc/passwd"}},{"int_arg":2}]},'
            '"time":"2026-10-05T10:00:00Z"}')
    n = Normalizer()
    n(line)
    assert n.stats.get("denied", 0) == 0                 # no return value is not a refusal


def test_socket_and_pipe_writes_stay_in_the_kernel():
    sel = load(OPT / "write.yaml")["spec"]["kprobes"][0]["selectors"][0]
    assert {"index": 0, "operator": "Prefix", "values": ["/"]} in sel["matchArgs"]
    assert any(a["index"] == 1 and a["values"] == ["2"] for a in sel["matchArgs"])   # still MAY_WRITE only
