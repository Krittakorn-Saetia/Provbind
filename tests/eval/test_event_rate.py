import json

from eval import event_rate


def ev(kind, fn=None, path=None, pod="demo-app-1", ns="demo"):
    body = {"process": {"binary": "/usr/local/bin/python", "pod": {"namespace": ns, "name": pod}}}
    if fn:
        body["function_name"] = fn
        body["args"] = [{"file_arg": {"path": path}}] if path is not None else []
    return json.dumps({kind: body, "time": "2026-10-08T00:00:00Z"})


def test_counts_per_hook_and_path_class():
    lines = [ev("process_kprobe", "security_file_permission", "/tmp/app-cache/entry3.json"),
             ev("process_kprobe", "security_file_permission", "socket:[123]"),
             ev("process_kprobe", "security_file_permission", "/data/x"),
             ev("process_kprobe", "security_file_truncate", "/tmp/app-cache/entry3.json"),
             ev("process_exec"),
             ev("process_kprobe", "cap_capable", pod="other-pod"),          # another pod: not counted
             ev("process_kprobe", "cap_capable", ns="kube-system"),         # another namespace: not counted
             "not json"]
    c = event_rate.count(lines)
    assert c == {"write (cache file)": 1, "write to a pipe or socket": 1, "write (other file)": 1,
                 "truncate": 1, "process exec": 1}


def test_summary_divides_by_requests(tmp_path):
    evs = tmp_path / "ev.jsonl"
    evs.write_text("\n".join([ev("process_kprobe", "security_file_truncate", "/tmp/app-cache/e1.json")] * 4))
    client = tmp_path / "client.json"
    client.write_text(json.dumps({"requests": 8}))
    assert event_rate.main([str(evs), str(client), "--path", "/cache"]) == 0
    assert "0.500" in event_rate.summary(event_rate.count(evs.read_text().splitlines()), 8, "/cache")
