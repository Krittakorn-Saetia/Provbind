"""Unit tests for testbed/profiling/run.py assemble (MLA-03, Role 1)."""
import json

from testbed.profiling import run


def _kprobe(cap, ret=0, pod="nginx-1"):
    return json.dumps({"time": "2026-09-28T10:00:00Z", "process_kprobe": {
        "function_name": "cap_capable",
        "process": {"pid": 1, "binary": "/x", "pod": {"namespace": "demo", "name": pod}},
        "args": [{"capability_arg": {"name": cap}}], "return": {"int_arg": ret}}})


def _image_dir(raw, slug, image, digest, run1, run2):
    d = raw / slug
    d.mkdir()
    (d / "meta.json").write_text(json.dumps({"image": image, "digest": digest}))
    (d / "run1.jsonl").write_text("\n".join(run1) + "\n")
    (d / "run2.jsonl").write_text("\n".join(run2) + "\n")
    return d


def test_assemble_builds_rows(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    _image_dir(raw, "nginx", "nginx:1.27", "sha256:aaa",
               [_kprobe("CAP_NET_BIND_SERVICE"), _kprobe("CAP_SETUID")],
               [_kprobe("CAP_NET_BIND_SERVICE")])
    _image_dir(raw, "redis", "redis:7", "sha256:bbb",
               [_kprobe("CAP_SETGID")], [_kprobe("CAP_SETGID")])

    rows, skipped = run.assemble(str(raw), namespace="demo")
    assert skipped == []
    by_image = {r["image"]: r for r in rows}
    assert by_image["nginx:1.27"]["labels"] == ["CAP_NET_BIND_SERVICE", "CAP_SETUID"]
    assert by_image["nginx:1.27"]["run_disagreement"] == 1        # SETUID only in run1
    assert by_image["redis:7"]["labels"] == ["CAP_SETGID"]
    assert by_image["redis:7"]["run_disagreement"] == 0


def test_assemble_skips_without_digest(tmp_path):
    raw = tmp_path / "raw"
    (raw / "noimg").mkdir(parents=True)
    (raw / "noimg" / "run1.jsonl").write_text(_kprobe("CAP_CHOWN") + "\n")
    rows, skipped = run.assemble(str(raw))
    assert rows == [] and skipped and "digest" in skipped[0][1]


def test_assemble_skips_without_captures(tmp_path):
    raw = tmp_path / "raw"
    d = raw / "empty"
    d.mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"image": "x", "digest": "sha256:z"}))
    rows, skipped = run.assemble(str(raw))
    assert rows == [] and "run*.jsonl" in skipped[0][1]


def test_assemble_missing_root(tmp_path):
    rows, skipped = run.assemble(str(tmp_path / "nope"))
    assert rows == [] and skipped == []


def test_write_labels_roundtrip(tmp_path):
    out = tmp_path / "sub" / "labels.jsonl"
    run.write_labels([{"image": "nginx:1.27", "digest": "sha256:aaa", "labels": ["CAP_CHOWN"]}], str(out))
    lines = out.read_text().strip().splitlines()
    assert json.loads(lines[0])["digest"] == "sha256:aaa"


def test_assemble_keeps_only_the_images_own_pod(tmp_path):
    # meta.json names the profiling pod; events from other pods in `demo` (the running demo app,
    # the workload helper) must not become this image's labels.
    raw = tmp_path / "raw"
    d = raw / "nginx"
    d.mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"image": "nginx:1.27", "digest": "sha256:aaa",
                                             "pod": "prof-nginx-1-27"}))
    lines = [_kprobe("CAP_NET_BIND_SERVICE", pod="prof-nginx-1-27"),
             _kprobe("CAP_SYS_ADMIN", pod="demo-app-7d9f"),        # another pod in the namespace
             _kprobe("CAP_NET_RAW", pod="wl-prof-nginx-1-27-1")]   # the workload helper pod
    (d / "run1.jsonl").write_text("\n".join(lines) + "\n")
    (d / "run2.jsonl").write_text(lines[0] + "\n")
    rows, _ = run.assemble(str(raw), namespace="demo")
    assert rows[0]["labels"] == ["CAP_NET_BIND_SERVICE"]
    assert rows[0]["run_disagreement"] == 0
