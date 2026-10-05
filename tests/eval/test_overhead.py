"""eval/overhead.py: sampling from /proc, CPU deltas, and the overhead report (no VM needed)."""
import json

from eval import overhead


def fake_proc(tmp_path, procs, total=1000, idle=600):
    for pid, (comm, cmd, ut, st, rss) in procs.items():
        d = tmp_path / str(pid)
        d.mkdir()
        fields = ["S"] + ["0"] * 10 + [str(ut), str(st)] + ["0"] * 30
        (d / "stat").write_text(f"{pid} ({comm}) " + " ".join(fields))
        (d / "cmdline").write_text(cmd.replace(" ", "\0"))
        (d / "status").write_text(f"Name:\t{comm}\nVmRSS:\t{rss} kB\n")
    (tmp_path / "stat").write_text(f"cpu  {total - idle} 0 0 {idle} 0 0 0\n")
    return str(tmp_path)


def test_sample_groups_processes(tmp_path):
    proc = fake_proc(tmp_path, {
        10: ("tetragon", "/usr/bin/tetragon --bpf", 100, 50, 2048),
        11: ("falco", "/usr/bin/falco", 300, 100, 4096),
        12: ("python3", "python3 -m node.run --run ./run-overhead --mlb", 40, 10, 1024),
        13: ("kubectl", "kubectl logs -n kube-system ds/tetragon -c export-stdout -f", 5, 5, 512),
        14: ("python", "python app.py", 20, 0, 800),
        15: ("bash", "bash", 1, 1, 10),
    })
    s = overhead.sample(proc)
    groups = sorted(p["group"] for p in s["pids"].values())
    assert groups == ["app", "export", "falco", "provbind", "tetragon"]


def test_cpu_delta_and_monitor_total():
    before = {"time": 0, "host": {"total": 1000, "idle": 600},
              "pids": {"1": {"group": "tetragon", "cpu_s": 1.0, "rss_kb": 1024},
                       "2": {"group": "provbind", "cpu_s": 2.0, "rss_kb": 2048}}}
    after = {"time": 10, "host": {"total": 2000, "idle": 1100},
             "pids": {"1": {"group": "tetragon", "cpu_s": 2.0, "rss_kb": 1024},
                      "2": {"group": "provbind", "cpu_s": 2.5, "rss_kb": 2048},
                      "3": {"group": "app", "cpu_s": 3.0, "rss_kb": 512}}}
    d = overhead.cpu_delta(before, after)
    assert d["tetragon"]["cpu_pct"] == 10.0 and d["provbind"]["cpu_pct"] == 5.0
    assert d["monitor_cpu_pct"] == 15.0 and d["app"]["cpu_pct"] == 30.0     # app is not a monitor
    assert d["host_busy_pct"] == 50.0


def rows():
    out = []
    for cfg, mix95, cache95, rps, fop, spawn, cpu in (("none", 10, 12, 100, 5.0, 1.0, 0.0),
                                                       ("falco", 11, 13, 95, 6.0, 1.3, 20.0),
                                                       ("provbind", 11.5, 14, 92, 5.5, 1.1, 12.0)):
        for rep in (1, 2, 3):
            out += [{"config": cfg, "rep": rep, "kind": "mix", "p50_ms": mix95 / 2, "p95_ms": mix95, "rps": rps},
                    {"config": cfg, "rep": rep, "kind": "cache", "p50_ms": cache95 / 2, "p95_ms": cache95, "rps": rps},
                    {"config": cfg, "rep": rep, "kind": "micro", "file_op_us": fop, "spawn_ms": spawn},
                    {"config": cfg, "rep": rep, "kind": "cpu", "monitor_cpu_pct": cpu, "monitor_rss_mb": 100,
                     "host_busy_pct": 30}]
    out.append({"config": "provbind", "rep": 4, "kind": "mix"})          # a failed workload: no numbers
    return out


def test_report_overhead_verdict_and_tradeoff(tmp_path):
    comp = {"tables": {"systems": {"PROVBIND": {"TP": 50, "FP": 0, "f1": 0.87, "fpr": 0.0},
                                   "Falco": {"TP": 25, "FP": 10, "f1": 0.5, "fpr": 0.33}}}}
    doc = overhead.build(rows(), 20.0, comp)
    p95 = next(e for e in doc["table"] if e["metric"].startswith("request latency p95, mix"))
    assert p95["overhead_pct"]["provbind"] == 15.0 and p95["overhead_pct"]["falco"] == 10.0
    tput = next(e for e in doc["table"] if e["metric"].startswith("throughput, mix"))
    assert tput["overhead_pct"]["provbind"] == 8.0                       # throughput loss
    v = doc["verdict"]["provbind"]
    assert v["worst_app_overhead_pct"] == 16.7 and v["app_within_threshold"]
    assert doc["verdict"]["falco"]["worst_micro_overhead_pct"] == 30.0
    assert not doc["verdict"]["falco"]["micro_within_threshold"]
    assert doc["provbind_minus_falco"]["monitor CPU, PROVBIND / Falco"] == 0.6
    assert doc["tradeoff"][0]["system"] == "PROVBIND" and doc["tradeoff"][0]["fp"] == 0
    text = overhead.render(doc)
    assert "Against the 20% limit" in text and "Cost beside accuracy" in text


def test_record_and_report_cli(tmp_path, monkeypatch, capsys):
    import io
    out = tmp_path / "overhead.jsonl"
    for cfg in ("none", "provbind"):
        monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"p50_ms": 5, "p95_ms": 10, "rps": 50}) + "\n"))
        assert overhead.main(["record", "--out", str(out), "--config", cfg, "--rep", "1", "--kind", "mix"]) == 0
    assert overhead.main(["report", "--dir", str(tmp_path)]) == 0
    assert (tmp_path / "OVERHEAD.md").exists() and "PROVBIND runtime overhead" in capsys.readouterr().out
