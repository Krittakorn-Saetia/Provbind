"""eval/baselines/ryu_estimate.py: Ryu et al. [17]'s host-based detector rebuilt on recorded traces."""
import json

import numpy as np
import pytest

pytest.importorskip("sklearn")

from eval.baselines import ryu_estimate as ryu  # noqa: E402

# A web app's steady loop (8 distinct windows when repeated), and two attack bursts made of calls the
# loop never makes: rk-2 replays waitid/splice (its scenario's shape), rk-3 an injected library's mmap.
LOOP = ["epoll_wait", "accept4", "recvfrom", "openat", "read", "close", "sendto", "write"]
RK2 = ["waitid", "splice"] * 6
RK3 = ["openat", "mmap", "mprotect", "mmap", "munmap"] * 3


def _write_trace(path, calls):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("Attaching 367 probes...\n" + "".join(
        f"{1000 + i}\t42\tpython3\t{c}\n" for i, c in enumerate(calls)), encoding="utf-8")


def _loop(n):
    return [LOOP[i % len(LOOP)] for i in range(n)]


def _run_folder(tmp_path, baseline_len=400, attack_len=400):
    """A comparison run with 3 baseline recordings, 2 known attacks, an unknown attack, a trust run and
    a benign scenario (2 runs each), plus its ground_truth.csv."""
    run = tmp_path / "run"
    for i in range(1, 4):
        _write_trace(run / "traces" / "baseline" / f"benign-{i}.txt", _loop(baseline_len))
    runs = {"rk-2": RK2, "rk-3": RK3, "attack-1": ["ptrace", "mount", "pivot_root"] * 4, "trust-1": [],
            "benign-1": []}
    labels = {"rk-2": "malicious", "rk-3": "malicious", "attack-1": "malicious", "trust-1": "malicious",
              "benign-1": "benign"}
    gt = ["scenario,label,namespace,pod_prefix,start,end,expected"]
    for scen, burst in runs.items():
        for k in (1, 2):
            half = attack_len // 2
            _write_trace(run / "traces" / f"{scen}-{k}.txt", _loop(half) + burst + _loop(half))
            gt.append(f"{scen},{labels[scen]},demo,demo-app,2026-10-09T10:0{k}:00Z,2026-10-09T10:0{k}:30Z,x")
    (run / "ground_truth.csv").write_text("\n".join(gt) + "\n", encoding="utf-8")
    return run


def test_call_numbers_follow_the_x86_64_table():
    unknown = set()
    assert ryu.number_of("read") == 0 and ryu.number_of("write") == 1 and ryu.number_of("openat") == 257
    assert ryu.number_of("fstat") == 5 and ryu.number_of("fstatat") == 262      # tracepoint name -> newfstatat
    n = ryu.number_of("not_a_call", unknown)
    assert 1000 <= n < 2000 and unknown == {"not_a_call"} and ryu.number_of("not_a_call") == n


def test_windows_are_overlapping_5_grams():
    assert ryu.windows_of(np.array([1, 2, 3, 4])).shape == (0, 5)
    w = ryu.windows_of(np.arange(7))
    assert w.shape == (3, 5) and w[2].tolist() == [2, 3, 4, 5, 6]
    keys = ryu.keys_of(np.vstack([w, w[:1]]))
    assert len(set(keys.tolist())) == 3 and keys[0] == keys[3]


def test_table_counts_every_window_once():
    t = ryu.Table.of_calls(np.array([1, 2, 3, 4, 5] * 4))
    assert t.windows == 16 and len(t.rows) == 5          # 5 distinct rotations of the loop
    assert t.without(t.keys[:2]).windows == t.windows - int(t.counts[:2].sum())


def test_read_calls_drops_the_runtime_and_status_lines(tmp_path):
    p = tmp_path / "t.txt"
    p.write_text("Attaching 2 probes...\n1\t9\trunc:[2:INIT]\texecve\n2\t9\tpython3\tread\n3\t9\tpython3\tnewfstat\n")
    assert ryu.read_calls(p).tolist() == [0, 5]


def test_known_attacks_are_caught_out_of_sample_and_benign_runs_are_not(tmp_path):
    run = _run_folder(tmp_path)
    traces = sorted(str(p) for p in (run / "traces").glob("*.txt"))
    benign = sorted(str(p) for p in (run / "traces" / "baseline").glob("benign-*.txt"))
    report = ryu.estimate(traces, benign)
    res = report["results"]
    assert report["calibration"]["threshold"] == 0.0         # the loop is fully known: no benign window flagged
    for k in (1, 2):
        assert res[f"rk-2-{k}.txt"]["detected"] and res[f"rk-2-{k}.txt"]["model"] == "leave-one-run-out"
        assert res[f"rk-3-{k}.txt"]["detected"]
        assert not res[f"benign-1-{k}.txt"]["detected"]
        assert not res[f"trust-1-{k}.txt"]["detected"]       # a key/advisory state shows in no system call
    assert report["design"]["train_attacks"] == ["rk-2", "rk-3"]
    assert len(report["design"]["training_attack_runs"]) == 4
    par = report["their_protocol"]
    assert par["classes"] == 6 and 0.0 <= par["accuracy"] <= 1.0 and par["test_windows"] > 0


def test_run_labels_teach_the_model_that_normal_windows_are_attacks(tmp_path):
    """Labelling every window of an attack run (as Ryu et al. do for malware containers) makes the
    app's normal windows look like attacks when attack runs outnumber the normal recordings."""
    run = _run_folder(tmp_path, baseline_len=100, attack_len=2000)
    traces = sorted(str(p) for p in (run / "traces").glob("*.txt"))
    benign = sorted(str(p) for p in (run / "traces" / "baseline").glob("benign-*.txt"))
    clean = ryu.estimate(traces, benign, labels="clean", with_parity=False)["results"]
    raw = ryu.estimate(traces, benign, labels="run", rule="window", with_parity=False)["results"]
    assert not clean["benign-1-1.txt"]["detected"]
    assert raw["benign-1-1.txt"]["detected"] and raw["benign-1-1.txt"]["malicious_share"] > 0.5


def test_a_single_baseline_recording_is_cut_in_thirds(tmp_path):
    run = _run_folder(tmp_path)
    traces = sorted(str(p) for p in (run / "traces").glob("*.txt"))
    report = ryu.estimate(traces, [str(run / "traces" / "baseline" / "benign-1.txt")], with_parity=False)
    assert report["calibration"]["how"] == "thirds of one recording"
    assert len(report["calibration"]["baseline_shares"]) == 3


def test_no_baseline_windows_is_an_error(tmp_path):
    empty = tmp_path / "b.txt"
    empty.write_text("")
    with pytest.raises(ValueError):
        ryu.estimate([], [str(empty)])


def test_summary_counts_rows_and_reads_the_comparison(tmp_path):
    run = _run_folder(tmp_path)
    traces = sorted(str(p) for p in (run / "traces").glob("*.txt"))
    benign = sorted(str(p) for p in (run / "traces" / "baseline").glob("benign-*.txt"))
    report = ryu.estimate(traces, benign, with_parity=False)
    (run / "results").mkdir()
    (run / "results" / "COMPARISON.json").write_text(json.dumps({"tables": {
        "per_scenario": [{"scenario": "rk-2", "label": "malicious", "runs": 2, "PROVBIND": 0},
                         {"scenario": "attack-1", "label": "malicious", "runs": 2, "PROVBIND": 2}],
        "systems": {"PROVBIND": {"kind": "measured", "TP": 2, "FP": 0, "FN": 6, "TN": 2, "precision": 1.0,
                                 "recall": 0.25, "f1": 0.4, "fpr": 0.0}}}}))
    s = ryu.summary(run, report)
    detected_mal = sum(report["results"][f"{x}-{k}.txt"]["detected"]
                       for x in ("rk-2", "rk-3", "attack-1", "trust-1") for k in (1, 2))
    assert s["TP"] == detected_mal and s["FP"] == 0 and s["TN"] == 2
    assert s["known"][1] == 6 and s["unknown"] == [s["unknown"][0], 2]
    assert s["others"]["PROVBIND"]["known"] == [0, 2] and s["others"]["PROVBIND"]["unknown"] == [2, 2]
    text = ryu.render(report, s)
    assert "Ryu-E" in text and "| PROVBIND |" in text and "Their protocol" not in text


def test_cli_writes_the_report_and_summary(tmp_path, capsys):
    run = _run_folder(tmp_path)
    assert ryu.main(["--run", str(run)]) == 0
    report = json.loads((run / "results" / "ryu.json").read_text())
    assert report["system"] == "Ryu-E" and report["estimated"] is True
    assert set(report["results"]) == {p.name for p in (run / "traces").glob("*.txt")}
    assert "summary" in report and "their_protocol" in report
    md = (run / "results" / "RYU.md").read_text()
    assert md.startswith("# Ryu-E") and "Their protocol" in md
    assert "wrote" in capsys.readouterr().err


def test_cli_without_traces_fails_cleanly(tmp_path, capsys):
    assert ryu.main(["--run", str(tmp_path)]) == 2
    assert "no scenario traces" in capsys.readouterr().err
