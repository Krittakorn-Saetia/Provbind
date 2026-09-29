"""Unit tests for eval/compare.py (Role 1)."""
import datetime as dt

import pytest

from eval import compare


# --- parse_time ---------------------------------------------------------------------------

def test_parse_time_z_suffix():
    t = compare.parse_time("2026-09-28T10:14:22Z")
    assert t == dt.datetime(2026, 9, 28, 10, 14, 22, tzinfo=dt.timezone.utc)


def test_parse_time_offset():
    assert compare.parse_time("2026-09-28T17:14:22+07:00") == \
        dt.datetime(2026, 9, 28, 10, 14, 22, tzinfo=dt.timezone.utc)


def test_parse_time_nanoseconds_truncated_to_micros():
    # Falco prints nanoseconds; datetime keeps microseconds.
    t = compare.parse_time("2026-09-28T10:14:22.123456789Z")
    assert t.microsecond == 123456 and t.tzinfo is dt.timezone.utc


def test_parse_time_naive_gets_utc():
    assert compare.parse_time("2026-09-28T10:14:22").tzinfo == dt.timezone.utc


@pytest.mark.parametrize("bad", ["", None, "not-a-time", "2026-13-40T99:99:99Z"])
def test_parse_time_bad_is_none(bad):
    assert compare.parse_time(bad) is None


# --- loaders ------------------------------------------------------------------------------

def test_load_jsonl_missing_file(tmp_path):
    assert compare.load_jsonl(str(tmp_path / "nope.jsonl")) == []


def test_load_jsonl_skips_bad_lines(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text('{"x":1}\n\nnot json\n{"y":2}\n')
    assert compare.load_jsonl(str(p)) == [{"x": 1}, {"y": 2}]


def test_load_ground_truth(tmp_path):
    p = tmp_path / "ground_truth.csv"
    p.write_text("scenario,label,namespace,pod_prefix,start,end,expected\n"
                 "attack-1,malicious,demo,demo-app,2026-09-28T10:14:00Z,2026-09-28T10:15:00Z,D_exec + D_write\n")
    rows = compare.load_ground_truth(str(p))
    assert len(rows) == 1 and rows[0]["scenario"] == "attack-1" and rows[0]["expected"] == "D_exec + D_write"


# --- pod extraction -----------------------------------------------------------------------

def test_alert_pod_from_container_string():
    assert compare.alert_pod({"container": "demo/demo-app-7d9f/app"}) == ("demo", "demo-app-7d9f")


def test_alert_pod_explicit_fields_win():
    assert compare.alert_pod({"container": "x/y/z", "namespace": "demo", "pod": "p"}) == ("demo", "p")


def test_falco_pod():
    line = {"output_fields": {"k8s.ns.name": "demo", "k8s.pod.name": "demo-app-7d9f"}}
    assert compare.falco_pod(line) == ("demo", "demo-app-7d9f")


# --- compare ------------------------------------------------------------------------------

def _gt(scenario="attack-1", label="malicious", expected="x"):
    return {"scenario": scenario, "label": label, "namespace": "demo", "pod_prefix": "demo-app",
            "start": "2026-09-28T10:14:00Z", "end": "2026-09-28T10:15:00Z", "expected": expected}


def _alert(bucket="critical", cls="D_exec", sub="undeclared", t="2026-09-28T10:14:22Z", pod="demo-app-7d9f"):
    return {"container": f"demo/{pod}/app", "time": t, "class": cls, "subclass": sub, "bucket": bucket}


def _falco(rule="Terminal shell in container", prio="Warning", t="2026-09-28T10:14:30Z", pod="demo-app-7d9f"):
    return {"time": t, "rule": rule, "priority": prio,
            "output_fields": {"k8s.ns.name": "demo", "k8s.pod.name": pod}}


def test_compare_matches_by_pod_and_window():
    rows = compare.compare([_gt()], [_alert(), _alert(bucket="high", cls="D_write", sub="declared_file")],
                           [_falco()])
    r = rows[0]
    assert r["provbind_alerts"] == 2
    assert r["provbind_classes"] == ["D_exec/undeclared", "D_write/declared_file"]
    assert r["provbind_top_bucket"] == "critical"        # most severe of critical + high
    assert r["provbind_detected"] is True
    assert r["falco_hits"] == 1 and r["falco_top_priority"] == "warning"
    assert r["falco_detected"] is True


def test_compare_excludes_out_of_window():
    late = _alert(t="2026-09-28T10:20:00Z")
    assert compare.compare([_gt()], [late], [])[0]["provbind_alerts"] == 0


def test_compare_excludes_wrong_namespace_and_pod():
    other_ns = _alert()
    other_ns["container"] = "kube-system/demo-app-7d9f/app"
    other_pod = _alert(pod="unrelated-123")
    r = compare.compare([_gt()], [other_ns, other_pod], [])[0]
    assert r["provbind_alerts"] == 0


def test_compare_benign_no_alerts():
    r = compare.compare([_gt(scenario="benign-1", label="benign", expected="nothing above Low")], [], [])[0]
    assert r["provbind_alerts"] == 0 and r["provbind_detected"] is False and r["falco_detected"] is False


def test_compare_low_bucket_is_not_detected():
    r = compare.compare([_gt()], [_alert(bucket="low", cls="D_exec", sub="outside_closure")], [])[0]
    assert r["provbind_alerted"] is True and r["provbind_detected"] is False   # alerted, but not above Low


def test_compare_highest_falco_priority_wins():
    r = compare.compare([_gt()], [], [_falco(prio="Warning"), _falco(rule="Write below etc", prio="Error")])[0]
    assert r["falco_top_priority"] == "error"


def test_render_table_has_header_and_row():
    out = compare.render_table(compare.compare([_gt()], [_alert()], [_falco()]))
    assert "Scenario" in out and "PROVBIND" in out and "attack-1" in out
    assert "\n" in out


def test_main_json_output(tmp_path, capsys):
    (tmp_path / "ground_truth.csv").write_text(
        "scenario,label,namespace,pod_prefix,start,end,expected\n"
        "attack-1,malicious,demo,demo-app,2026-09-28T10:14:00Z,2026-09-28T10:15:00Z,x\n")
    (tmp_path / "alerts.jsonl").write_text('{"container":"demo/demo-app-7d9f/app",'
                                           '"time":"2026-09-28T10:14:22Z","class":"D_exec",'
                                           '"subclass":"undeclared","bucket":"critical"}\n')
    rc = compare.main(["--run", str(tmp_path), "--json"])
    assert rc == 0
    assert '"provbind_detected": true' in capsys.readouterr().out


def test_main_no_ground_truth_returns_1(tmp_path):
    assert compare.main(["--run", str(tmp_path)]) == 1


# --- scoring matrix ------------------------------------------------------------------------

def _row(scenario, label, pb, falco):
    return {"scenario": scenario, "label": label, "provbind_detected": pb, "falco_detected": falco}


# 3 malicious runs and 3 benign runs of each kind; values chosen so every cell is known by hand.
MATRIX_ROWS = (
    [_row("attack-1", "malicious", True, True)] * 3            # both detect
    + [_row("trust-1", "malicious", True, False)] * 3          # Falco has no trust check
    + [_row("benign-1", "benign", False, True)] * 3            # Falco's shell rule: a false positive
    + [_row("ph4-14", "benign", False, False)] * 3
    + [_row("tamper-1", "malicious", True, False)]             # integrity check: listed, never counted
)


def test_confusion_counts():
    c = compare.confusion(MATRIX_ROWS[:12], "falco_detected")
    assert c == {"TP": 3, "FP": 3, "FN": 3, "TN": 3}


def test_metrics_formulas():
    m = compare.metrics({"TP": 3, "FP": 3, "FN": 3, "TN": 3})
    assert m == {"precision": 0.5, "recall": 0.5, "f1": 0.5, "fpr": 0.5, "accuracy": 0.5}


def test_metrics_zero_denominators_are_none():
    m = compare.metrics({"TP": 0, "FP": 0, "FN": 2, "TN": 0})
    assert m["precision"] is None and m["recall"] == 0.0 and m["f1"] is None and m["fpr"] is None


def test_scoring_matrix_scopes_and_exclusions():
    m = compare.scoring_matrix(MATRIX_ROWS)
    allsc, rt = m["scopes"]["all"], m["scopes"]["runtime"]
    assert (allsc["runs"], allsc["malicious"], allsc["benign"]) == (12, 6, 6)      # tamper-1 not counted
    pb = allsc["systems"]["PROVBIND"]
    assert (pb["TP"], pb["FP"], pb["FN"], pb["TN"]) == (6, 0, 0, 6)
    assert allsc["systems"]["PROVBIND"]["f1"] == 1.0
    assert allsc["systems"]["Falco"]["recall"] == 0.5 and allsc["systems"]["Falco"]["fpr"] == 0.5
    # Runtime scope leaves trust-* out: Falco then detects every malicious run.
    assert (rt["runs"], rt["malicious"]) == (9, 3)
    assert rt["systems"]["Falco"]["recall"] == 1.0
    tamper = [s for s in m["per_scenario"] if s["scenario"] == "tamper-1"][0]
    assert tamper["counted"] is False and m["too_few_runs"] == ["tamper-1"]


def test_render_matrix_mentions_both_scopes_and_imbalance():
    text = compare.render_matrix(compare.scoring_matrix(MATRIX_ROWS[:3] + MATRIX_ROWS[6:12]))
    assert "Scoring matrix" in text and "Precision" in text and "Runtime scenarios only" in text
    assert "unbalanced" in text                                   # 3 malicious vs 6 benign


def test_main_writes_scoring_files(tmp_path, capsys):
    (tmp_path / "ground_truth.csv").write_text(
        "scenario,label,namespace,pod_prefix,start,end,expected\n"
        "attack-1,malicious,demo,demo-app,2026-09-28T10:14:00Z,2026-09-28T10:15:00Z,x\n"
        "benign-1,benign,demo,demo-app,2026-09-28T10:20:00Z,2026-09-28T10:21:00Z,y\n")
    (tmp_path / "alerts.jsonl").write_text('{"container":"demo/demo-app-7d9f/app","time":"2026-09-28T10:14:22Z",'
                                           '"class":"D_exec","subclass":"undeclared","bucket":"critical"}\n')
    assert compare.main(["--run", str(tmp_path), "--write"]) == 0
    out = capsys.readouterr().out
    assert "Scoring matrix" in out and "PROVBIND" in out
    assert (tmp_path / "results" / "SCORING.md").exists()
    doc = __import__("json").loads((tmp_path / "results" / "SCORING.json").read_text())
    assert doc["matrix"]["scopes"]["all"]["systems"]["PROVBIND"]["TP"] == 1


def test_report_ignores_scoring_json(tmp_path, capsys):
    from eval import report
    d = tmp_path / "results"
    d.mkdir()
    (d / "SCORING.json").write_text('{"rows": [], "matrix": {}}')
    (d / "EV-01.json").write_text('{"id": "EV-01", "status": "pass"}')
    assert set(report.load_results(str(d))) == {"EV-01"}
    assert "skipping" not in capsys.readouterr().err
