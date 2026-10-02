"""eval/baselines/plot_contributions.py: the data behind each contribution figure, and the PNGs."""
import json

import pytest

from eval.baselines import aggregate
from eval.baselines import plot_contributions as pc

SYS = [n for n, _ in aggregate.SYSTEMS]


def _row(scenario, label, stage=None, *hit):
    return {"scenario": scenario, "label": label, "PROVBIND_stage": stage, **{n: n in hit for n in SYS}}


def _run(tmp_path, oh01=None):
    run = tmp_path
    for d in ("results", "envelopes", "traces/baseline"):
        (run / d).mkdir(parents=True)
    rows = [_row("ak-2", "malicious", "admission", "PROVBIND", "Sig-only"),
            _row("ak-3", "malicious", "admission", "PROVBIND"),
            _row("trust-2", "malicious", "trust", "PROVBIND"),
            _row("ru-3", "malicious", "runtime", "PROVBIND", "DeSFAM-E"),
            _row("rk-2", "malicious", None, "Confine-E"),
            _row("benign-1", "benign", None, "Falco"),
            _row("benign-3", "benign", None),
            _row("tamper-1", "malicious", None, "PROVBIND")]
    (run / "results" / "COMPARISON.json").write_text(json.dumps({"rows": rows, "tables": aggregate.tables(rows)}))
    (run / "ground_truth.csv").write_text(
        "scenario,label,namespace,pod_prefix,start,end,expected\n"
        "ru-3,malicious,demo,demo-app,2026-10-02T10:00:00Z,2026-10-02T10:01:00Z,x\n"
        "benign-1,benign,demo,demo-app,2026-10-02T10:02:00Z,2026-10-02T10:03:00Z,y\n")
    alerts = [{"time": "2026-10-02T10:00:10Z", "container": "demo/demo-app-1/app", "class": "D_net", "bucket": "high",
               "violated_clause": "connect: 203.0.113.9: not allowed",
               "attribution": {"layer": "sha256:aa", "package": None, "process_chain": ["/usr/bin/python3"],
                               "dependency_path": []}},
              {"time": "2026-10-02T10:00:20Z", "container": "demo/demo-app-1/app", "class": "D_exec", "bucket": "critical",
               "violated_clause": "exec: /tmp/x: in no layer",
               "attribution": {"layer": "sha256:bb", "package": "requestz-helper", "process_chain": ["/usr/bin/python3"],
                               "dependency_path": ["demo-app", "requestz-helper"]}},
              {"time": "2026-10-02T10:02:30Z", "container": "demo/demo-app-1/app", "class": "D_exec", "bucket": "low",
               "violated_clause": "x", "attribution": {}},                    # Low and benign window: not counted
              {"time": "2026-10-02T10:05:00Z", "container": "demo/demo-app-1/app", "class": "trust", "subclass": "key",
               "bucket": "high", "latency_s": 2.4},
              {"time": "2026-10-02T10:06:00Z", "container": "demo/demo-app-1/app", "class": "trust", "subclass": "comp",
               "bucket": "high", "latency_s": 3.1}]
    (run / "alerts.jsonl").write_text("".join(json.dumps(a) + "\n" for a in alerts))
    (run / "falco.jsonl").write_text(json.dumps(
        {"time": "2026-10-02T10:00:30Z", "rule": "Outbound connection", "priority": "Notice",
         "output_fields": {"k8s.ns.name": "demo", "k8s.pod.name": "demo-app-1", "proc.name": "python3"}}) + "\n")
    for i, total in enumerate((4000, 6000)):
        (run / "envelopes" / f"e{i}.json").write_text(json.dumps(
            {"timings_ms": {"evidence": total * 0.6, "union": total * 0.3, "validate": total * 0.1},
             "files": {f"/f{j}": {} for j in range(100 + i)}}))
    (run / "traces" / "baseline" / "benign-1.txt").write_text("0\t1\tpython\tread\n600000000000\t1\tpython\tread\n")
    (run / "results" / "desfam.json").write_text(json.dumps({"published_reference": {"recall": 0.9, "fpr": 0.016}}))
    if oh01 is not None:
        (run / "results" / "OH-01.json").write_text(json.dumps(oh01))
    return run


def test_c1_readiness_and_steps(tmp_path):
    d = pc.load_run(_run(tmp_path))
    ready = {r["system"]: r for r in pc.c1_readiness(d)}
    assert ready["PROVBIND"]["seconds"] == 5.0 and ready["PROVBIND"]["how"] == "measured"   # median of 4 s and 6 s
    assert ready["Confine-E"]["seconds"] == 30.0 and ready["Confine-E"]["how"] == "by design"
    assert ready["DeSFAM-E"]["seconds"] == 600.0             # the baseline trace's real span
    assert ready["Falco"]["seconds"] is None
    st = pc.c1_steps(d)
    assert [k for k, _ in st["steps"]] == ["evidence", "union", "validate"] and st["total_s"] == 5.0
    assert st["index_ms"] is None                             # no OH-04: said, not invented


def test_c2_scope_metrics_and_latency(tmp_path):
    d = pc.load_run(_run(tmp_path, oh01={"status": "fail", "notes": "rec.jsonl: 5000 events verified",
                                        "metrics": {"events": 5000, "p50_ns": 4000, "p99_ns": 15000}}))
    m = {x["system"]: x for x in pc.c2_metrics(d["rows"])}
    # trust/admission-trust rows and tamper-1 are left out: 2 attack runs (ru-3, rk-2), 2 benign runs
    assert m["PROVBIND"]["attack_runs"] == 2 and m["PROVBIND"]["benign_runs"] == 2
    assert m["PROVBIND"]["recall"] == 0.5 and m["PROVBIND"]["fpr"] == 0.0
    assert m["Falco"]["fpr"] == 0.5 and m["Confine-E"]["kind"] == "estimated"
    lat = pc.c2_latency(d)
    assert lat == {"p50_us": 4.0, "p99_us": 15.0, "events": 5000, "short": True}


def test_c2_latency_ignores_synthetic(tmp_path):
    d = pc.load_run(_run(tmp_path, oh01={"status": "not_run", "notes": "synthetic library",
                                        "metrics": {"events": 9, "p50_ns": 1, "p99_ns": 2}}))
    assert pc.c2_latency(d) is None


def test_c3_attribution_shares(tmp_path):
    att = pc.c3_attribution(pc.load_run(_run(tmp_path)))
    prov = dict(zip(att["fields"], att["share"]["PROVBIND"]))
    assert att["n"]["PROVBIND"] == 2                           # the Low alert and the benign window are excluded
    assert prov["Container / pod"] == 1.0 and prov["Package"] == 0.5 and prov["Dependency path"] == 0.5
    falco = dict(zip(att["fields"], att["share"]["Falco"]))
    assert falco["Process"] == 1.0 and falco["Package"] == 0.0
    assert att["how"]["DeSFAM-E"] == "by design" and att["share"]["Confine-E"] == [0.0] * 6


def test_c4_matrix_and_trust_latency(tmp_path):
    d = pc.load_run(_run(tmp_path))
    systems, rows = pc.c4_matrix(d["rows"])
    by = {r["scenario"]: r for r in rows}
    assert systems[-1] == "Sig-only" and list(by) == ["ak-2", "ak-3", "trust-2"]
    assert by["ak-2"]["caught"] == [1, 0, 0, 0, 1] and by["trust-2"]["provbind_stage"] == "trust"
    lat = pc.c4_trust_latency(d["alerts"])
    assert lat == {"Key revoked": [2.4], "Advisory\n(component)": [3.1]}


def test_missing_comparison_is_an_error(tmp_path):
    assert pc.main(["--run", str(tmp_path)]) == 1


def test_renders_five_pngs(tmp_path):
    pytest.importorskip("matplotlib")
    run = _run(tmp_path)
    assert pc.main(["--run", str(run), "--dpi", "60"]) == 0
    for name, _ in pc.FIGURES:
        assert (run / "results" / "figures" / name).read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
