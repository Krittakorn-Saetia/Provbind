"""eval/baselines/aggregate.py: four systems joined per ground-truth run."""
import json

from eval.baselines import aggregate


def test_rows_and_tables(tmp_path):
    run = tmp_path
    (run / "ground_truth.csv").write_text(
        "scenario,label,namespace,pod_prefix,start,end,expected\n"
        "attack-1,malicious,demo,demo-app,2026-09-30T10:00:00Z,2026-09-30T10:01:00Z,x\n"
        "benign-1,benign,demo,demo-app,2026-09-30T10:02:00Z,2026-09-30T10:03:00Z,y\n")
    (run / "alerts.jsonl").write_text(json.dumps(
        {"container": "demo/demo-app-1/app", "time": "2026-09-30T10:00:10Z", "class": "D_exec",
         "subclass": "undeclared", "bucket": "critical"}) + "\n")
    (run / "falco.jsonl").write_text(json.dumps(
        {"time": "2026-09-30T10:02:10Z", "rule": "Terminal shell", "priority": "Notice",
         "output_fields": {"k8s.ns.name": "demo", "k8s.pod.name": "demo-app-1"}}) + "\n")
    conf = run / "confine.json"
    conf.write_text(json.dumps({"results": {"attack-1-1.txt": {"blocked": False}, "benign-1-1.txt": {"blocked": False}}}))
    des = run / "desfam.json"
    des.write_text(json.dumps({"results": {"attack-1-1.txt": {"detected": True}, "benign-1-1.txt": {"detected": False}}}))

    rows = aggregate.rows_for(run, conf, des)
    a, b = rows
    assert a["PROVBIND"] and a["PROVBIND_stage"] == "runtime" and not a["Falco"]
    assert not a["Confine-E"] and a["DeSFAM-E"]
    assert b["Falco"] and not b["PROVBIND"]
    t = aggregate.tables(rows)
    assert t["systems"]["PROVBIND"]["TP"] == 1 and t["systems"]["Falco"]["FP"] == 1
    assert t["systems"]["Confine-E"]["kind"] == "estimated"
    assert "estimated" in aggregate.render(t)
