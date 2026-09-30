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


def test_sig_only_from_bindings(tmp_path):
    """Sig-only catches an unsigned artifact (ak-2) but not a revoked key (ak-3)."""
    run = tmp_path
    (run / "ground_truth.csv").write_text(
        "scenario,label,namespace,pod_prefix,start,end,expected\n"
        "ak-2,malicious,demo,demo-app-unsigned,2026-09-30T10:00:00Z,2026-09-30T10:01:00Z,binding failure\n"
        "ak-3,malicious,demo,demo-app-akrev,2026-09-30T10:02:00Z,2026-09-30T10:03:00Z,v_trust\n")
    (run / "alerts.jsonl").write_text("")
    (run / "falco.jsonl").write_text("")
    # Both pods failed admission, but for different reasons.
    (run / "bindings.json").write_text(json.dumps({
        "c1": {"namespace": "demo", "pod": "demo-app-unsigned-abc", "verified": False,
               "reason": "v_sig: no matching signatures found"},
        "c2": {"namespace": "demo", "pod": "demo-app-akrev-xyz", "verified": False,
               "reason": "key: cosign key is revoked"},
    }))

    rows = aggregate.rows_for(run)
    by = {r["scenario"]: r for r in rows}
    assert by["ak-2"]["Sig-only"] and by["ak-2"]["Sig-only_stage"] == "admission"
    assert not by["ak-3"]["Sig-only"]        # revoked key: a signature check misses it
    t = aggregate.tables(rows)
    assert t["systems"]["Sig-only"]["kind"] == "derived"
    assert t["systems"]["Sig-only"]["TP"] == 1 and t["systems"]["Sig-only"]["FN"] == 1


def test_sig_only_from_saved_bindings_after_teardown(tmp_path):
    """The pods are gone from bindings.json; the saved copies count only inside their own run's window."""
    run = tmp_path
    (run / "ground_truth.csv").write_text(
        "scenario,label,namespace,pod_prefix,start,end,expected\n"
        "ak-2,malicious,demo,demo-app-unsigned,2026-09-30T10:00:00Z,2026-09-30T10:01:00Z,binding failure\n"
        "ak-2,malicious,demo,demo-app-unsigned,2026-09-30T10:05:00Z,2026-09-30T10:06:00Z,binding failure\n")
    (run / "alerts.jsonl").write_text("")
    (run / "falco.jsonl").write_text("")
    (run / "bindings.json").write_text("{}")                       # the controller forgot both pods
    (run / "results").mkdir()
    (run / "results" / "admission-bindings.jsonl").write_text(json.dumps(
        {"namespace": "demo", "pod": "demo-app-unsigned-abc", "verified": False,
         "reason": "v_sig: no matching signatures found", "snapshot_at": "2026-09-30T10:00:40Z"}) + "\n")

    first, second = aggregate.rows_for(run)
    assert first["Sig-only"]            # its window holds the saved copy
    assert not second["Sig-only"]       # no copy saved during the second run
