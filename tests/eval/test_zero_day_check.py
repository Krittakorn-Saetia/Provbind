"""eval/zero_day_check.py on a small fake run folder (no VM needed)."""
import json
import os
import time

from eval import zero_day_check as z

HEX = "ab" * 32


def make_run(tmp_path, leak=False):
    run = tmp_path / "run"
    for d in ("envelopes", "traces/baseline", "advisories", f"envelopes/{HEX}.mlb"):
        (run / d).mkdir(parents=True, exist_ok=True)
    files = {"/usr/bin/ls": {"package": "coreutils", "layer": 0}}
    if leak:
        files["/tmp/.x9"] = {"package": None, "layer": 2}
    (run / "envelopes" / f"{HEX}.json").write_text(json.dumps({"compiled_at": "2026-10-01T10:00:00Z", "files": files}))
    (run / "envelopes" / "cd.json").write_text(json.dumps(
        {"compiled_at": "2026-10-01T10:00:00Z", "files": {"/usr/local/bin/helperd": {"package": None}}}))
    (run / "ground_truth.csv").write_text(
        "scenario,label,namespace,pod_prefix,start,end,expected\n"
        "benign-1,benign,demo,demo-app,2026-10-02T09:00:00Z,2026-10-02T09:01:00Z,x\n"
        "attack-2,malicious,demo,demo-app,2026-10-02T09:05:00Z,2026-10-02T09:06:00Z,y\n")
    old = time.mktime((2026, 10, 1, 12, 0, 0, 0, 0, 0))
    for name in ("benign-1.txt",):
        p = run / "traces" / "baseline" / name
        p.write_text("1\t1\tpython\tread\n")
        os.utime(p, (old, old))
    model = run / "envelopes" / f"{HEX}.mlb" / "model.json"
    model.write_text("{}")
    os.utime(model, (old, old))
    data = tmp_path / HEX
    data.mkdir()
    end = "2026-10-02T09:05:30Z" if leak else "2026-10-01T18:00:30Z"
    (data / "train.jsonl").write_text(json.dumps({"start": "2026-10-01T18:00:00Z", "end": end}) + "\n")
    (data / "validation.jsonl").write_text(json.dumps({"start": "2026-10-01T19:00:00Z", "end": "2026-10-01T19:00:30Z"}) + "\n")
    (run / "advisories" / "a.json").write_text(json.dumps({"affected": [{"package": {"name": "requestz-helper"}}]}))
    egress = tmp_path / "egress.json"
    egress.write_text(json.dumps({"allow": ["10.0.0.0/8"]}))
    return run, data, egress


def test_clean_run_passes(tmp_path):
    run, data, egress = make_run(tmp_path)
    rows = {r["check"].split()[0]: r for r in z.run_checks(run, data, egress, helm=False, digest=HEX)}
    assert all(rows[k]["status"] == "pass" for k in ("Z1", "Z2", "Z3", "Z4", "Z5", "Z6")), rows


def test_leaks_are_reported(tmp_path):
    run, data, egress = make_run(tmp_path, leak=True)
    rows = {r["check"].split()[0]: r for r in z.run_checks(run, data, egress, helm=False, digest=HEX)}
    assert rows["Z2"]["status"] == "fail" and "/tmp/.x9" in rows["Z2"]["detail"]
    assert rows["Z3"]["status"] == "fail" and "1 overlap an attack row" in rows["Z3"]["detail"]
    assert z.main(["--run", str(run), "--mlb-data", str(data), "--egress", str(egress), "--no-helm"]) == 1
    assert (run / "results" / "ZERODAY.md").exists()
