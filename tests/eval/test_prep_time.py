"""eval/prep_time.py and figure 1's measured mode (no VM needed)."""
import json

from eval import prep_time
from eval.baselines import plot_contributions as pc


def test_falco_mlb_and_report(tmp_path, monkeypatch):
    out = tmp_path / "prep.jsonl"
    assert prep_time.main(["falco", "--ready-s", "40.5", "42.5", "--out", str(out)]) == 0
    log = tmp_path / "record-d2.log"
    log.write_text("x\nloadgen: 4532 requests in 25200s, 0 failed\nloadgen: 645 requests in 3600s, 0 failed\n")
    data = tmp_path / "mlb"
    data.mkdir()
    (data / "train.jsonl").write_text("{}\n{}\n")
    (data / "validation.jsonl").write_text("{}\n")
    monkeypatch.setattr(prep_time.subprocess, "run",
                        lambda *a, **k: type("P", (), {"returncode": 0, "stderr": ""})())
    assert prep_time.main(["mlb", "--log", str(log), "--data", str(data), "--work", str(tmp_path),
                           "--out", str(out)]) == 0
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    falco, mlb = rows
    assert falco["seconds"] == 0.0 and falco["restart_ready_s"] == 41.5 and falco["restarts"] == 2
    assert mlb["n"] == 4532 and mlb["windows"] == 3 and mlb["parts_s"]["benign_load"] == 25200.0
    with out.open("a") as f:
        f.write(json.dumps({"system": "PROVBIND", "what": "compile", "seconds": 8.4, "seconds_all": [8.4],
                            "n": 5, "n_what": "compiles", "files": 3120}) + "\n")
    assert prep_time.main(["report", "--prep", str(out), "--out", str(tmp_path)]) == 0
    text = (tmp_path / "PREP.md").read_text()
    assert "| PROVBIND | 8.40 s |" in text and "PROVBIND + ML-B" in text and "median of 2 restarts" in text


def test_figure1_uses_measured_times():
    prep = {"PROVBIND": {"seconds": 8.4, "n": 5, "files": 3120},
            "PROVBIND + ML-B": {"seconds": 25210.0, "n": 4532, "windows": 220,
                                "parts_s": {"benign_load": 25200.0, "training": 10.0}},
            "Falco": {"seconds": 0.0, "restart_ready_s": 41.0, "restarts": 6},
            "Confine-E": {"seconds": 44.7, "n": 31, "parts_s": {"startup_observation": 30.0,
                                                               "export_binaries": 12.3, "static_analysis": 2.4}},
            "DeSFAM-E": {"seconds": 1812.5, "n": 320, "windows": 2378,
                         "parts_s": {"profiling": 1800.0, "training": 10.4}}}
    rows = pc.c1_readiness({"prep": prep})
    assert [r["system"] for r in rows] == ["PROVBIND", "PROVBIND + ML-B", "Falco", "Confine-E", "DeSFAM-E"]
    assert all(r["how"] in ("measured", "none") for r in rows)
    assert "n = 5 cold compiles" in rows[0]["note"] and "n = 4,532 requests" in rows[1]["note"]
    assert rows[2]["seconds"] is None and "no per-image step" in rows[2]["note"]
