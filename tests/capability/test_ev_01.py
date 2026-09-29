"""EV-01: detection per scenario, PROVBIND against Falco (Test Plan §3.11, owner R1, P0).

Pass criterion: a table of "detected or not, per system" across the E2E scenarios. This runs on
the demo PC after the scenarios and Falco capture; in a cloud sandbox the run artifacts are
absent, so it records `not_run`. Evidence is built by eval/compare.py.
"""
import os

from eval import compare

from .e2e_helpers import load_run


def test_ev_01(record_result):
    data = load_run()
    if not data["gt"] or not data["alerts_present"] or not data["falco_present"]:
        record_result("EV-01", "not_run",
                      notes="needs run/ground_truth.csv, run/alerts.jsonl and run/falco.jsonl "
                            "from the demo PC (make attack / make benign, with Falco capture)")
        return

    rows = compare.compare(data["gt"], data["alerts"], data["falco"])
    table = compare.render_table(rows)

    run = os.environ.get("PROVBIND_RUN", "./run")
    art_dir = os.path.join(run, "results", "EV-01")
    os.makedirs(art_dir, exist_ok=True)
    art = os.path.join(art_dir, "table.md")
    with open(art, "w", encoding="utf-8") as f:
        f.write(table + "\n")

    malicious = [r for r in rows if r["label"] == "malicious"]
    benign = [r for r in rows if r["label"] == "benign"]
    metrics = {
        "scenarios": len(rows),
        "provbind_detected_malicious": sum(r["provbind_detected"] for r in malicious),
        "falco_detected_malicious": sum(r["falco_detected"] for r in malicious),
        "provbind_alerts_on_benign": sum(r["provbind_detected"] for r in benign),
        "falco_alerts_on_benign": sum(r["falco_detected"] for r in benign),
    }
    # The pass criterion is that the per-system table is produced across the scenarios.
    record_result("EV-01", "pass" if rows else "fail", metrics=metrics, artifacts=[art],
                  notes="PROVBIND vs Falco per scenario; see table.md" if rows
                        else "no ground-truth rows matched")
    assert rows
