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
    matrix = compare.scoring_matrix(rows) if rows else None

    run = os.environ.get("PROVBIND_RUN", "./run")
    art_dir = os.path.join(run, "results", "EV-01")
    os.makedirs(art_dir, exist_ok=True)
    art = os.path.join(art_dir, "table.md")
    with open(art, "w", encoding="utf-8") as f:
        f.write(compare.render_table(rows) + "\n\n" + (compare.render_matrix(matrix) if matrix else "") + "\n")

    metrics = {"scenarios": len(rows)}
    if matrix:
        # REPORT.md shows the first four metrics, so the headline numbers come first.
        pb, fa = (matrix["scopes"]["all"]["systems"][s] for s in ("PROVBIND", "Falco"))
        rt_pb, rt_fa = (matrix["scopes"]["runtime"]["systems"][s] for s in ("PROVBIND", "Falco"))
        metrics = {"provbind_f1": pb["f1"], "falco_f1": fa["f1"], "provbind_fpr": pb["fpr"], "falco_fpr": fa["fpr"],
                   "scenarios": len(rows),
                   **{f"provbind_{k}": pb[k] for k in ("TP", "FP", "FN", "TN", "precision", "recall", "accuracy")},
                   **{f"falco_{k}": fa[k] for k in ("TP", "FP", "FN", "TN", "precision", "recall", "accuracy")},
                   "runtime_provbind_f1": rt_pb["f1"], "runtime_falco_f1": rt_fa["f1"],
                   "too_few_runs": matrix["too_few_runs"]}
    # The pass criterion is that the per-system table is produced across the scenarios.
    record_result("EV-01", "pass" if rows else "fail", metrics=metrics, artifacts=[art],
                  notes="PROVBIND vs Falco per scenario, with the scoring matrix; see table.md" if rows
                        else "no ground-truth rows matched")
    assert rows
