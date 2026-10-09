"""The final numbers in docs/figures/data/final-2026-10-09: the CSV files agree with each other and with
what the documents claim, and the plotting example runs on them."""
import csv
import subprocess
import sys
from pathlib import Path

import pytest

DATA = Path(__file__).resolve().parents[2] / "docs" / "figures" / "data" / "final-2026-10-09"


def _rows(name):
    with open(DATA / name, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_scenario_rows_add_up_to_the_system_totals():
    scenarios, systems = _rows("detection_by_scenario.csv"), _rows("detection_by_system.csv")
    attack_runs = sum(int(r["runs"]) for r in scenarios if r["truth"] == "malicious")
    benign_runs = sum(int(r["runs"]) for r in scenarios if r["truth"] == "benign")
    assert (attack_runs, benign_runs) == (65, 30)
    for s in systems:
        name = s["system"]
        tp = sum(int(r[name]) for r in scenarios if r["truth"] == "malicious")
        fp = sum(int(r[name]) for r in scenarios if r["truth"] == "benign")
        assert (tp, fp) == (int(s["TP"]), int(s["FP"])), name
        assert int(s["TP"]) + int(s["FN"]) == attack_runs and int(s["FP"]) + int(s["TN"]) == benign_runs, name
        known = sum(int(r[name]) for r in scenarios if r["known_or_unknown"] == "known")
        unknown = sum(int(r[name]) for r in scenarios if r["known_or_unknown"] == "unknown")
        assert (known, unknown) == (int(s["known_caught"]), int(s["unknown_caught"])), name


def test_provbind_application_overhead_is_within_the_20_percent_limit():
    rows = _rows("overhead_opt5.csv")
    app = [r for r in rows if r["configuration"] == "provbind" and r["unit"] in ("ms", "req/s")
           and "worst case" not in r["metric"]]
    assert len(app) == 6
    assert max(float(r["overhead_pct"]) for r in app) == pytest.approx(9.9)


def test_plot_example_draws_four_charts(tmp_path):
    pytest.importorskip("matplotlib")
    pytest.importorskip("pandas")
    done = subprocess.run([sys.executable, str(DATA / "plot_example.py"), "--out", str(tmp_path)],
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr
    names = {"detection.png", "runtime_cost.png", "cost_history.png", "preparation.png"}
    assert {Path(p).name for p in done.stdout.split()} == names
    assert all((tmp_path / n).stat().st_size > 10_000 for n in names)
