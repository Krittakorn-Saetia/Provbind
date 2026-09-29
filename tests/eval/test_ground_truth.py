"""Unit tests for eval/ground_truth.py (Role 1)."""
import csv
import datetime as dt

from eval import compare, ground_truth


def test_append_writes_header_once(tmp_path):
    run = str(tmp_path)
    ground_truth.append_row(run, "attack-1", "malicious", "demo", "demo-app",
                            "2026-09-28T10:14:00Z", "2026-09-28T10:15:00Z", "D_exec + D_write")
    ground_truth.append_row(run, "benign-1", "benign", "demo", "demo-app",
                            "2026-09-28T10:20:00Z", "2026-09-28T10:21:00Z", "nothing above Low")
    text = (tmp_path / "ground_truth.csv").read_text()
    assert text.count("scenario,label,namespace") == 1              # header written once
    rows = list(csv.DictReader(text.splitlines()))
    assert [r["scenario"] for r in rows] == ["attack-1", "benign-1"]


def test_append_one_row_per_run(tmp_path):
    # D4 (§12.2): every scenario runs at least 3 times, one ground-truth row per run.
    run = str(tmp_path)
    for _ in range(3):
        ground_truth.append_row(run, "attack-1", "malicious", "demo", "demo-app",
                                "2026-09-28T10:14:00Z", "2026-09-28T10:15:00Z", "x")
    rows = list(csv.DictReader((tmp_path / "ground_truth.csv").read_text().splitlines()))
    assert len(rows) == 3


def test_now_is_resolved(tmp_path):
    row = ground_truth.append_row(str(tmp_path), "attack-1", "malicious", "demo", "demo-app",
                                  "now", "now", "x")
    # Both parse as timestamps near now, and are not the literal string "now".
    start = compare.parse_time(row["start"])
    assert start is not None and abs((dt.datetime.now(dt.timezone.utc) - start).total_seconds()) < 60


def test_expected_with_commas_is_quoted_and_roundtrips(tmp_path):
    ground_truth.append_row(str(tmp_path), "attack-1", "malicious", "demo", "demo-app",
                            "2026-09-28T10:14:00Z", "2026-09-28T10:15:00Z", "D_exec, then D_write")
    rows = compare.load_ground_truth(str(tmp_path / "ground_truth.csv"))
    assert rows[0]["expected"] == "D_exec, then D_write"


def test_main_cli(tmp_path, capsys):
    rc = ground_truth.main(["--run", str(tmp_path), "--scenario", "benign-1", "--label", "benign",
                            "--pod-prefix", "demo-app", "--start", "2026-09-28T10:20:00Z",
                            "--end", "2026-09-28T10:21:00Z", "--expected", "nothing above Low"])
    assert rc == 0
    assert "benign-1" in capsys.readouterr().out
    assert (tmp_path / "ground_truth.csv").exists()
