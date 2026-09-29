"""Helpers for Role 1's end-to-end and evaluation capability tests.

Not a test module (no `test_` prefix), so pytest does not collect it. The E2E and EV tests need
the integrated run folder (alerts.jsonl, falco.jsonl, ground_truth.csv), which is produced on the
demo PC. In a cloud sandbox those files are absent, so the tests record `not_run` and pass.
"""
import os

from eval import compare

# Deterministic detection classes (Sprint Handoff §4.4). D_beh is the behavioural (ML-B) class.
DETERMINISTIC = {"D_exec", "D_write", "D_hash", "D_load", "D_cap", "D_net", "binding"}


def run_dir():
    return os.environ.get("PROVBIND_RUN", "./run")


def load_run(run=None):
    run = run or run_dir()
    return {
        "gt": compare.load_ground_truth(os.path.join(run, "ground_truth.csv")),
        "alerts": compare.load_jsonl(os.path.join(run, "alerts.jsonl")),
        "falco": compare.load_jsonl(os.path.join(run, "falco.jsonl")),
        "alerts_present": os.path.isfile(os.path.join(run, "alerts.jsonl")),
        "falco_present": os.path.isfile(os.path.join(run, "falco.jsonl")),
    }


def rows_for(gt, scenario):
    return [g for g in gt if g.get("scenario") == scenario]


def alerts_in(gt_row, alerts):
    """Alerts matched to one ground-truth row by pod prefix, namespace and time window."""
    start, end = compare.parse_time(gt_row.get("start")), compare.parse_time(gt_row.get("end"))
    return [a for a in alerts
            if compare._matches(gt_row, *compare.alert_pod(a))
            and compare._in_window(compare.parse_time(a.get("time")), start, end)]


def classes(alerts):
    """The set of "class/subclass" strings present in a list of alerts."""
    out = set()
    for a in alerts:
        c = a.get("class", "")
        out.add(f"{c}/{a['subclass']}" if a.get("subclass") else c)
    return out
