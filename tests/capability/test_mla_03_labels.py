"""MLA-03: ground-truth capability labels from observed use (Test Plan §3.4, §4.2; owner R1, P0).

Pass criterion: `ml/data/labels.jsonl`, one row per image, from profiling at least 20 images under
Tetragon's `cap_capable` policy (testbed/profile_corpus.sh on the demo PC). The file checked is
PROVBIND_ML_LABELS if set, else ml/data/labels.jsonl. Without it the test records `not_run`.

Each row must: carry a sha256 digest, unique across the file (Role 2 joins by digest); use only
capability names from ml.alg1.ALL_CAPS; keep denied-only checks out of the labels; come from two
runs with the disagreement recorded (the label noise, §4.2); and record no pod of its own, because
every image is profiled in a default pod and ml.dataset refuses such a row.
"""
import json
import os
import pathlib
import re

from ml.alg1 import ALL_CAPS
from testbed.profiling.labels import rare_labels

ROOT = pathlib.Path(__file__).resolve().parents[2]
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MIN_IMAGES = 20                                            # §4.7
OWN_POD_FIELDS = ("allowed", "securityContext", "deployment")  # ml.dataset refuses these


def _labels_path():
    return pathlib.Path(os.environ.get("PROVBIND_ML_LABELS") or ROOT / "ml" / "data" / "labels.jsonl")


def row_problems(rows):
    """Every problem found in the label rows, as readable strings."""
    problems, seen, caps = [], set(), set(ALL_CAPS)
    for n, r in enumerate(rows, 1):
        where = f"row {n} ({r.get('image', '?')})"
        d = r.get("digest")
        if not isinstance(d, str) or not DIGEST.match(d):
            problems.append(f"{where}: digest {d!r} is not sha256:<64 hex>")
        elif d in seen:
            problems.append(f"{where}: digest {d[:19]} appears twice")
        seen.add(d)
        labels, denied = r.get("labels"), r.get("denied", [])
        if not isinstance(labels, list):
            problems.append(f"{where}: labels is not a list")
            labels = []
        bad = sorted(set(labels) - caps) + sorted(set(denied) - caps)
        if bad:
            problems.append(f"{where}: unknown capability names {bad}")
        if set(labels) & set(denied):
            problems.append(f"{where}: {sorted(set(labels) & set(denied))} both granted and denied-only")
        if not isinstance(r.get("runs"), int) or r["runs"] < 2:
            problems.append(f"{where}: runs is {r.get('runs')!r}, §4.2 wants two runs")
        if "run_disagreement" not in r:
            problems.append(f"{where}: run_disagreement not recorded")
        own = [f for f in OWN_POD_FIELDS if f in r]
        if own:
            problems.append(f"{where}: records a pod of its own ({own}); profile in a default pod")
    return problems


def test_mla_03_labels(record_result):
    path = _labels_path()
    if not path.is_file():
        record_result("MLA-03", "not_run",
                      notes=f"no {path.name}: run `make profile` on the demo PC (testbed/profile_corpus.sh)")
        return

    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    problems = row_problems(rows)
    noisy = sum(1 for r in rows if r.get("run_disagreement"))
    metrics = {
        "images": len(rows),
        "images_whose_runs_disagree": noisy,
        "run_disagreement_rate": round(noisy / len(rows), 4) if rows else None,
        "distinct_labels": len({c for r in rows for c in r.get("labels", [])}),
        "mean_labels_per_image": round(sum(len(r.get("labels", [])) for r in rows) / len(rows), 2) if rows else None,
        "too_rare_labels": rare_labels(rows),
    }
    if problems:
        status, notes = "fail", f"{len(problems)} problem(s): " + "; ".join(problems[:5])
    elif len(rows) < MIN_IMAGES:
        status, notes = "fail", f"{len(rows)} images profiled; Test Plan §4.7 needs at least {MIN_IMAGES}"
    else:
        status, notes = "pass", f"{len(rows)} images, two runs each; label noise in {noisy}"
    record_result("MLA-03", status, metrics=metrics, artifacts=[str(path)], notes=notes)
    assert status == "pass", notes
