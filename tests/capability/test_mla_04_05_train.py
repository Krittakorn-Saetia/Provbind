"""MLA-04: LightGBM trains and predicts under repeated 5-fold cross-validation by image.
MLA-05: ML-A against the four baselines on the same folds (Test Plan §§3.4, 4.4-4.7).

Data: PROVBIND_ML_DATASET if set, otherwise ml/data/dataset.jsonl if it exists (dataset D1,
handoff T13 step 3). Until D1 exists (MLA-03, profiled by Role 1), this runs the whole pipeline
on the synthetic 40-image dataset in tests/ml/synthetic.py and records not_run: the pipeline
works, but synthetic numbers are not results.

- MLA-04 passes when the model is saved and reloads with the same predictions, and per-label,
  micro and macro metrics are reported, on at least 20 images (§4.7). Fewer images is blocked
  on MLA-03.
- MLA-05 passes when the comparison table is reported. Whether ML-A beats the allowlist on
  under-prediction goes in the notes either way: §4.7 counts a loss as a legitimate result.

Artifacts in $PROVBIND_RUN/results/MLA-04/: report.json, comparison.md, sweep.md, model/model.json.
"""
import json
import os
from pathlib import Path

import pytest

from ml.train import (BASELINES, MIN_IMAGES, CapabilityModel, comparison_table, evaluate, fit, load_dataset, matrix,
                      row_features, sweep_table, trainable_labels, write_text_atomically)
from tests.ml import synthetic

ROOT = Path(__file__).resolve().parents[2]
RUN = Path(os.environ.get("PROVBIND_RUN", "./run"))
DATASET = ROOT / "ml" / "data" / "dataset.jsonl"
SYNTHETIC_NOTE = ("D1 not collected yet (MLA-03), so this ran on the synthetic 40-image dataset "
                  "(tests/ml/synthetic.py): the pipeline works end to end, but the numbers are not results. "
                  "Set PROVBIND_ML_DATASET or write ml/data/dataset.jsonl for the real test")


def _dataset():
    path = os.environ.get("PROVBIND_ML_DATASET") or (str(DATASET) if DATASET.exists() else None)
    return (load_dataset(path), path) if path else (synthetic.rows(), None)


def _round(m):
    return None if m is None else round(m["mean"], 4)


@pytest.fixture(scope="module")
def trained():
    rows, source = _dataset()
    out = RUN / "results" / "MLA-04"
    report = evaluate(rows)
    labels, too_rare = trainable_labels(rows)
    model = fit(rows, labels, too_rare=too_rare)
    model_path = model.save(out / "model")
    X = matrix([row_features(r, model.vocabulary) for r in rows], model.feature_names)
    reloads = CapabilityModel.load(out / "model").predict_proba_matrix(X) == model.predict_proba_matrix(X)
    table, sweep = comparison_table(report), sweep_table(report)
    for name, text in (("report.json", json.dumps(report, indent=2)), ("comparison.md", table), ("sweep.md", sweep)):
        write_text_atomically(out / name, text + "\n")
    artifacts = [str(out / n) for n in ("report.json", "comparison.md", "sweep.md")] + [str(model_path)]
    return {"rows": rows, "source": source, "report": report, "reloads": reloads, "table": table,
            "artifacts": artifacts}


def _status(t, ok):
    if t["source"] is None:
        return "not_run", SYNTHETIC_NOTE
    images = t["report"]["images"]
    if images < MIN_IMAGES:
        return "blocked", f"{t['source']}: {images} images; §4.7 needs at least {MIN_IMAGES} (MLA-03)"
    return ("pass" if ok else "fail"), f"dataset {t['source']}"


def test_mla_04_lightgbm_trains_and_predicts(trained, record_result):
    report = trained["report"]
    model = report["model"]
    metrics_reported = (model["micro_f1"] is not None and model["macro_f1"] is not None
                        and all(m["support"] == 0 or m["recall"] is not None for m in model["per_label"].values()))
    ok = trained["reloads"] and metrics_reported
    status, notes = _status(trained, ok)
    if not ok:
        notes += "; " + ("model does not reload with the same predictions" if not trained["reloads"]
                         else "metrics missing")
    record_result("MLA-04", status,
                  metrics={"images": report["images"],
                           "under_prediction_rate": _round(model["under_prediction_rate"]),
                           "over_prediction_rate": _round(model["over_prediction_rate"]),
                           "micro_f1": _round(model["micro_f1"]), "macro_f1": _round(model["macro_f1"]),
                           "subset_accuracy": _round(model["subset_accuracy"]),
                           "hamming_loss": _round(model["hamming_loss"]),
                           "labels": len(report["labels"]), "too_rare": report["too_rare"],
                           "folds": report["folds"], "repeats": report["repeats"], "theta_c": report["theta_c"],
                           "reloads_identically": trained["reloads"], "synthetic": trained["source"] is None},
                  notes=notes, artifacts=trained["artifacts"])
    assert ok, notes


def test_mla_05_against_the_baselines(trained, record_result):
    report = trained["report"]
    under = {"ml_a": _round(report["model"]["under_prediction_rate"])}
    under |= {b: _round(report["baselines"][b]["under_prediction_rate"]) for b in BASELINES}
    over = {"ml_a": _round(report["model"]["over_prediction_rate"])}
    over |= {b: _round(report["baselines"][b]["over_prediction_rate"]) for b in BASELINES}
    beats = under["ml_a"] < under["allowlist"]
    ok = trained["table"].count("\n") == 1 + 1 + len(BASELINES)             # header, rule, model, baselines
    status, notes = _status(trained, ok)
    notes += (f"; ML-A {'beats' if beats else 'does not beat'} the allowlist on under-prediction "
              f"({under['ml_a']} vs {under['allowlist']})")
    record_result("MLA-05", status,
                  metrics={"images": report["images"], "under_ml_a": under["ml_a"],
                           "under_allowlist": under["allowlist"], "beats_allowlist_on_under_prediction": beats,
                           "under_prediction_rate": under, "over_prediction_rate": over},
                  notes=notes, artifacts=trained["artifacts"][:3])
    assert ok, notes
