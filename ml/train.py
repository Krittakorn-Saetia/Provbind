"""ML-A training and evaluation (Role 2 handoff T13 step 4; Test Plan §§4.2-4.7).

    python -m ml.train --data ml/data/dataset.jsonl --out ml/model --report run/results/MLA-04/report.json

Dataset D1 has one JSON object per line, one per profiled image. T13 step 3 builds it by joining
Role 1's labels to our features by digest:

    {"digest": "sha256:<hex>", "image": "nginx:1.27",
     "features": {...},            # ml/features.py with no vocabulary: the 46 fixed features (null = missing)
     "packages": ["pkg:...", ...], # the envelope's purls: pkg.has.* features and the allowlist baseline
     "labels": ["CAP_...", ...],   # capabilities with a granted check during profiling (MLA-03)
     "allowed": ["CAP_...", ...],  # 𝒞_K8s of the profiled pod
     "exposed_ports": ["80/tcp"]}  # optional: the allowlist baseline's port rule

- **Model:** MultiOutputClassifier(LGBMClassifier(n_estimators=200, num_leaves=15, min_child_samples=2,
  learning_rate=0.05)), trained on the labels with at least 3 positive images. Rarer labels are
  reported as too rare and never predicted (§4.2). A label with one class in the training images
  gets a constant probability, because LightGBM cannot fit it.
- **Evaluation:** 5 folds, repeated 3 times, split by image. Each fold rebuilds the package
  vocabulary and the trainable labels from its own training images, so nothing about its test
  images leaks in. Metrics are computed on each repeat's out-of-fold predictions (every image
  predicted once, by a model that never saw it) and reported as mean and standard deviation over
  the repeats. A test fold of 4-8 images is too small for per-label metrics on its own.
- **Predicted set:** Algorithm 1 (ml/alg1.py) with the image's own 𝒞_K8s and nothing declared, so
  the metrics measure what PROVBIND would put in the envelope.
- **Metrics (§4.5):**
  - the under-prediction rate: capabilities used but not predicted, over capabilities used. Each
    one is a false D_cap alert.
  - the over-prediction rate: capabilities predicted but not used, over capabilities predicted.
    Each one widens the envelope.
  - per-label precision, recall and F1, micro- and macro-F1, subset accuracy and Hamming loss.
  Both rates are swept over θ_C from 0.2 to 0.8. They are 1 minus micro recall and 1 minus micro
  precision. The label space is every capability some profiled pod allowed, so a baseline that
  predicts capabilities nobody used is charged for them. Macro-F1 averages the capabilities used
  by at least one image. A per-label value is null where it is undefined, such as the precision
  of a capability that was never predicted.
- **Baselines (§4.6):** the curated allowlist with its port rule, the empty set, the pod's full
  default set, and the per-label majority. They run on the same folds and are capped at 𝒞_K8s,
  like the model.
- **Model file:** <out>/model.json holds the feature names, the vocabulary, the constant labels
  and one LightGBM text model per label. It is JSON rather than a pickle because the compiler
  loads it (T13 step 6).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import math
import os
import random
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

import numpy as np
from lightgbm import Booster, LGBMClassifier
from sklearn.multioutput import MultiOutputClassifier

from compiler import caps as compiler_caps
from .alg1 import ALL_CAPS, THETA_C, infer, normalise
from .features import FEATURES_VERSION, build_vocabulary, feature_names, package_id

log = logging.getLogger("provbind.ml.train")

LGBM_PARAMS = dict(n_estimators=200, num_leaves=15, min_child_samples=2, learning_rate=0.05,   # §4.4
                   random_state=0, n_jobs=1, verbose=-1)                  # repeatable, and quiet on stdout
MIN_POSITIVES = 3                                                         # §4.2
FOLDS, REPEATS = 5, 3                                                     # §4.4
THETA_SWEEP = tuple(round(0.2 + 0.05 * i, 2) for i in range(13))          # 0.2 .. 0.8
MIN_IMAGES = 20                                                           # §4.7
MODEL_FILE = "model.json"
MODEL_FORMAT = "provbind-mla-model/1"
BASELINES = ("allowlist", "empty", "pod_defaults", "per_label_majority")
METHOD_NAMES = {"model": "ML-A (LightGBM)", "allowlist": "Curated allowlist + port rule", "empty": "Empty set",
                "pod_defaults": "Pod's full default set (𝒞_K8s)", "per_label_majority": "Per-label majority"}
REQUIRED = ("digest", "features", "packages", "labels", "allowed")


# --- dataset ---------------------------------------------------------------------------------------

def load_dataset(path: str | Path) -> list[dict]:
    """The rows of D1, with capability names normalised to CAP_*."""
    fixed = feature_names()
    rows = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            missing = [k for k in REQUIRED if k not in row] or [k for k in fixed if k not in row["features"]]
            if missing:
                raise ValueError(f"{path}:{n}: missing {', '.join(missing[:5])}")
            try:
                row["labels"] = sorted({normalise(c) for c in row["labels"]})
                row["allowed"] = sorted({normalise(c) for c in row["allowed"]})
            except ValueError as e:
                raise ValueError(f"{path}:{n}: {e}") from None
            outside = set(row["labels"]) - set(row["allowed"])
            if outside:
                log.warning("%s:%d: labels outside the pod's allowed set: %s", path, n, ", ".join(sorted(outside)))
            rows.append(row)
    return rows


def row_features(row: Mapping, vocabulary: Sequence[str]) -> dict[str, float | None]:
    """A row's full feature dict: its fixed features plus pkg.has.* for this vocabulary."""
    ids = {package_id(p) for p in row["packages"]}
    return {**row["features"], **{f"pkg.has.{v}": float(v in ids) for v in vocabulary}}


def matrix(rows: Iterable[Mapping[str, float | None]], names: Sequence[str]) -> np.ndarray:
    """Feature dicts as a float matrix with columns in `names` order; None or absent is NaN."""
    return np.array([[math.nan if r.get(n) is None else float(r[n]) for n in names] for r in rows],
                    dtype=float).reshape(-1, len(names))


def trainable_labels(rows: Sequence[Mapping], min_positives: int = MIN_POSITIVES) -> tuple[list[str], list[str]]:
    """(labels with at least min_positives positive images, labels that are too rare)."""
    counts: dict[str, int] = {}
    for row in rows:
        for cap in set(row["labels"]):
            counts[cap] = counts.get(cap, 0) + 1
    return (sorted(c for c, n in counts.items() if n >= min_positives),
            sorted(c for c, n in counts.items() if n < min_positives))


# --- the model -------------------------------------------------------------------------------------

@dataclass
class CapabilityModel:
    """LGBM_cap of Eq. (33), with what inference needs to rebuild z_I."""
    feature_names: list[str]
    vocabulary: list[str]
    boosters: dict[str, Booster] = field(default_factory=dict)     # label -> LightGBM model of p(c)
    constants: dict[str, float] = field(default_factory=dict)      # labels with one class in training
    too_rare: list[str] = field(default_factory=list)              # seen in training, never predicted
    theta: float = THETA_C
    features_version: int = FEATURES_VERSION
    params: dict = field(default_factory=lambda: dict(LGBM_PARAMS))

    @property
    def labels(self) -> list[str]:
        return sorted(set(self.boosters) | set(self.constants))

    def predict_proba_matrix(self, X: np.ndarray) -> list[dict[str, float]]:
        """p(c) for each row of X, whose columns are in feature_names order."""
        out = [dict(self.constants) for _ in range(len(X))]
        if len(X):
            for label, booster in sorted(self.boosters.items()):
                for i, p in enumerate(booster.predict(X)):
                    out[i][label] = float(p)
        return out

    def predict_proba(self, features: Mapping[str, float | None]) -> dict[str, float]:
        """p_I(c) for one image from its full feature dict (Eq. 33): ml.features.extract with this
        model's vocabulary."""
        missing = [n for n in self.feature_names if n not in features]
        if missing:
            raise ValueError(f"features missing for this model: {', '.join(missing[:5])}")
        return self.predict_proba_matrix(matrix([features], self.feature_names))[0]

    def to_json(self) -> dict:
        return {"format": MODEL_FORMAT, "features_version": self.features_version,
                "feature_names": self.feature_names, "vocabulary": self.vocabulary, "theta_c": self.theta,
                "labels": self.labels, "constants": dict(sorted(self.constants.items())),
                "too_rare": self.too_rare, "params": self.params,
                "boosters": {c: b.model_to_string() for c, b in sorted(self.boosters.items())}}

    def save(self, directory: str | Path) -> Path:
        """Write <directory>/model.json atomically; returns its path."""
        doc = {**self.to_json(), "created": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        path = Path(directory) / MODEL_FILE
        write_text_atomically(path, json.dumps(doc, indent=1) + "\n")
        return path

    @classmethod
    def load(cls, directory: str | Path) -> "CapabilityModel":
        path = Path(directory) / MODEL_FILE
        doc = json.loads(path.read_text(encoding="utf-8"))
        if doc.get("format") != MODEL_FORMAT:
            raise ValueError(f"{path}: format {doc.get('format')!r}, expected {MODEL_FORMAT!r}")
        if doc["features_version"] != FEATURES_VERSION:
            raise ValueError(f"{path}: features version {doc['features_version']}, the code has {FEATURES_VERSION}")
        names = list(doc["feature_names"])
        if names != list(feature_names(doc["vocabulary"])):
            raise ValueError(f"{path}: feature names do not match features version {FEATURES_VERSION}")
        bad = [c for c in [*doc["boosters"], *doc["constants"]] if c not in ALL_CAPS]
        if bad:
            raise ValueError(f"{path}: not capability names: {', '.join(bad)}")
        boosters = {c: Booster(model_str=s) for c, s in doc["boosters"].items()}
        wrong = [c for c, b in boosters.items() if b.num_feature() != len(names)]
        if wrong:
            raise ValueError(f"{path}: models for {', '.join(wrong)} expect a different number of features")
        return cls(names, list(doc["vocabulary"]), boosters, {c: float(p) for c, p in doc["constants"].items()},
                   list(doc["too_rare"]), float(doc["theta_c"]), doc["features_version"], dict(doc["params"]))


def fit(rows: Sequence[Mapping], labels: Sequence[str], vocabulary: Sequence[str] | None = None,
        too_rare: Sequence[str] = (), params: Mapping | None = None) -> CapabilityModel:
    """Train on `rows` for `labels`. The vocabulary is built from these rows unless given."""
    params = dict(LGBM_PARAMS if params is None else params)
    if vocabulary is None:
        vocabulary = build_vocabulary([{"packages": dict.fromkeys(r["packages"])} for r in rows])
    vocabulary = list(vocabulary)
    names = list(feature_names(vocabulary))
    X = matrix([row_features(r, vocabulary) for r in rows], names)
    Y = np.array([[int(c in r["labels"]) for c in labels] for r in rows], dtype=int).reshape(len(rows), len(labels))
    positives = Y.sum(axis=0)
    varying = [j for j, n in enumerate(positives) if 0 < n < len(rows)]
    constants = {labels[j]: float(positives[j] > 0) for j in range(len(labels)) if j not in varying}
    boosters = {}
    if varying:
        estimator = MultiOutputClassifier(LGBMClassifier(**params)).fit(X, Y[:, varying])
        boosters = {labels[j]: e.booster_ for j, e in zip(varying, estimator.estimators_)}
    return CapabilityModel(names, vocabulary, boosters, constants, sorted(too_rare), params=params)


# --- cross-validation ------------------------------------------------------------------------------

def group_folds(groups: Sequence[str], folds: int = FOLDS, repeats: int = REPEATS, seed: int = 0):
    """(repeat, fold, train indices, test indices). In each repeat every image (group) is in exactly
    one test fold, and never in train and test at once; fold sizes differ by at most one image."""
    unique = sorted(set(groups))
    if folds < 2 or len(unique) < folds:
        raise ValueError(f"{len(unique)} images cannot be split into {folds} folds")
    for r in range(repeats):
        order = unique[:]
        random.Random(seed + r).shuffle(order)
        fold_of = {g: i % folds for i, g in enumerate(order)}
        for k in range(folds):
            yield (r, k, [i for i, g in enumerate(groups) if fold_of[g] != k],
                   [i for i, g in enumerate(groups) if fold_of[g] == k])


def predicted_sets(probabilities: Sequence[Mapping[str, float]], rows: Sequence[Mapping],
                   theta: float) -> list[set[str]]:
    """Algorithm 1 per image: threshold θ_C, capped at the image's own 𝒞_K8s, nothing declared."""
    return [{c.cap for c in infer(p, r["allowed"], theta=theta)} for p, r in zip(probabilities, rows)]


def set_metrics(true: Sequence[set[str]], pred: Sequence[set[str]], space: Sequence[str]) -> dict:
    """§4.5 metrics for predicted capability sets. The per-label metrics, macro-F1 and Hamming loss
    are over the label space `space`; the rates and micro-F1 count every capability."""
    tp = sum(len(t & p) for t, p in zip(true, pred))
    fn = sum(len(t - p) for t, p in zip(true, pred))
    fp = sum(len(p - t) for t, p in zip(true, pred))
    per_label, errors = {}, 0
    for c in space:
        ctp = sum(c in t and c in p for t, p in zip(true, pred))
        cfn = sum(c in t and c not in p for t, p in zip(true, pred))
        cfp = sum(c in p and c not in t for t, p in zip(true, pred))
        per_label[c] = {"precision": ctp / (ctp + cfp) if ctp + cfp else None,
                        "recall": ctp / (ctp + cfn) if ctp + cfn else None,
                        "f1": 2 * ctp / (2 * ctp + cfp + cfn) if ctp + cfp + cfn else None,
                        "support": ctp + cfn, "predicted": ctp + cfp}
        errors += cfn + cfp
    used = [m["f1"] for m in per_label.values() if m["support"]]
    return {"under_prediction_rate": fn / (tp + fn) if tp + fn else 0.0,
            "over_prediction_rate": fp / (tp + fp) if tp + fp else 0.0,
            "micro_f1": 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else 1.0,
            "macro_f1": sum(used) / len(used) if used else None,
            "subset_accuracy": sum(t == p for t, p in zip(true, pred)) / len(true) if true else None,
            "hamming_loss": errors / (len(true) * len(space)) if true and space else None,
            "per_label": per_label}


def baselines(train: Sequence[Mapping], test: Sequence[Mapping],
              allowlist: Mapping[tuple, list[str]] | None = None) -> dict[str, list[set[str]]]:
    """The four §4.6 baselines' predicted sets for the test images, each capped at 𝒞_K8s."""
    allow = compiler_caps.load_allowlist() if allowlist is None else allowlist
    seen = {c for r in train for c in r["labels"]}
    majority = {c for c in seen if 2 * sum(c in r["labels"] for r in train) > len(train)}
    return {
        "allowlist": [{e["cap"] for e in compiler_caps.capabilities(r["packages"], r.get("exposed_ports"), allow)}
                      & set(r["allowed"]) for r in test],
        "empty": [set() for _ in test],
        "pod_defaults": [set(r["allowed"]) for r in test],
        "per_label_majority": [majority & set(r["allowed"]) for r in test],
    }


def _mean(values: Iterable[float | None]) -> float | None:
    xs = [v for v in values if v is not None]
    return float(np.mean(xs)) if xs else None


def _mean_std(values: Iterable[float | None]) -> dict | None:
    xs = [v for v in values if v is not None]
    return {"mean": float(np.mean(xs)), "std": float(np.std(xs))} if xs else None


def _summary(scores: Sequence[dict]) -> dict:
    """Mean and standard deviation over the repeats."""
    out = {k: _mean_std(s[k] for s in scores) for k in scores[0] if k != "per_label"}
    out["per_label"] = {c: {**{m: _mean(s["per_label"][c][m] for s in scores)
                               for m in ("precision", "recall", "f1", "predicted")},
                            "support": scores[0]["per_label"][c]["support"]}
                        for c in scores[0]["per_label"]}
    return out


def evaluate(rows: Sequence[Mapping], folds: int = FOLDS, repeats: int = REPEATS, seed: int = 0,
             fit_fn: Callable[..., CapabilityModel] = fit, params: Mapping | None = None) -> dict:
    """Repeated k-fold cross-validation by image: the model at θ_C, the θ_C sweep, the baselines."""
    groups = [r["digest"] for r in rows]
    true = [set(r["labels"]) for r in rows]
    space = sorted(set().union(*true, *(r["allowed"] for r in rows)))
    allow = compiler_caps.load_allowlist()
    out_of_fold: dict[int, dict[str, list]] = {}
    for rep, _, tr, te in group_folds(groups, folds, repeats, seed):
        oof = out_of_fold.setdefault(rep, {m: [None] * len(rows) for m in ("proba",) + BASELINES})
        train, test = [rows[i] for i in tr], [rows[i] for i in te]
        fold_labels, fold_rare = trainable_labels(train)
        model = fit_fn(train, fold_labels, too_rare=fold_rare, params=params)
        proba = model.predict_proba_matrix(matrix([row_features(r, model.vocabulary) for r in test],
                                                  model.feature_names))
        for name, values in [("proba", proba), *baselines(train, test, allow).items()]:
            for i, v in zip(te, values):
                oof[name][i] = v
    scores = {m: [] for m in ("model",) + BASELINES}
    sweep: dict[float, list[dict]] = {t: [] for t in THETA_SWEEP}
    for rep in sorted(out_of_fold):
        oof = out_of_fold[rep]
        scores["model"].append(set_metrics(true, predicted_sets(oof["proba"], rows, THETA_C), space))
        for name in BASELINES:
            scores[name].append(set_metrics(true, oof[name], space))
        for t in THETA_SWEEP:
            sweep[t].append(set_metrics(true, predicted_sets(oof["proba"], rows, t), space))
    labels, too_rare = trainable_labels(rows)
    return {"images": len(set(groups)), "rows": len(rows), "folds": folds, "repeats": repeats, "seed": seed,
            "theta_c": THETA_C, "params": dict(LGBM_PARAMS if params is None else params),
            "features_version": FEATURES_VERSION, "labels": labels, "too_rare": too_rare, "label_space": space,
            "positives": {c: sum(c in t for t in true) for c in space},
            "model": _summary(scores["model"]),
            "baselines": {name: _summary(scores[name]) for name in BASELINES},
            "theta_sweep": [{"theta_c": t, **{k: _mean_std(s[k] for s in sweep[t])
                                              for k in ("under_prediction_rate", "over_prediction_rate", "micro_f1")}}
                            for t in THETA_SWEEP]}


# --- reporting -------------------------------------------------------------------------------------

def _cell(m: dict | None) -> str:
    return "n/a" if m is None else f"{m['mean']:.3f} ± {m['std']:.3f}"


def comparison_table(report: Mapping) -> str:
    """MLA-05: the model against the four baselines (mean ± std over the repeats)."""
    keys = ("under_prediction_rate", "over_prediction_rate", "micro_f1", "macro_f1", "subset_accuracy", "hamming_loss")
    lines = ["| Method | Under-prediction | Over-prediction | Micro-F1 | Macro-F1 | Subset accuracy | Hamming loss |",
             "|---|---|---|---|---|---|---|"]
    for name, m in [("model", report["model"]), *report["baselines"].items()]:
        lines.append(f"| {METHOD_NAMES.get(name, name)} | " + " | ".join(_cell(m[k]) for k in keys) + " |")
    return "\n".join(lines)


def sweep_table(report: Mapping) -> str:
    """The under- and over-prediction rates against θ_C (§4.5)."""
    lines = ["| θ_C | Under-prediction | Over-prediction | Micro-F1 |", "|---|---|---|---|"]
    lines += [f"| {s['theta_c']:.2f} | {_cell(s['under_prediction_rate'])} | {_cell(s['over_prediction_rate'])} | "
              f"{_cell(s['micro_f1'])} |" for s in report["theta_sweep"]]
    return "\n".join(lines)


def write_text_atomically(path: str | Path, text: str) -> None:
    """Write through a temp file and a rename, so a reader never sees half a file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        with open(tmp, "x", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ml.train", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default="ml/data/dataset.jsonl", help="dataset D1 (JSON lines)")
    ap.add_argument("--out", help="directory for the model trained on every image, such as ml/model")
    ap.add_argument("--report", help="write the cross-validation report here as JSON")
    ap.add_argument("--folds", type=int, default=FOLDS)
    ap.add_argument("--repeats", type=int, default=REPEATS)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="[ml.train] %(message)s", stream=sys.stderr)

    try:
        rows = load_dataset(args.data)
        images = len({r["digest"] for r in rows})
        if images < MIN_IMAGES:
            log.warning("%d images; the test plan asks for at least %d (§4.7)", images, MIN_IMAGES)
        report = evaluate(rows, args.folds, args.repeats, args.seed)
    except (OSError, ValueError) as e:
        log.error("%s", e)
        return 3
    print(comparison_table(report) + "\n\n" + sweep_table(report), file=sys.stderr)
    if args.report:
        write_text_atomically(args.report, json.dumps(report, indent=2) + "\n")
        log.info("report: %s", args.report)
    if args.out:
        labels, too_rare = trainable_labels(rows)
        print(fit(rows, labels, too_rare=too_rare).save(args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
