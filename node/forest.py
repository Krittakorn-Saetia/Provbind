"""An Isolation Forest as JSON: export a fitted scikit-learn forest, and score it without scikit-learn.

ML-B's per-image model is stored in the run folder beside the envelope (Eq. 49). A pickle there
would run code when loaded, and a security tool should not unpickle a file from a shared folder;
JSON can only be data. It also keeps scikit-learn off the node. Training still uses it.

The scorer reproduces IsolationForest.score_samples; the tests compare the two.
- For each tree, walk from the root: go left when x[f] <= threshold. Features are compared as
  float32, as scikit-learn's trees compare them.
- Add the leaf's path length: its depth plus c(n), the expected depth left for the n training
  samples in that leaf.
- score = -2 ** (-(sum over trees) / (trees * c(max_samples))), in (-1, 0). The anomaly score is
  its negation, in (0, 1]: higher is more anomalous.
"""
from __future__ import annotations

import math
import struct
from typing import Mapping, Sequence

FORMAT = "provbind.iforest/v1"
EULER_GAMMA = 0.5772156649015329
_F32_MAX = 3.4028234663852886e38


def c(n: float) -> float:
    """Average path length of an unsuccessful search in a binary search tree of n items."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1.0) + EULER_GAMMA) - 2.0 * (n - 1.0) / n


def f32(v: float) -> float:
    """v rounded to float32, as scikit-learn converts inputs before walking a tree."""
    try:
        return struct.unpack("<f", struct.pack("<f", v))[0]
    except OverflowError:
        return math.copysign(math.inf, v)


def export(model, feature_names: Sequence[str]) -> dict:
    """A fitted sklearn.ensemble.IsolationForest as a JSON-ready dict."""
    names = list(feature_names)
    if len(names) != model.n_features_in_:
        raise ValueError(f"{len(names)} feature names for a model with {model.n_features_in_} features")
    subsample = getattr(model, "_max_features", model.n_features_in_) != model.n_features_in_
    dpl = getattr(model, "_decision_path_lengths", None)        # sklearn's own, for identical scores
    apl = getattr(model, "_average_path_length_per_tree", None)
    trees = []
    for i, est in enumerate(model.estimators_):
        t = est.tree_
        left, right = t.children_left.tolist(), t.children_right.tolist()
        cols = model.estimators_features_[i]
        feature = [int(cols[f]) if subsample and f >= 0 else int(f) for f in t.feature.tolist()]
        if dpl is not None and apl is not None:
            leaf = [float(dpl[i][n] + apl[i][n] - 1.0) if left[n] == -1 else 0.0 for n in range(len(left))]
        else:
            depth = [0] * len(left)
            for n in range(len(left)):                         # children always follow their parent
                if left[n] != -1:
                    depth[left[n]] = depth[right[n]] = depth[n] + 1
            samples = t.n_node_samples.tolist()
            leaf = [depth[n] + c(samples[n]) if left[n] == -1 else 0.0 for n in range(len(left))]
        trees.append({"left": left, "right": right, "feature": feature, "threshold": t.threshold.tolist(),
                      "leaf": leaf})
    max_samples = int(getattr(model, "_max_samples", model.max_samples_))
    return {"format": FORMAT, "features": names, "max_samples": max_samples,
            "denominator": len(trees) * c(max_samples), "trees": trees}


class Forest:
    """A forest exported by `export`, scored in pure Python."""

    def __init__(self, doc: Mapping):
        if not isinstance(doc, Mapping) or doc.get("format") != FORMAT:
            raise ValueError(f"not a {FORMAT} document")
        self.features = list(doc["features"])
        self.max_samples = int(doc["max_samples"])
        self.denominator = float(doc["denominator"])
        self.trees = []
        for t in doc["trees"]:
            arrays = tuple(t[k] for k in ("left", "right", "feature", "threshold", "leaf"))
            if len({len(a) for a in arrays}) != 1 or not arrays[0]:
                raise ValueError("a tree's arrays differ in length")
            n = len(arrays[0])
            for n_left, n_right, f in zip(arrays[0], arrays[1], arrays[2]):
                if n_left != -1 and not (0 < n_left < n and 0 < n_right < n and 0 <= f < len(self.features)):
                    raise ValueError("a tree points outside itself or at an unknown feature")
            self.trees.append(arrays)
        if not self.trees:
            raise ValueError("a forest without trees")

    def path_length_sum(self, x: Sequence[float]) -> float:
        xs = [f32(float(v)) for v in x]
        total = 0.0
        for left, right, feature, threshold, leaf in self.trees:
            node = 0
            while left[node] != -1:
                node = left[node] if xs[feature[node]] <= threshold[node] else right[node]
            total += leaf[node]
        return total

    def score_samples(self, x: Sequence[float]) -> float:
        """What IsolationForest.score_samples gives for one sample: negative, lower is more anomalous."""
        if len(x) != len(self.features):
            raise ValueError(f"expected {len(self.features)} features, got {len(x)}")
        if self.denominator == 0:
            return -1.0                                          # sklearn's rule for a one-sample forest
        return -(2.0 ** (-self.path_length_sum(x) / self.denominator))

    def anomaly(self, x: Sequence[float]) -> float:
        """The draft's anomaly score s(x, n) in (0, 1]; higher is more anomalous."""
        return -self.score_samples(x)
