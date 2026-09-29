"""node/forest.py: an exported Isolation Forest scores exactly as scikit-learn does."""
import json

import pytest

np = pytest.importorskip("numpy")
ensemble = pytest.importorskip("sklearn.ensemble")

from node.forest import FORMAT, Forest, c, export, f32  # noqa: E402


def fit(X, **kw):
    params = dict(n_estimators=50, max_samples=min(256, len(X)), contamination="auto", random_state=0)
    params.update(kw)
    return ensemble.IsolationForest(**params).fit(X)


def roundtrip(model, n):
    return Forest(json.loads(json.dumps(export(model, [f"f{i}" for i in range(n)]))))


@pytest.mark.parametrize("seed,n,d,kw", [
    (0, 300, 5, {}), (1, 40, 3, {}), (2, 1000, 20, {}), (3, 500, 4, {"max_samples": 64}),
    (4, 300, 6, {"max_features": 0.5}), (5, 200, 2, {"n_estimators": 100}),
])
def test_scores_match_scikit_learn(seed, n, d, kw):
    rng = np.random.RandomState(seed)
    X = rng.gamma(2.0, 3.0, size=(n, d))
    X[: n // 4] = X[0]                                        # many identical windows, as idle ones are
    model = fit(X, **kw)
    forest = roundtrip(model, d)
    tests = np.vstack([X[:50], rng.gamma(2.0, 3.0, size=(100, d)) * rng.choice([0.1, 1, 10], size=(100, 1)),
                       np.zeros((1, d)), np.full((1, d), 1e6), np.full((1, d), -5.0)])
    ours = np.array([forest.score_samples(row) for row in tests])
    assert np.allclose(ours, model.score_samples(tests), rtol=0, atol=1e-12)


def test_anomaly_is_the_negated_score():
    X = np.random.RandomState(9).rand(100, 3)
    forest = roundtrip(fit(X), 3)
    x = [0.5, 0.5, 0.5]
    assert forest.anomaly(x) == -forest.score_samples(x) and 0 < forest.anomaly(x) <= 1


def test_average_path_length():
    from sklearn.ensemble._iforest import _average_path_length
    for n in (0, 1, 2, 3, 10, 256, 1000):
        assert c(n) == pytest.approx(float(_average_path_length([n])[0]), abs=1e-12)


def test_float32_rounding():
    assert f32(0.1) != 0.1 and abs(f32(0.1) - 0.1) < 1e-8
    assert f32(1e40) == float("inf") and f32(-1e40) == float("-inf")


def test_export_needs_one_name_per_feature():
    model = fit(np.random.RandomState(0).rand(50, 3))
    with pytest.raises(ValueError):
        export(model, ["a", "b"])


def test_wrong_length_input_is_refused():
    forest = roundtrip(fit(np.random.RandomState(0).rand(50, 3)), 3)
    with pytest.raises(ValueError):
        forest.score_samples([1.0, 2.0])


@pytest.mark.parametrize("change", [
    lambda d: d.update(format="pickle"), lambda d: d.update(trees=[]), lambda d: d["trees"][0]["leaf"].pop(),
    lambda d: d["trees"][0]["left"].__setitem__(0, 10 ** 6), lambda d: d["trees"][0]["feature"].__setitem__(0, 99),
    lambda d: d.pop("denominator"),
])
def test_broken_documents_are_refused(change):
    doc = export(fit(np.random.RandomState(0).rand(60, 3)), ["a", "b", "c"])
    change(doc)
    with pytest.raises((ValueError, KeyError)):
        Forest(doc)


def test_document_is_plain_json():
    doc = export(fit(np.random.RandomState(0).rand(60, 3)), ["a", "b", "c"])
    assert doc["format"] == FORMAT and json.loads(json.dumps(doc)) == doc
