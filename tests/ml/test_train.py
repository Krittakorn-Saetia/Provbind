"""Unit tests for ml/train.py (T13 step 4) on synthetic data. The real run is MLA-04 and MLA-05."""
import copy
import json
import logging
import random

import numpy as np
import pytest
from sklearn.metrics import accuracy_score, f1_score, hamming_loss, precision_score, recall_score

from ml.alg1 import ALL_CAPS
from ml.features import build_vocabulary, extract, feature_names, package_id
from ml.train import (BASELINES, LGBM_PARAMS, MODEL_FILE, THETA_SWEEP, CapabilityModel, baselines,
                      comparison_table, evaluate, fit, group_folds, load_dataset, main, matrix, predicted_sets,
                      row_features, set_metrics, sweep_table, trainable_labels)

from . import synthetic

FAST = {**LGBM_PARAMS, "n_estimators": 20}
ROWS = synthetic.rows()


def fast_fit(rows, labels, **kwargs):
    return fit(rows, labels, **{**kwargs, "params": FAST})


def write_jsonl(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


# --- dataset -----------------------------------------------------------------------------------------

def test_synthetic_rows_are_in_the_dataset_format(tmp_path):
    assert len(ROWS) == 40 == len({r["digest"] for r in ROWS})
    for r in ROWS:
        assert set(r["features"]) == set(feature_names())
        assert set(r["labels"]) <= set(r["allowed"]) <= set(ALL_CAPS)
    assert load_dataset(write_jsonl(tmp_path / "d.jsonl", ROWS)) == ROWS


def test_load_dataset_normalises_names_and_skips_blank_lines(tmp_path, caplog):
    row = copy.deepcopy(ROWS[0]) | {"labels": ["net_bind_service", "CAP_SETUID"], "allowed": ["NET_BIND_SERVICE"]}
    path = tmp_path / "d.jsonl"
    path.write_text("\n" + json.dumps(row) + "\n\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="provbind.ml.train"):
        [got] = load_dataset(path)
    assert (got["labels"], got["allowed"]) == (["CAP_NET_BIND_SERVICE", "CAP_SETUID"], ["CAP_NET_BIND_SERVICE"])
    assert "outside the pod's allowed set: CAP_SETUID" in caplog.text


@pytest.mark.parametrize("change,message", [
    (lambda r: r.pop("allowed"), "missing allowed"),
    (lambda r: r["features"].pop("imp.bind"), "missing imp.bind"),
    (lambda r: r.update(labels=["CAP_BOGUS"]), "CAP_BOGUS"),
])
def test_load_dataset_rejects_bad_rows_with_their_line(tmp_path, change, message):
    bad = copy.deepcopy(ROWS[1])
    change(bad)
    with pytest.raises(ValueError, match=rf"d\.jsonl:2: .*{message}"):
        load_dataset(write_jsonl(tmp_path / "d.jsonl", [ROWS[0], bad]))


def test_row_features_match_the_extractor_with_the_same_vocabulary():
    envelope = {"packages": dict.fromkeys(["pkg:pypi/Flask@3.0.3", "pkg:deb/debian/libc6@2.36?arch=amd64"], {}),
                "closure": ["/usr/local/bin/python3.11"]}
    config = {"User": "app", "ExposedPorts": {"8080/tcp": {}}, "Env": []}
    vocabulary = ["deb/libc6", "npm/express", "pypi/flask"]
    names = feature_names(vocabulary)
    row = {"features": extract(envelope, config).to_json(), "packages": list(envelope["packages"])}
    assert np.array_equal(matrix([row_features(row, vocabulary)], names),
                          matrix([extract(envelope, config, vocabulary=vocabulary).to_json()], names), equal_nan=True)


def test_matrix_orders_columns_and_turns_none_or_absent_into_nan():
    X = matrix([{"b": 2.0, "a": None}, {"a": 1.0}], ["a", "b"])
    assert X.shape == (2, 2) and X[1, 0] == 1.0 and X[0, 1] == 2.0
    assert np.isnan(X[0, 0]) and np.isnan(X[1, 1])
    assert matrix([], ["a", "b"]).shape == (0, 2)


def test_trainable_labels_need_three_positive_images():
    rows = [{"labels": ["CAP_CHOWN", "CAP_CHOWN", "CAP_KILL"]}, {"labels": ["CAP_CHOWN", "CAP_KILL"]},
            {"labels": ["CAP_CHOWN"]}]
    assert trainable_labels(rows) == (["CAP_CHOWN"], ["CAP_KILL"])


# --- folds by image ------------------------------------------------------------------------------------

def test_each_image_is_tested_once_per_repeat_and_never_trained_on_then():
    groups = [f"img{i % 23}" for i in range(46)]                 # two rows per image
    seen = {}
    for rep, _, train, test in group_folds(groups, folds=5, repeats=3, seed=0):
        assert not {groups[i] for i in train} & {groups[i] for i in test}
        assert sorted(train + test) == list(range(46))
        for g in {groups[i] for i in test}:
            seen[rep, g] = seen.get((rep, g), 0) + 1
    assert seen == {(r, f"img{i}"): 1 for r in range(3) for i in range(23)}


def test_folds_are_balanced_repeatable_and_differ_between_repeats():
    groups = [f"img{i}" for i in range(23)]
    folds = list(group_folds(groups, 5, 2, seed=4))
    assert {len(test) for rep, _, _, test in folds} == {4, 5}
    assert folds == list(group_folds(groups, 5, 2, seed=4))
    assert [t for r, _, _, t in folds if r == 0] != [t for r, _, _, t in folds if r == 1]


@pytest.mark.parametrize("n,folds", [(4, 5), (10, 1)])
def test_too_few_images_for_the_folds(n, folds):
    with pytest.raises(ValueError, match="cannot be split"):
        list(group_folds([f"img{i}" for i in range(n)], folds))


# --- fitting ---------------------------------------------------------------------------------------------

def test_fit_learns_from_the_features():
    labels, _ = trainable_labels(ROWS)
    model = fast_fit(ROWS, labels)
    proba = model.predict_proba_matrix(matrix([row_features(r, model.vocabulary) for r in ROWS], model.feature_names))
    for p, r in zip(proba, ROWS):
        assert set(p) == set(labels)
        if r["image"].startswith("synthetic/webserver") and "CAP_NET_BIND_SERVICE" in r["labels"]:
            assert p["CAP_NET_BIND_SERVICE"] > 0.5
        if r["image"].startswith("synthetic/python_app:"):
            assert p["CAP_SETUID"] < 0.5


def test_fit_builds_the_vocabulary_from_its_own_rows():
    model = fast_fit(ROWS[:10], ["CAP_NET_BIND_SERVICE"])
    assert model.vocabulary == build_vocabulary([{"packages": dict.fromkeys(r["packages"])} for r in ROWS[:10]])
    assert list(model.feature_names) == list(feature_names(model.vocabulary))


def test_a_label_with_one_class_gets_a_constant():
    rows = copy.deepcopy(ROWS[:12])
    for r in rows:
        r["labels"] = sorted(set(r["labels"]) | {"CAP_CHOWN"})
    model = fast_fit(rows, ["CAP_CHOWN", "CAP_KILL", "CAP_SETUID"], too_rare=["CAP_SYS_ADMIN"])
    assert model.constants == {"CAP_CHOWN": 1.0, "CAP_KILL": 0.0}
    assert set(model.boosters) == {"CAP_SETUID"} and model.labels == ["CAP_CHOWN", "CAP_KILL", "CAP_SETUID"]
    assert model.too_rare == ["CAP_SYS_ADMIN"]
    p = model.predict_proba(row_features(rows[0], model.vocabulary))
    assert (p["CAP_CHOWN"], p["CAP_KILL"]) == (1.0, 0.0) and "CAP_SYS_ADMIN" not in p


def test_predict_proba_needs_every_feature_of_the_model():
    model = fast_fit(ROWS, ["CAP_NET_BIND_SERVICE"])
    features = row_features(ROWS[0], model.vocabulary)
    shuffled = dict(sorted(features.items(), reverse=True))
    assert model.predict_proba(features) == model.predict_proba(shuffled)
    features.pop("cfg.port_below_1024")
    with pytest.raises(ValueError, match="cfg.port_below_1024"):
        model.predict_proba(features)


# --- the model file ---------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def saved(tmp_path_factory):
    labels, too_rare = trainable_labels(ROWS)
    model = fast_fit(ROWS, labels + ["CAP_MKNOD"], too_rare=too_rare)       # no image uses CAP_MKNOD: a constant
    assert model.constants == {"CAP_MKNOD": 0.0}
    directory = tmp_path_factory.mktemp("model")
    return model, directory, model.save(directory)


def test_save_and_load_give_the_same_probabilities(saved):
    model, directory, path = saved
    assert path == directory / MODEL_FILE and sorted(p.name for p in directory.iterdir()) == [MODEL_FILE]
    loaded = CapabilityModel.load(directory)
    assert (loaded.feature_names, loaded.vocabulary, loaded.labels, loaded.constants, loaded.too_rare, loaded.theta,
            loaded.params) == (model.feature_names, model.vocabulary, model.labels, model.constants, model.too_rare,
                               model.theta, FAST)
    X = matrix([row_features(r, model.vocabulary) for r in ROWS], model.feature_names)
    X[::3, 20] = np.nan
    assert loaded.predict_proba_matrix(X) == model.predict_proba_matrix(X)


def test_the_model_file_is_json_not_a_pickle(saved):
    doc = json.loads(saved[2].read_text(encoding="utf-8"))
    assert doc["format"] == "provbind-mla-model/1" and doc["labels"] == saved[0].labels
    assert all(s.startswith("tree\n") for s in doc["boosters"].values())


@pytest.mark.parametrize("change,message", [
    (lambda d, other: d.update(format="pickle"), "format"),
    (lambda d, other: d.update(features_version=0), "features version 0"),
    (lambda d, other: d.update(vocabulary=d["vocabulary"][1:]), "feature names do not match"),
    (lambda d, other: d["constants"].update(CAP_BOGUS=1.0), "not capability names: CAP_BOGUS"),
    (lambda d, other: d["boosters"].update(CAP_SETUID=other), "CAP_SETUID expect a different number of features"),
])
def test_load_rejects_a_model_that_does_not_fit_the_code(saved, tmp_path, change, message):
    doc = json.loads(saved[2].read_text(encoding="utf-8"))
    other = fast_fit(ROWS, ["CAP_SETUID"], vocabulary=["pypi/flask"]).boosters["CAP_SETUID"].model_to_string()
    change(doc, other)
    (tmp_path / MODEL_FILE).write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        CapabilityModel.load(tmp_path)


# --- metrics and baselines ---------------------------------------------------------------------------------

def test_set_metrics_by_hand():
    true = [{"CAP_CHOWN", "CAP_SETUID"}, {"CAP_NET_RAW"}, set()]
    pred = [{"CAP_CHOWN"}, {"CAP_NET_RAW", "CAP_KILL"}, set()]
    m = set_metrics(true, pred, ["CAP_CHOWN", "CAP_KILL", "CAP_NET_RAW", "CAP_SETUID"])
    assert m["under_prediction_rate"] == pytest.approx(1 / 3)          # CAP_SETUID missed
    assert m["over_prediction_rate"] == pytest.approx(1 / 3)           # CAP_KILL extra
    assert m["micro_f1"] == pytest.approx(2 / 3) and m["macro_f1"] == pytest.approx(2 / 3)
    assert m["subset_accuracy"] == pytest.approx(1 / 3) and m["hamming_loss"] == pytest.approx(2 / 12)
    assert m["per_label"]["CAP_KILL"] == {"precision": 0.0, "recall": None, "f1": 0.0, "support": 0, "predicted": 1}
    assert m["per_label"]["CAP_SETUID"] == {"precision": None, "recall": 0.0, "f1": 0.0, "support": 1, "predicted": 0}


def test_set_metrics_agree_with_scikit_learn():
    rng = random.Random(1)
    space = sorted(rng.sample(ALL_CAPS, 8))
    true = [set(rng.sample(space, rng.randint(0, 4))) for _ in range(60)]
    pred = [set(rng.sample(space, rng.randint(0, 4))) for _ in range(60)]
    m = set_metrics(true, pred, space)
    Yt, Yp = (np.array([[int(c in s) for c in space] for s in sets]) for sets in (true, pred))
    used = [j for j, c in enumerate(space) if m["per_label"][c]["support"]]
    assert m["micro_f1"] == pytest.approx(f1_score(Yt, Yp, average="micro"))
    assert m["macro_f1"] == pytest.approx(f1_score(Yt, Yp, average="macro", labels=used, zero_division=0))
    assert m["hamming_loss"] == pytest.approx(hamming_loss(Yt, Yp))
    assert m["subset_accuracy"] == pytest.approx(accuracy_score(Yt, Yp))
    assert m["under_prediction_rate"] == pytest.approx(1 - recall_score(Yt, Yp, average="micro"))
    assert m["over_prediction_rate"] == pytest.approx(1 - precision_score(Yt, Yp, average="micro"))
    for j, c in enumerate(space):
        assert m["per_label"][c]["f1"] == pytest.approx(f1_score(Yt[:, j], Yp[:, j], zero_division=0))


def test_nothing_used_and_nothing_predicted():
    m = set_metrics([set(), set()], [set(), set()], ["CAP_CHOWN"])
    assert (m["under_prediction_rate"], m["over_prediction_rate"], m["micro_f1"], m["macro_f1"],
            m["subset_accuracy"], m["hamming_loss"]) == (0.0, 0.0, 1.0, None, 1.0, 0.0)


def test_baselines():
    base = {"features": {}, "exposed_ports": []}
    train = [base | {"packages": [], "labels": labels, "allowed": ["CAP_CHOWN", "CAP_NET_RAW", "CAP_SETUID"]}
             for labels in (["CAP_SETUID", "CAP_CHOWN"], ["CAP_SETUID"], ["CAP_SETUID", "CAP_CHOWN"], [])]
    test = [base | {"packages": ["pkg:deb/debian/iputils-ping@20221126"], "labels": [],
                    "allowed": ["CAP_CHOWN", "CAP_NET_RAW", "CAP_SETUID"]},
            base | {"packages": ["pkg:pypi/requests@2.32.3"], "labels": [], "exposed_ports": ["80/tcp"],
                    "allowed": ["CAP_NET_BIND_SERVICE"]},
            base | {"packages": ["pkg:deb/debian/iputils-ping@20221126"], "labels": [],
                    "allowed": ["CAP_NET_BIND_SERVICE"]}]
    got = baselines(train, test)
    assert list(got) == list(BASELINES)
    assert got["allowlist"] == [{"CAP_NET_RAW"}, {"CAP_NET_BIND_SERVICE"}, set()]      # capped at 𝒞_K8s
    assert got["empty"] == [set(), set(), set()]
    assert got["pod_defaults"] == [{"CAP_CHOWN", "CAP_NET_RAW", "CAP_SETUID"}, {"CAP_NET_BIND_SERVICE"},
                                   {"CAP_NET_BIND_SERVICE"}]
    assert got["per_label_majority"] == [{"CAP_SETUID"}, set(), set()]   # CAP_CHOWN is in 2 of 4, not a majority


def test_predicted_sets_apply_theta_and_the_pods_allowed_set():
    rows = [{"allowed": ["CAP_NET_BIND_SERVICE"]}, {"allowed": ["CAP_NET_BIND_SERVICE", "CAP_SETUID"]}]
    proba = [{"CAP_NET_BIND_SERVICE": 0.9, "CAP_SETUID": 0.9}, {"CAP_NET_BIND_SERVICE": 0.4, "CAP_SETUID": 0.6}]
    assert predicted_sets(proba, rows, 0.5) == [{"CAP_NET_BIND_SERVICE"}, {"CAP_SETUID"}]
    assert predicted_sets(proba, rows, 0.3) == [{"CAP_NET_BIND_SERVICE"}, {"CAP_NET_BIND_SERVICE", "CAP_SETUID"}]


# --- cross-validation --------------------------------------------------------------------------------------

def test_each_fold_learns_only_from_its_training_images():
    rows = copy.deepcopy(ROWS)
    rows[7]["packages"].append("pkg:pypi/only-in-one-image@1.0")
    calls = []

    def spy(train, labels, **kwargs):
        model = fast_fit(train, labels, **kwargs)
        calls.append((train, labels, kwargs["too_rare"], model))
        return model

    evaluate(rows, folds=5, repeats=2, fit_fn=spy)
    assert len(calls) == 10
    for n, (train, labels, too_rare, model) in enumerate(calls):
        ids = {package_id(p) for r in train for p in r["packages"]}
        assert set(model.vocabulary) <= ids
        assert (labels, too_rare) == trainable_labels(train)
        assert len(train) == 32
        assert ("pypi/only-in-one-image" in model.vocabulary) == (rows[7] in train)
    everyone = {r["digest"] for r in rows}
    for rep in (0, 1):                                  # held out exactly once per repeat
        held_out = [everyone - {r["digest"] for r in train} for train, _, _, _ in calls[5 * rep:5 * rep + 5]]
        assert sorted(d for h in held_out for d in h) == sorted(everyone)


@pytest.fixture(scope="module")
def report():
    return evaluate(ROWS, folds=5, repeats=2, fit_fn=fast_fit)


def test_report_shape(report):
    assert (report["images"], report["rows"], report["folds"], report["repeats"]) == (40, 40, 5, 2)
    assert list(report["baselines"]) == list(BASELINES)
    assert [s["theta_c"] for s in report["theta_sweep"]] == list(THETA_SWEEP)
    assert THETA_SWEEP[0] == 0.2 and THETA_SWEEP[-1] == 0.8 and 0.5 in THETA_SWEEP
    assert set(report["label_space"]) >= {c for r in ROWS for c in r["allowed"]}
    for c, m in report["model"]["per_label"].items():
        assert m["support"] == report["positives"][c]
    json.dumps(report, allow_nan=False)


def test_the_sweep_trades_under_for_over_prediction(report):
    under = [s["under_prediction_rate"]["mean"] for s in report["theta_sweep"]]
    over = [s["over_prediction_rate"]["mean"] for s in report["theta_sweep"]]
    assert under == sorted(under)                       # a higher θ_C never predicts more
    assert under[0] < under[-1] and over[0] > over[-1]
    at_half = next(s for s in report["theta_sweep"] if s["theta_c"] == 0.5)
    assert at_half["under_prediction_rate"] == report["model"]["under_prediction_rate"]


def test_the_model_beats_the_trivial_baselines_on_synthetic_data(report):
    model, base = report["model"], report["baselines"]
    assert base["empty"]["under_prediction_rate"]["mean"] == 1.0
    assert base["pod_defaults"]["under_prediction_rate"]["mean"] == 0.0
    assert model["under_prediction_rate"]["mean"] < base["allowlist"]["under_prediction_rate"]["mean"]
    assert model["over_prediction_rate"]["mean"] < base["pod_defaults"]["over_prediction_rate"]["mean"]
    assert model["micro_f1"]["mean"] > 0.7


def test_evaluate_is_repeatable(report):
    assert evaluate(ROWS, folds=5, repeats=2, fit_fn=fast_fit) == report


def test_tables(report):
    table = comparison_table(report)
    assert table.count("\n") == 6 and "| ML-A (LightGBM) | " in table and "| Per-label majority |" in table
    assert sweep_table(report).count("\n") == 1 + len(THETA_SWEEP)
    empty = copy.deepcopy(report)
    empty["model"]["macro_f1"] = None
    assert "| n/a |" in comparison_table(empty)


# --- command line ---------------------------------------------------------------------------------------------

def test_cli_writes_the_report_and_the_model(tmp_path, capfd):
    data = write_jsonl(tmp_path / "dataset.jsonl", ROWS)
    rc = main(["--data", str(data), "--out", str(tmp_path / "model"), "--report", str(tmp_path / "r" / "report.json"),
               "--repeats", "1"])
    out, err = capfd.readouterr()
    assert rc == 0
    assert out == f"{tmp_path / 'model' / MODEL_FILE}\n"                  # stdout is only the model path
    assert "| ML-A (LightGBM) |" in err and "| θ_C |" in err
    assert json.loads((tmp_path / "r" / "report.json").read_text(encoding="utf-8"))["repeats"] == 1
    assert CapabilityModel.load(tmp_path / "model").params == LGBM_PARAMS


@pytest.mark.parametrize("rows", [None, ROWS[:4]])
def test_cli_bad_input_exits_3(tmp_path, capfd, rows):
    data = tmp_path / "dataset.jsonl"
    if rows is not None:
        write_jsonl(data, rows)
    assert main(["--data", str(data)]) == 3
    assert capfd.readouterr().out == ""
