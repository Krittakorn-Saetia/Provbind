"""T13 step 3: dataset D1, Role 1's labels joined to the compiler's features (ml/dataset.py)."""
import json
import os

import pytest

from ml import dataset
from ml.alg1 import RUNTIME_DEFAULT_CAPS
from ml.features import FEATURES_VERSION, feature_names


def digest(i):
    return f"sha256:{i:064x}"


def label_row(i, labels=("NET_BIND_SERVICE",), **extra):
    """A row as testbed/profiling/labels.py build_label_row writes it."""
    return {"image": f"img{i}:1", "digest": digest(i), "labels": list(labels), "denied": ["CAP_SYS_ADMIN"],
            "runs": 2, "run_disagreement": 0, "disagreement_fraction": 0.0, "workload": "curl", **extra}


def feature_row(i, clo_size=None, **extra):
    """A line as compiler.compile --features-out appends it."""
    features = {n: 0.0 for n in feature_names()}
    features["clo.size"] = float(i if clo_size is None else clo_size)
    features["imp.socket"] = None                               # missing, as NaN is written
    return {"digest": digest(i), "ref": f"localhost:5001/img{i}@{digest(i)}", "features_version": FEATURES_VERSION,
            "features": features, "packages": ["pkg:deb/debian/libc6@2.36"], "exposed_ports": ["80/tcp"], **extra}


def write(path, rows):
    path.write_text("".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in rows), encoding="utf-8")
    return path


def read(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def paths(tmp_path):
    def make(labels, features):
        return (write(tmp_path / "labels.jsonl", labels), write(tmp_path / "features.jsonl", features),
                tmp_path / "data" / "dataset.jsonl")
    return make


def run(labels, features, out):
    return dataset.main(["--labels", str(labels), "--features", str(features), "--out", str(out)])


# --- the join ---------------------------------------------------------------------------------------

def test_rows_join_by_digest_in_label_order(paths, capsys):
    labels, features, out = paths([label_row(1), label_row(2, labels=["cap_net_raw", "CHOWN"])],
                                  [feature_row(2), feature_row(1)])
    assert run(labels, features, out) == 0
    assert capsys.readouterr().out == f"{out}\n"                 # stdout carries only the path
    rows = read(out)
    assert [r["digest"] for r in rows] == [digest(1), digest(2)]
    first, second = rows
    assert first["image"] == "img1:1" and first["ref"] == f"localhost:5001/img1@{digest(1)}"
    assert first["features"] == feature_row(1)["features"]
    assert first["packages"] == ["pkg:deb/debian/libc6@2.36"] and first["exposed_ports"] == ["80/tcp"]
    assert first["labels"] == ["CAP_NET_BIND_SERVICE"]
    assert second["labels"] == ["CAP_CHOWN", "CAP_NET_RAW"]      # normalised and sorted
    assert all(r["allowed"] == sorted(RUNTIME_DEFAULT_CAPS) for r in rows)   # default pods
    assert (first["denied"], first["runs"], first["disagreement_fraction"], first["workload"]) == \
           (["CAP_SYS_ADMIN"], 2, 0.0, "curl")                  # Role 1's fields are kept


def test_rows_load_with_ml_train(paths):
    pytest.importorskip("lightgbm")
    pytest.importorskip("sklearn")
    from ml.train import load_dataset
    labels, features, out = paths([label_row(i) for i in range(1, 4)], [feature_row(i) for i in range(1, 4)])
    assert run(labels, features, out) == 0
    rows = load_dataset(out)
    assert len(rows) == 3 and rows[0]["labels"] == ["CAP_NET_BIND_SERVICE"]


def test_digests_in_only_one_file_are_reported(paths, capsys):
    labels, features, out = paths([label_row(1), label_row(2)], [feature_row(2), feature_row(3)])
    assert run(labels, features, out) == 0
    err = capsys.readouterr().err
    assert f"labels but no features: {digest(1)} (img1:1)" in err
    assert f"features but no labels: {digest(3)}" in err
    assert "1 images joined (1 labelled only, 1 with features only)" in err
    assert [r["digest"] for r in read(out)] == [digest(2)]


def test_the_last_line_wins(paths):
    labels, features, out = paths([label_row(1, labels=["CHOWN"]), label_row(1, labels=["NET_RAW"])],
                                  [feature_row(1, clo_size=3), feature_row(1, clo_size=9)])
    assert run(labels, features, out) == 0
    (row,) = read(out)
    assert row["labels"] == ["CAP_NET_RAW"] and row["features"]["clo.size"] == 9.0


def test_features_of_another_version_are_skipped(paths, capsys):
    labels, features, out = paths([label_row(1), label_row(2)],
                                  [feature_row(1, features_version=FEATURES_VERSION + 1), feature_row(2)])
    assert run(labels, features, out) == 0
    assert "skipped (recompile it with --features-out)" in capsys.readouterr().err
    assert [r["digest"] for r in read(out)] == [digest(2)]


# --- what is refused, with nothing written ------------------------------------------------------------

def refused(tmp_path, paths, labels, features, capsys, message):
    labels_path, features_path, out = paths(labels, features)
    assert run(labels_path, features_path, out) == 1
    err = capsys.readouterr().err
    assert message in err and "nothing written" in err
    assert not out.exists()


@pytest.mark.parametrize("field,value", [("allowed", ["CAP_CHOWN"]), ("securityContext", {"privileged": True}),
                                         ("deployment", {"add": ["SYS_ADMIN"]})])
def test_a_label_row_with_its_own_pod_is_refused(tmp_path, paths, capsys, field, value):
    refused(tmp_path, paths, [label_row(1, **{field: value})], [feature_row(1)], capsys, "records its own pod")


@pytest.mark.parametrize("labels,features,message", [
    (["{not json"], [feature_row(1)], "not JSON"),
    ([["a list"]], [feature_row(1)], "not a JSON object"),
    ([{"image": "x", "digest": digest(1)}], [feature_row(1)], "missing labels"),
    ([label_row(1, digest="sha256:abc")], [feature_row(1)], "digest is not sha256:<64 hex>"),
    ([label_row(1, labels=["CAP_FLY"])], [feature_row(1)], "unknown capability"),
    ([label_row(1)], [{k: v for k, v in feature_row(1).items() if k != "packages"}], "missing packages"),
    ([label_row(1)], [feature_row(1, features={"clo.size": 1.0})], "are not the"),
    ([label_row(1)], [feature_row(2)], "no digest is in both"),
], ids=["not-json", "not-an-object", "missing-field", "bad-digest", "unknown-cap", "features-missing-field",
        "wrong-features", "no-common-digest"])
def test_bad_input_writes_nothing(tmp_path, paths, capsys, labels, features, message):
    refused(tmp_path, paths, labels, features, capsys, message)


def test_a_missing_input_file_writes_nothing(tmp_path, capsys):
    out = tmp_path / "dataset.jsonl"
    assert run(tmp_path / "nope.jsonl", write(tmp_path / "f.jsonl", [feature_row(1)]), out) == 1
    assert "cannot read" in capsys.readouterr().err and not out.exists()


def test_the_output_is_replaced_whole(paths):
    labels, features, out = paths([label_row(1)], [feature_row(1)])
    out.parent.mkdir(parents=True)
    out.write_text("old\n")
    assert run(labels, features, out) == 0
    assert [r["digest"] for r in read(out)] == [digest(1)]
    assert os.listdir(out.parent) == ["dataset.jsonl"]           # no temp file left behind


# --- end to end: the compiler's --features-out line joined to a label row -------------------------------

def test_a_compiled_image_joins_to_its_label_row(tmp_path, capsys):
    from compiler.compile import EXIT_OK, main as compile_main
    from compiler.tests.helpers import FakeCosign, FakeRegistry
    from compiler.tests.test_compile import PROVENANCE, REPO, SBOM, push_synthetic

    reg = FakeRegistry()
    d = push_synthetic(reg)
    features = tmp_path / "features.jsonl"
    assert compile_main([f"{REPO}@{d}", "--run", str(tmp_path / "run"), "--key", "unused",
                         "--features-out", str(features)], crane=reg, cosign=FakeCosign(d, SBOM, PROVENANCE)) == EXIT_OK
    labels = write(tmp_path / "labels.jsonl", [{**label_row(0), "digest": d, "image": "standin-app"}])
    out = tmp_path / "dataset.jsonl"
    assert run(labels, features, out) == 0
    (row,) = read(out)
    (line,) = read(features)
    assert row["features"] == line["features"] and row["packages"] == line["packages"]
    assert row["exposed_ports"] == ["8080/tcp"] and row["image"] == "standin-app"
