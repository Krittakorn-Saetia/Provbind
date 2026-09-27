"""T13 step 6 with a trained ML-A model: loading it, the envelope it produces, and the CLI.
Skipped where the ML libraries are not installed (requirements-role2.txt alone)."""
import json

import pytest

pytest.importorskip("lightgbm")

from compiler import caps, oci                                                    # noqa: E402
from compiler.compile import EXIT_INPUT, EXIT_OK, build_envelope, main, validate  # noqa: E402
from compiler.oci import BadInput                                                 # noqa: E402
from ml import train                                                              # noqa: E402
from ml.alg1 import RUNTIME_DEFAULT_CAPS                                          # noqa: E402
from ml.train import fit, matrix, row_features, trainable_labels                  # noqa: E402
from tests.ml import synthetic                                                    # noqa: E402

from .helpers import FakeCosign, FakeRegistry, MemFS, config, make_elf            # noqa: E402
from .test_compile import NOW, PROVENANCE, REPO, SBOM, evidence_for, push_synthetic  # noqa: E402


class Recorder:
    """A model that predicts nothing and records the features it is given."""
    theta, vocabulary, seen = 0.5, [], None

    def predict_proba(self, features):
        self.seen = dict(features)
        return {}


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    """The synthetic compile image, and its feature row as the training dataset would store it."""
    reg = FakeRegistry()
    digest = push_synthetic(reg)
    image = oci.fetch(f"{REPO}@{digest}", str(tmp_path_factory.mktemp("cache")), reg)
    recorder = Recorder()
    env = build_envelope(image, evidence_for(digest), NOW, model=recorder)
    assert env["capabilities"] == []
    return digest, image, {"features": recorder.seen, "packages": sorted(env["packages"])}


@pytest.fixture(scope="module")
def model_dir(tmp_path_factory, compiled):
    """Trained with the real parameters on the synthetic rows plus four images like the compile
    image that use CAP_NET_RAW, so a booster has to predict it for that image."""
    _, _, row = compiled
    rows = synthetic.rows() + [{**row, "digest": f"sha256:{i:064x}", "labels": ["CAP_NET_RAW"],
                                "allowed": sorted(RUNTIME_DEFAULT_CAPS)} for i in range(4)]
    labels, too_rare = trainable_labels(rows)
    directory = tmp_path_factory.mktemp("model")
    fit(rows, labels, too_rare=too_rare).save(directory)
    return directory


@pytest.fixture
def image(tmp_path):
    reg = FakeRegistry()
    digest = push_synthetic(reg)
    return reg, digest, oci.fetch(f"{REPO}@{digest}", str(tmp_path / "cache"), reg)


class Spy:
    """A model that records the features the compiler gives it."""
    def __init__(self, model):
        self.model, self.theta, self.vocabulary, self.seen = model, model.theta, model.vocabulary, None

    def predict_proba(self, features):
        self.seen = dict(features)
        return self.model.predict_proba(features)


def test_the_model_file_name_is_the_trainers():
    assert caps.MODEL_FILE == train.MODEL_FILE


def test_load_model_reads_a_trained_model(model_dir):
    model = caps.load_model(model_dir)
    assert model.labels and model.theta == 0.5 and len(model.feature_names) == 46 + len(model.vocabulary)


@pytest.mark.parametrize("change,message", [
    (lambda text: "{not json", "cannot be used"),
    (lambda text: text.replace('"features_version": 1', '"features_version": 99'), "features version 99"),
    (lambda text: json.dumps({**json.loads(text), "boosters": {"CAP_SETUID": "tree\ngarbage"}}), "cannot be used"),
])
def test_a_model_that_cannot_be_used_is_bad_input(model_dir, tmp_path, change, message):
    (tmp_path / "model.json").write_text(change((model_dir / "model.json").read_text(encoding="utf-8")))
    with pytest.raises(BadInput, match=message):
        caps.load_model(tmp_path)


def test_the_envelope_carries_the_models_capabilities_with_probabilities(model_dir, compiled):
    digest, img, _ = compiled
    spy = Spy(caps.load_model(model_dir))
    assert "CAP_NET_RAW" in spy.model.boosters
    env = build_envelope(img, evidence_for(digest), NOW, model=spy)
    validate(env)                                       # the extra field is within the contract
    z = spy.seen                                        # the compiler passed this image's features
    assert (z["pkg.count.pypi"], z["pkg.count.deb"], z["cfg.exposed_ports"], z["cfg.port_below_1024"]) == \
        (3.0, 4.0, 1.0, 0.0)
    assert (z["clo.size"], z["clo.interp.python"], z["imp.socket"], z["dep.caps_dropped"]) == (5.0, 1.0, 0.0, 0.0)
    probabilities = spy.model.predict_proba(z)
    assert env["capabilities"] == [{"cap": c, "origin": "INFERRED", "probability": round(p, 4)}
                                   for c, p in sorted(probabilities.items()) if p >= 0.5]
    assert "CAP_NET_RAW" in [c["cap"] for c in env["capabilities"]]


def test_training_rows_and_compilation_see_the_same_features(model_dir):
    """The dataset stores image_features() with no vocabulary plus the purls (T13 step 3); the
    trainer adds pkg.has.*. That must equal what the compiler computes with the vocabulary."""
    model = caps.load_model(model_dir)
    fs = MemFS({"/usr/local/bin/python3.11": make_elf(interp="/lib64/ld-linux-x86-64.so.2", imports=["socket"]),
                "/usr/sbin/nginx": make_elf(imports=["setuid", "bind"])})
    packages = {purl: {"depth": 1} for purl in ["pkg:deb/debian/nginx@1.27.0", "pkg:deb/debian/libc6@2.36",
                                                "pkg:pypi/requests@2.32.3", "pkg:npm/lodash@4.17.21"]}
    cfg = config(env=["A=1"], exposed_ports={"80/tcp": {}})
    closure = ["/usr/sbin/nginx", "/usr/local/bin/python3.11"]
    row = {"features": caps.image_features(packages, cfg, closure, fs).to_json(), "packages": list(packages)}
    at_compile = caps.image_features(packages, cfg, closure, fs, model.vocabulary).as_dict()
    assert (matrix([row_features(row, model.vocabulary)], model.feature_names).tolist()
            == matrix([at_compile], model.feature_names).tolist())
    assert model.predict_proba(row_features(row, model.vocabulary)) == model.predict_proba(at_compile)


def test_the_cli_uses_the_model_named_by_the_environment(model_dir, image, tmp_path, monkeypatch, capsys):
    reg, digest, _ = image
    monkeypatch.setenv("PROVBIND_CAPS_MODEL", str(model_dir))
    code = main([f"{REPO}@{digest}", "--run", str(tmp_path / "run"), "--key", "unused"], crane=reg,
                cosign=FakeCosign(digest, SBOM, PROVENANCE))
    out = capsys.readouterr()
    assert code == EXIT_OK and "ML-A model in" in out.err
    env = json.loads(open(out.out.strip(), encoding="utf-8").read())
    assert env["capabilities"]
    assert all(c["origin"] == "INFERRED" and 0.5 <= c["probability"] <= 1 for c in env["capabilities"])
    assert "cannot read" not in out.err


def test_the_cli_with_a_broken_model_exits_3_before_the_network(tmp_path, monkeypatch, capsys):
    (tmp_path / "model").mkdir()
    (tmp_path / "model" / "model.json").write_text("{not json")
    monkeypatch.setenv("PROVBIND_CAPS_MODEL", str(tmp_path / "model"))
    reg = FakeRegistry()
    digest = push_synthetic(reg)
    cosign = FakeCosign(digest, SBOM, PROVENANCE)
    code = main([f"{REPO}@{digest}", "--run", str(tmp_path / "run"), "--key", "unused"], crane=reg, cosign=cosign)
    assert code == EXIT_INPUT
    assert reg.calls == [] and cosign.refs == [] and not (tmp_path / "run" / "envelopes").exists()
    assert "cannot be used" in capsys.readouterr().err
