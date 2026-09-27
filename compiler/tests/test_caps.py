"""T10: capabilities from the allowlist and the port rule. T13 step 6: the model hook, with a
stub model here; test_caps_model.py uses a trained one."""
import sys
from pathlib import Path

import pytest

from compiler import caps as caps_module
from compiler.caps import capabilities, for_image, load_allowlist, load_model, model_dir, predicted
from compiler.oci import BadInput
from compiler.purls import identity, pep503

from .helpers import MemFS, config, make_elf


def caps(packages=(), ports=None, allowlist=None):
    return capabilities(packages, ports, allowlist)


def test_allowlist_hits_a_package():
    assert caps(["pkg:pypi/gunicorn@21.2.0"]) == [{"cap": "CAP_NET_BIND_SERVICE", "origin": "INFERRED"}]


def test_allowlist_ignores_version_and_qualifiers():
    purl = "pkg:deb/debian/iputils-ping@3:20221126-1?arch=amd64&distro=debian-12"
    assert caps([purl]) == [{"cap": "CAP_NET_RAW", "origin": "INFERRED"}]


def test_allowlist_matches_pypi_names_after_pep503():
    allow = {("pypi", None, "foo-bar"): ["CAP_SYS_TIME"]}
    assert caps(["pkg:pypi/Foo_Bar@1.0"], allowlist=allow) == [{"cap": "CAP_SYS_TIME", "origin": "INFERRED"}]


@pytest.mark.parametrize("port,fires", [("80/tcp", True), ("8080/tcp", False), ("53/udp", True),
                                        ("1023/tcp", True), ("1024/tcp", False)])
def test_port_rule(port, fires):
    expected = [{"cap": "CAP_NET_BIND_SERVICE", "origin": "INFERRED"}] if fires else []
    assert caps(ports={port: {}}) == expected


def test_one_entry_per_capability():
    assert caps(["pkg:pypi/gunicorn@21.2.0", "pkg:pypi/uvicorn@0.30.0"], {"80/tcp": {}}) == \
        [{"cap": "CAP_NET_BIND_SERVICE", "origin": "INFERRED"}]


def test_nothing_matches():
    assert caps(["pkg:pypi/requests@2.32.3", "not a purl"], {"8080/tcp": {}, "junk": {}}) == []


def test_shipped_allowlist_skips_the_comment():
    allow = load_allowlist()
    assert ("pypi", None, "gunicorn") in allow
    assert all(isinstance(k, tuple) for k in allow)


def test_purl_helpers():
    assert pep503("Foo_Bar.baz--Qux") == "foo-bar-baz-qux"
    assert identity("pkg:deb/debian/libc6@2.36-9?arch=amd64") == ("deb", "debian", "libc6")
    assert identity("nonsense") is None


def test_the_allowlist_is_capped_at_the_allowed_set_when_given():
    ping = "pkg:deb/debian/iputils-ping@20221126"
    assert caps([ping], {"80/tcp": {}}) == [{"cap": "CAP_NET_BIND_SERVICE", "origin": "INFERRED"},
                                           {"cap": "CAP_NET_RAW", "origin": "INFERRED"}]
    assert capabilities([ping], {"80/tcp": {}}, allowed=["NET_BIND_SERVICE"]) == \
        [{"cap": "CAP_NET_BIND_SERVICE", "origin": "INFERRED"}]
    assert capabilities([ping], {"80/tcp": {}}, allowed=[]) == []


# --- the model hook (T13 step 6) --------------------------------------------------------------------

class StubModel:
    """Stands in for ml.train.CapabilityModel: fixed probabilities, and it keeps the features."""
    theta = 0.5
    vocabulary = ["pypi/requests", "npm/express"]

    def __init__(self, probabilities):
        self.probabilities = probabilities
        self.seen = None

    def predict_proba(self, features):
        self.seen = dict(features)
        return dict(self.probabilities)


def test_predicted_is_algorithm_1_with_rounded_probabilities():
    model = StubModel({"CAP_NET_BIND_SERVICE": 0.912345678, "CAP_SETUID": 0.5, "CAP_CHOWN": 0.4999})
    assert predicted(model, {}) == [{"cap": "CAP_NET_BIND_SERVICE", "origin": "INFERRED", "probability": 0.9123},
                                    {"cap": "CAP_SETUID", "origin": "INFERRED", "probability": 0.5}]


def test_predicted_is_capped_at_the_allowed_set_when_given():
    model = StubModel({"CAP_NET_BIND_SERVICE": 0.9, "CAP_SETUID": 0.9, "CAP_SYS_ADMIN": 1.0})
    assert [c["cap"] for c in predicted(model, {}, allowed=["NET_BIND_SERVICE"])] == ["CAP_NET_BIND_SERVICE"]
    assert predicted(model, {}, allowed=[]) == []
    assert [c["cap"] for c in predicted(model, {})] == ["CAP_NET_BIND_SERVICE", "CAP_SETUID", "CAP_SYS_ADMIN"]


def test_for_image_gives_the_model_this_images_features():
    fs = MemFS({"/usr/bin/server": make_elf(interp="/lib64/ld-linux-x86-64.so.2", imports=["socket", "bind"])})
    packages = {"pkg:pypi/requests@2.32.3": {"depth": 1}, "pkg:deb/debian/libc6@2.36-9": {"depth": None}}
    model = StubModel({"CAP_NET_BIND_SERVICE": 0.8})
    got = for_image(packages, config(exposed_ports={"80/tcp": {}}), ["/usr/bin/server"], fs, model)
    assert got == [{"cap": "CAP_NET_BIND_SERVICE", "origin": "INFERRED", "probability": 0.8}]
    seen = model.seen
    assert (seen["pkg.has.pypi/requests"], seen["pkg.has.npm/express"], seen["pkg.count.deb"]) == (1.0, 0.0, 1.0)
    assert (seen["imp.socket"], seen["imp.bind"], seen["imp.setuid"]) == (1.0, 1.0, 0.0)   # read from the ELF
    assert (seen["cfg.port_below_1024"], seen["clo.size"], seen["dep.privileged"]) == (1.0, 1.0, 0.0)


def test_for_image_without_a_model_is_the_allowlist():
    packages = {"pkg:pypi/gunicorn@21.2.0": {"depth": 1}}
    assert for_image(packages, config(exposed_ports={"8080/tcp": {}}), [], MemFS({})) == \
        [{"cap": "CAP_NET_BIND_SERVICE", "origin": "INFERRED"}]


@pytest.mark.parametrize("value,expected", [(None, caps_module.MODEL_DIR), ("", caps_module.MODEL_DIR),
                                            ("none", None), (" None ", None), ("/opt/model", Path("/opt/model"))])
def test_model_dir(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("PROVBIND_CAPS_MODEL", raising=False)
    else:
        monkeypatch.setenv("PROVBIND_CAPS_MODEL", value)
    assert model_dir() == expected


def test_the_default_model_dir_is_ml_model_in_the_repo():
    assert caps_module.MODEL_DIR == Path(__file__).resolve().parents[2] / "ml" / "model"


def test_no_model_file_means_the_allowlist(tmp_path):
    assert load_model(None) is None
    assert load_model(tmp_path) is None
    assert load_model(tmp_path / "missing") is None


def test_a_model_without_the_ml_libraries_is_bad_input(tmp_path, monkeypatch):
    (tmp_path / "model.json").write_text("{}")
    monkeypatch.setitem(sys.modules, "ml.train", None)          # as if numpy or LightGBM were missing
    with pytest.raises(BadInput, match="needs the ML libraries"):
        load_model(tmp_path)


def test_unit_tests_compile_with_the_allowlist():
    """conftest.py keeps a model trained into ml/model/ on this machine out of the unit tests."""
    assert model_dir() is None and load_model(model_dir()) is None
