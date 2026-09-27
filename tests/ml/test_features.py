"""Unit tests for ml/features.py: Ω_I (Eq. 32, Test Plan §4.3)."""
import copy
import json
import math
import random
from pathlib import Path

import pytest

from compiler.oci import ImageConfig
from compiler.tests.helpers import MemFS, make_elf
from ml.features import (WATCHED_SYMBOLS, build_vocabulary, closure_imports, extract, feature_names, package_id,
                         runs_as_root)

from .features_doc import VOCABULARY_PATTERN, documented_names, undocumented

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = json.loads((ROOT / "compiler" / "tests" / "golden" / "envelope.json").read_text())
CONFIG = {"User": "", "ExposedPorts": {"8080/tcp": {}}, "Env": ["PATH=/usr/local/bin:/usr/bin", "LANG=C.UTF-8"]}


def f(envelope=GOLDEN, config=CONFIG, **kwargs):
    return extract(envelope, config, **kwargs).as_dict()


# --- shape and documentation -----------------------------------------------------------------

def test_length_is_fixed_for_a_vocabulary():
    assert len(feature_names()) == 46
    assert len(feature_names(["pypi/requests", "deb/libc6"])) == 48
    assert len(extract(GOLDEN, CONFIG).values) == 46


def test_every_feature_is_documented_and_every_documented_feature_exists():
    documented = documented_names()
    assert undocumented(feature_names(["pypi/requests"]), documented) == []
    assert documented - {VOCABULARY_PATTERN} == set(feature_names())


def test_repeated_vocabulary_entry_raises():
    with pytest.raises(ValueError, match="repeats"):
        feature_names(["pypi/requests", "pypi/requests"])


# --- configuration --------------------------------------------------------------------------------

@pytest.mark.parametrize("user,root", [("", True), ("root", True), ("0", True), ("0:0", True),
                                       ("root:root", True), ("1000", False), ("app", False), ("1000:1000", False)])
def test_runs_as_root(user, root):
    assert runs_as_root(user) is root


def test_configuration_features():
    v = f(config={"User": "app", "ExposedPorts": {"80/tcp": {}, "8080/tcp": {}, "junk": {}}, "Env": ["A=1"]})
    assert (v["cfg.runs_as_root"], v["cfg.user_set"], v["cfg.exposed_ports"], v["cfg.port_below_1024"],
            v["cfg.env_vars"]) == (0.0, 1.0, 3.0, 1.0, 1.0)
    v = f()
    assert (v["cfg.runs_as_root"], v["cfg.user_set"], v["cfg.port_below_1024"]) == (1.0, 0.0, 0.0)


def test_config_forms_agree():
    as_object = ImageConfig([], ["python", "app.py"], CONFIG["Env"], CONFIG["ExposedPorts"], "", "/app",
                            "linux", "amd64")
    assert extract(GOLDEN, CONFIG) == extract(GOLDEN, {"config": CONFIG}) == extract(GOLDEN, as_object)


# --- packages -----------------------------------------------------------------------------------

def test_package_counts_per_ecosystem():
    v = f()
    assert (v["pkg.count.deb"], v["pkg.count.pypi"], v["pkg.count.other"]) == (4.0, 3.0, 0.0)
    assert v["pkg.count.npm"] == 0.0


def test_a_key_that_is_not_a_purl_counts_as_other():
    v = f(envelope={"packages": {"local-thing": {"depth": None}}, "closure": []})
    assert v["pkg.count.other"] == 1.0


@pytest.mark.parametrize("purl,expected", [
    ("pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12", "deb/libc6"),
    ("pkg:pypi/Foo_Bar@1.0", "pypi/foo-bar"),
    ("pkg:npm/%40scope/pkg@1.0.0", "npm/pkg"),
    ("not a purl", None),
])
def test_package_id(purl, expected):
    assert package_id(purl) == expected


def test_vocabulary_indicators():
    v = f(vocabulary=["pypi/requests", "deb/libc6", "npm/express"])
    assert (v["pkg.has.pypi/requests"], v["pkg.has.deb/libc6"], v["pkg.has.npm/express"]) == (1.0, 1.0, 0.0)


def test_build_vocabulary_counts_images_and_breaks_ties_by_name():
    envs = [{"packages": {"pkg:pypi/b@1": {}, "pkg:pypi/b@2": {}, "pkg:pypi/a@1": {}}},
            {"packages": {"pkg:pypi/a@1": {}, "pkg:deb/debian/c@1": {}}},
            {"packages": {"pkg:deb/debian/c@1": {}, "pkg:pypi/b@1": {}}}]
    assert build_vocabulary(envs) == ["deb/c", "pypi/a", "pypi/b"]      # each is in 2 images
    assert build_vocabulary(envs, k=2) == ["deb/c", "pypi/a"]


# --- closure ------------------------------------------------------------------------------------

def test_closure_features_on_the_golden_envelope():
    v = f()
    assert v["clo.size"] == 5.0
    assert (v["clo.interp.python"], v["clo.interp.node"], v["clo.interp.java"], v["clo.interp.shell"],
            v["clo.static"]) == (1.0, 0.0, 0.0, 0.0, 0.0)


@pytest.mark.parametrize("closure,feature", [
    (["/usr/local/lib/libpython3.11.so.1.0"], "clo.interp.python"),
    (["/usr/bin/python3"], "clo.interp.python"),
    (["/usr/local/bin/node"], "clo.interp.node"),
    (["/opt/java/bin/java"], "clo.interp.java"),
    (["/usr/lib/jvm/lib/server/libjvm.so"], "clo.interp.java"),
    (["/usr/bin/dash"], "clo.interp.shell"),
    (["/bin/busybox"], "clo.interp.shell"),
    (["/app/server"], "clo.static"),
])
def test_interpreter_and_static_detection(closure, feature):
    assert f(envelope={"packages": {}, "closure": closure})[feature] == 1.0


def test_a_dynamic_loader_means_not_static():
    v = f(envelope={"packages": {}, "closure": ["/app/server", "/lib/ld-musl-x86_64.so.1"]})
    assert v["clo.static"] == 0.0
    assert f(envelope={"packages": {}, "closure": []})["clo.static"] == 0.0


# --- ELF imports ----------------------------------------------------------------------------------

def test_imports_unknown_are_nan():
    v = f()
    assert all(math.isnan(v[f"imp.{s}"]) for s in WATCHED_SYMBOLS)


def test_imports_count_only_closure_binaries():
    py = "/usr/local/bin/python3.11"
    v = f(imports={py: ["socket", "connect"], "/usr/bin/ls": ["chown"]})
    assert (v["imp.socket"], v["imp.connect"], v["imp.chown"], v["imp.bind"]) == (1.0, 1.0, 0.0, 0.0)


def test_closure_imports_reads_undefined_symbols_from_the_image(caplog):
    fs = MemFS({"/usr/bin/tool": make_elf(interp="/lib64/ld-linux-x86-64.so.2", needed=["libc.so.6"],
                                          imports=["socket", "bind", "printf"], exports=["setuid"]),
                "/usr/lib/libc.so.6": make_elf(exports=["socket", "setuid"]),
                "/app/run.sh": b"#!/bin/sh\n",
                "/app/broken": b"\x7fELF" + b"\x02\x01\x01" + b"\0" * 9 + b"garbage"})
    got = closure_imports(fs, ["/usr/bin/tool", "/usr/lib/libc.so.6", "/app/run.sh", "/app/broken"])
    assert got == {"/usr/bin/tool": ("bind", "socket"), "/usr/lib/libc.so.6": ()}
    assert "/app/broken" in caplog.text
    v = f(envelope={"packages": {}, "closure": ["/usr/bin/tool", "/usr/lib/libc.so.6"]}, imports=got)
    assert (v["imp.socket"], v["imp.bind"], v["imp.setuid"]) == (1.0, 1.0, 0.0)


def test_an_elf_without_dynamic_symbols_imports_nothing(caplog):
    fs = MemFS({"/usr/bin/tool": make_elf(interp="/lib64/ld-linux-x86-64.so.2", needed=["libc.so.6"]),   # no DT_SYMTAB
                "/app/server": make_elf()})
    assert closure_imports(fs, ["/usr/bin/tool", "/app/server"]) == {"/usr/bin/tool": (), "/app/server": ()}
    assert caplog.text == ""


# --- deployment -------------------------------------------------------------------------------------

@pytest.mark.parametrize("deployment,expected", [
    (None, (0.0, 0.0, 0.0)),
    ({"privileged": True}, (1.0, 27.0, 0.0)),
    ({"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]}, (0.0, 0.0, 13.0)),
    ({"add": ["NET_ADMIN"], "drop": ["NET_RAW"]}, (0.0, 1.0, 1.0)),
])
def test_deployment_features(deployment, expected):
    v = f(deployment=deployment)
    assert (v["dep.privileged"], v["dep.caps_added"], v["dep.caps_dropped"]) == expected


# --- determinism ------------------------------------------------------------------------------------

def test_order_of_inputs_does_not_matter():
    rng = random.Random(7)
    shuffled = copy.deepcopy(GOLDEN)
    items = list(shuffled["packages"].items())
    rng.shuffle(items)
    shuffled["packages"] = dict(items)
    rng.shuffle(shuffled["closure"])
    imports = {p: ["socket", "bind"] for p in GOLDEN["closure"]}
    reversed_imports = {p: list(reversed(s)) for p, s in reversed(list(imports.items()))}
    vocab = ["pypi/requests", "deb/libc6"]
    assert extract(GOLDEN, CONFIG, imports=imports, vocabulary=vocab) == \
        extract(shuffled, dict(reversed(list(CONFIG.items()))), imports=reversed_imports, vocabulary=vocab)


def test_to_json_turns_nan_into_null():
    js = extract(GOLDEN, CONFIG).to_json()
    assert js["imp.socket"] is None and js["clo.size"] == 5.0
    json.dumps(js, allow_nan=False)
