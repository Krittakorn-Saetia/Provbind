"""Eq. (37): the runtime indices J_I built from an envelope."""
import json
from pathlib import Path

import pytest

from compiler.indices import build

GOLDEN = json.loads((Path(__file__).with_name("golden") / "envelope.json").read_text())
LIBC = "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12"


def envelope(files, packages=None):
    return {"layers": [{"index": 0, "digest": "sha256:" + "a" * 64}, {"index": 1, "digest": "sha256:" + "b" * 64}],
            "files": files, "packages": packages or {}}


def test_each_index_maps_what_eq_37_says():
    env = envelope({"/usr/bin/ls": {"sha256": "11", "layer": 0, "package": LIBC, "mode": "0755"},
                    "/app/ls-copy": {"sha256": "11", "layer": 1, "package": None, "mode": "0755"},
                    "/app/app.py": {"sha256": "22", "layer": 1, "package": None, "mode": "0644"}},
                   {LIBC: {"depth": 2}, "pkg:pypi/pip@24.0": {"depth": None}})
    j = build(env)
    assert j.path == {"/usr/bin/ls": ("11", 0), "/app/ls-copy": ("11", 1), "/app/app.py": ("22", 1)}
    assert j.hash == {"11": frozenset({"/usr/bin/ls", "/app/ls-copy"}), "22": frozenset({"/app/app.py"})}
    assert j.layer == {"/usr/bin/ls": "sha256:" + "a" * 64, "/app/ls-copy": "sha256:" + "b" * 64,
                       "/app/app.py": "sha256:" + "b" * 64}
    assert j.pkg == {"/usr/bin/ls": LIBC, "/app/ls-copy": None, "/app/app.py": None}
    assert j.depth == {LIBC: 2, "pkg:pypi/pip@24.0": None}


def test_a_file_in_an_unknown_layer_is_an_error():
    with pytest.raises(ValueError, match="layer 7"):
        build(envelope({"/x": {"sha256": "11", "layer": 7, "package": None, "mode": "0644"}}))


def test_the_golden_envelope():
    j = build(GOLDEN)
    assert set(j.path) == set(j.layer) == set(j.pkg) == set(GOLDEN["files"])
    assert sum(len(ps) for ps in j.hash.values()) == len(GOLDEN["files"])
    assert j.pkg["/usr/lib/x86_64-linux-gnu/libc.so.6"] == LIBC and j.depth[LIBC] == 2
    assert j.depth["pkg:pypi/requests@2.32.3"] == 1 and j.depth["pkg:pypi/urllib3@2.2.2"] == 2
