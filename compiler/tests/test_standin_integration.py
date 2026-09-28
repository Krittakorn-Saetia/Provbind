"""Integration (T3, T4, T7, T9, T11, T12): the real compiler on a built, signed image.

    export PROVBIND_STANDIN_REF=$(pipeline/build-and-attest.sh testbed/standin-app standin-app)
    pytest -q -m integration -s          # -s shows the compile time for the slide

For Role 1's demo image, point PROVBIND_STANDIN_REF at its reference and set
PROVBIND_TEST_PACKAGE=requestz-helper. Needs crane, cosign, the registry and
pipeline/keys/cosign.pub; PROVBIND_OFFLINE=1 if the image was signed offline.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from compiler import evidence, oci
from compiler.compile import validate

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
PUB = str(ROOT / "pipeline" / "keys" / "cosign.pub")
PACKAGE = os.environ.get("PROVBIND_TEST_PACKAGE", "requests")


@pytest.fixture(scope="module")
def ref():
    value = os.environ.get("PROVBIND_STANDIN_REF")
    if not value:
        pytest.skip("export PROVBIND_STANDIN_REF=<ref@digest printed by build-and-attest.sh>")
    return value


@pytest.fixture(scope="module")
def compiled(ref, tmp_path_factory):
    """Run `python -m compiler.compile` once, as make demo would."""
    run = tmp_path_factory.mktemp("run")
    started = time.perf_counter()
    out = subprocess.run([sys.executable, "-m", "compiler.compile", ref, "--run", str(run), "--key", PUB],
                         cwd=ROOT, capture_output=True, text=True, timeout=600)
    seconds = time.perf_counter() - started
    assert out.returncode == 0, out.stderr
    path = Path(out.stdout.strip())
    envelope = json.loads(path.read_text())
    print(f"\ncompile time {seconds:.1f} s (target < 60 s on the demo PC); steps (ms): {envelope['timings_ms']}")
    return envelope


# --- T3 and T4 on their own ---------------------------------------------------------------------

def test_t3_evidence_has_sbom_components_and_a_commit(ref):
    _, digest = oci.parse_ref(ref)
    ev = evidence.collect(ref, digest, evidence.Cosign(PUB, offline=os.environ.get("PROVBIND_OFFLINE") == "1"))
    assert ev.sbom.get("components")
    assert ev.source_commit and ev.source_commit != "unknown"


def test_t3_rekor_log_index_is_recorded(compiled):
    """cosign v3 no longer prints it with `verify`; it comes from the signature bundle."""
    index = compiled["image"]["rekor_log_index"]
    if os.environ.get("PROVBIND_OFFLINE") == "1":
        assert index is None
    else:
        assert isinstance(index, int) and index >= 0, index
    assert compiled["verification"]["v_sig"] is True


def test_t4_fetch_gives_layers_and_the_config(ref, tmp_path):
    image = oci.fetch(ref, str(tmp_path / "blobs"), oci.Crane())
    assert len(image.layers) >= 4
    assert image.config.cmd == ["python", "app.py"]


# --- the envelope: handoff Section 1 "done when", T7 and T9 ----------------------------------------------

def test_envelope_validates(compiled):
    validate(compiled)


def test_t7_closure(compiled):
    closure = compiled["closure"]
    assert "/usr/local/bin/python3.11" in closure
    assert "/usr/local/lib/libpython3.11.so.1.0" in closure
    assert any(p.endswith("/libc.so.6") for p in closure)
    assert any(p.endswith("/ld-linux-x86-64.so.2") for p in closure)
    assert "/usr/bin/ls" not in closure and "/usr/bin/dash" not in closure


def test_ls_and_dash_are_in_files(compiled):
    assert "/usr/bin/ls" in compiled["files"] and "/usr/bin/dash" in compiled["files"]


def test_no_entry_for_tmp_x9(compiled):
    assert "/tmp/.x9" not in compiled["files"] and "/tmp/.x9" not in compiled["symlinks"]


def test_t9_package_files_are_owned_by_its_pypi_purl(compiled):
    module = PACKAGE.replace("-", "_")
    mine = {p: f for p, f in compiled["files"].items()
            if f"/site-packages/{module}/" in p or f"/site-packages/{module}-" in p}
    assert mine, f"no files of {PACKAGE} in the envelope"
    purls = {f["package"] for f in mine.values()}
    assert len(purls) == 1 and next(iter(purls)).startswith(f"pkg:pypi/{PACKAGE}@"), purls


def test_t9_ls_is_owned_by_coreutils(compiled):
    assert (compiled["files"]["/usr/bin/ls"]["package"] or "").startswith("pkg:deb/debian/coreutils@")


def test_every_package_reference_is_a_packages_key(compiled):
    referenced = {f["package"] for f in compiled["files"].values()} - {None}
    assert referenced <= set(compiled["packages"])
