"""T2 (integration): the stand-in image is signed and attested. Build it first, then run:

    export PROVBIND_STANDIN_REF=$(pipeline/build-and-attest.sh testbed/standin-app standin-app)
    pytest -q -m integration

These tests only verify. They never build or sign, since signing publishes to Rekor."""
import json
import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
PUB = ROOT / "pipeline" / "keys" / "cosign.pub"


@pytest.fixture(scope="module")
def ref():
    value = os.environ.get("PROVBIND_STANDIN_REF")
    if not value:
        pytest.skip("export PROVBIND_STANDIN_REF=<ref@digest printed by build-and-attest.sh>")
    return value


def cosign(command, ref, *extra):
    offline = ["--insecure-ignore-tlog=true"] if os.environ.get("PROVBIND_OFFLINE") == "1" else []
    return subprocess.run(["cosign", command, "--key", str(PUB), *offline, *extra, ref],
                          capture_output=True, text=True, timeout=300)


def test_signature_verifies(ref):
    out = cosign("verify", ref)
    assert out.returncode == 0, out.stderr


@pytest.mark.parametrize("predicate", ["cyclonedx", "slsaprovenance1"])
def test_attestation_verifies(ref, predicate):
    out = cosign("verify-attestation", ref, "--type", predicate)
    assert out.returncode == 0, out.stderr


def test_debug_sbom_has_dependency_edges(ref):
    run = Path(os.environ.get("PROVBIND_RUN", ROOT / "run"))
    sbom = json.loads((run / "attest" / "standin-app" / "sbom.json").read_text())
    assert len(sbom.get("dependencies") or []) > 0
