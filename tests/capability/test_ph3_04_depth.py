"""PH3-04: dependency depth δ (Eq. 29) (Test Plan §3.3). Pass: the T8 unit tests pass, and on the
stand-in image `requests` has depth 1 and `urllib3` depth 2.

The stand-in's depths come from PROVBIND_ENVELOPE (its `packages` section) or PROVBIND_SBOM (its
CycloneDX SBOM, or an in-toto statement holding one, through compiler.sbom.depths). With neither,
the compile tests' synthetic SBOM stands in and the result is not_run.
"""
import json
import os
from pathlib import Path

from compiler.purls import identity
from compiler.sbom import depths
from compiler.tests.test_compile import SBOM as SYNTHETIC_SBOM

from .test_ph3_01_02_06_kit import run_suite

EXPECTED = {"requests": 1, "urllib3": 2}


def _packages():
    """(purl -> {"depth": ...}, where they came from, whether that is the real stand-in)."""
    envelope, sbom = os.environ.get("PROVBIND_ENVELOPE"), os.environ.get("PROVBIND_SBOM")
    if envelope:
        return json.loads(Path(envelope).read_text(encoding="utf-8"))["packages"], f"envelope {envelope}", True
    if sbom:
        doc = json.loads(Path(sbom).read_text(encoding="utf-8"))
        if "bomFormat" not in doc and isinstance(doc.get("predicate"), dict):
            doc = doc["predicate"]
        return depths(doc)[0], f"SBOM {sbom}", True
    return depths(SYNTHETIC_SBOM)[0], "synthetic SBOM of compiler/tests/test_compile.py", False


def pypi_depth(packages: dict, name: str) -> int | None:
    """The smallest non-null depth among the versions of a PyPI package, or None."""
    found = [info.get("depth") for purl, info in packages.items() if identity(purl) == ("pypi", None, name)]
    known = [d for d in found if d is not None]
    return min(known) if known else None


def test_ph3_04_dependency_depth(record_result):
    kit = run_suite("PH3-04", "compiler/tests/test_sbom.py")
    packages, source, real = _packages()
    got = {name: pypi_depth(packages, name) for name in EXPECTED}
    ok = kit["ok"] and got == EXPECTED
    notes = (f"{source}: requests depth {got['requests']}, urllib3 depth {got['urllib3']}; "
             f"T8 unit tests: {kit['metrics']['passed']} passed, {kit['metrics']['failed']} failed")
    status = "pass" if ok and real else ("fail" if not ok else "not_run")
    if status == "not_run":
        notes += "; set PROVBIND_ENVELOPE or PROVBIND_SBOM to the stand-in's for the real test"
    record_result("PH3-04", status,
                  metrics={"requests_depth": got["requests"], "urllib3_depth": got["urllib3"],
                           "unit_tests_passed": kit["metrics"]["passed"], "unit_tests_failed": kit["metrics"]["failed"],
                           "packages": len(packages)},
                  notes=notes, artifacts=[kit["junit"]])
    assert ok, notes + "\n" + kit["output"]
