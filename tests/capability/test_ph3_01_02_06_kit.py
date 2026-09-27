"""PH3-01, PH3-02 and PH3-06: the Role 2 kit's unit tests (Test Plan §3.3). Pass: all of them pass.

- PH3-01: two-pass whiteout union (Eqs. 24-26), T5: compiler/tests/test_layers.py
- PH3-02: real-path keys on merged /usr images, T6: compiler/tests/test_paths.py
- PH3-06: ownership Φ (Eq. 30), T9: compiler/tests/test_owners.py

Each suite runs in a fresh pytest process, so its result is its own, and its JUnit XML goes to
$PROVBIND_RUN/results/<ID>/junit.xml. The kit builds its fixtures in memory by design (tar layers,
dpkg and pip records), so these results count without a real image.
"""
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUN = Path(os.environ.get("PROVBIND_RUN", "./run"))
SUITES = {
    "PH3-01": "compiler/tests/test_layers.py",
    "PH3-02": "compiler/tests/test_paths.py",
    "PH3-06": "compiler/tests/test_owners.py",
}


def run_suite(test_id: str, suite: str) -> dict:
    """Run one unit-test file in a fresh pytest process: its counts, output and JUnit XML path."""
    junit = RUN / "results" / test_id / "junit.xml"
    junit.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-m", "not integration", "-p", "no:cacheprovider",
                           f"--junitxml={junit.resolve()}", suite], cwd=ROOT, capture_output=True, text=True,
                          timeout=600)
    root = ET.parse(junit).getroot()
    counts = {k: int((root if root.tag == "testsuite" else root.find("testsuite")).get(k, 0))
              for k in ("tests", "failures", "errors", "skipped")}
    passed = counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"]
    return {"ok": proc.returncode == 0 and passed > 0 and counts["failures"] == counts["errors"] == 0,
            "metrics": {"passed": passed, "failed": counts["failures"] + counts["errors"],
                        "skipped": counts["skipped"], "tests": counts["tests"]},
            "output": proc.stdout[-3000:] + proc.stderr[-1000:], "junit": str(junit)}


@pytest.mark.parametrize("test_id", sorted(SUITES))
def test_ph3_kit_suite_passes(test_id, record_result):
    r = run_suite(test_id, SUITES[test_id])
    m = r["metrics"]
    notes = f"{SUITES[test_id]}: {m['passed']} passed, {m['failed']} failed, {m['skipped']} skipped"
    record_result(test_id, "pass" if r["ok"] else "fail", metrics=m, notes=notes, artifacts=[r["junit"]])
    assert r["ok"], r["output"]
