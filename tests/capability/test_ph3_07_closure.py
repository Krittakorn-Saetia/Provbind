"""PH3-07: the execution closure 𝒬_I (Eq. 31) (Test Plan §3.3). Pass: the T7 unit tests pass, and in
the stand-in's envelope the closure holds python, libpython and libc, while ls and dash, which the
image has, are not in it.

The envelope is PROVBIND_ENVELOPE, the stand-in's as the CLI writes it (handoff T12 step 3). Without
it, the golden envelope of the compile tests stands in and the result is not_run. The T7 integration
test (compiler/tests/test_standin_integration.py) checks the same thing on the PC but records no
result; this test records it.
"""
import json
import os
import posixpath
import re
from pathlib import Path

from .test_ph3_01_02_06_kit import run_suite

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "compiler" / "tests" / "golden" / "envelope.json"
MUST_BE_IN = {                                   # by file name; closure paths are real paths
    "python": re.compile(r"^python3(\.\d+)?$"),
    "libpython": re.compile(r"^libpython3\.\d+\.so(\.[\d.]+)?$"),
    "libc": re.compile(r"^(libc\.so\.6|libc\.musl-.+\.so\.1|ld-musl-.+\.so\.1)$"),
}
MUST_BE_OUT = ("ls", "dash")


def scan(env: dict) -> dict:
    """What PH3-07 looks for in one envelope's closure and files."""
    closure, files = env.get("closure") or [], env.get("files") or {}
    return {"closure": len(closure),
            "found": {k: sorted(p for p in closure if rx.match(posixpath.basename(p))) for k, rx in MUST_BE_IN.items()},
            "wrongly_in": sorted(p for p in closure if posixpath.basename(p) in MUST_BE_OUT),
            "in_image": {n: sorted(p for p in files if posixpath.basename(p) == n) for n in MUST_BE_OUT}}


def test_ph3_07_execution_closure(record_result):
    kit = run_suite("PH3-07", "compiler/tests/test_closure.py")
    path = os.environ.get("PROVBIND_ENVELOPE")
    env = json.loads(Path(path or GOLDEN).read_text(encoding="utf-8"))
    s = scan(env)
    missing = [k for k, paths in s["found"].items() if not paths]
    ok = kit["ok"] and not missing and not s["wrongly_in"]
    status = "pass" if ok and path else ("fail" if not ok else "not_run")
    notes = f"envelope {path or GOLDEN.relative_to(ROOT)}; closure of {s['closure']}"
    notes += f"; T7 unit tests: {kit['metrics']['passed']} passed, {kit['metrics']['failed']} failed"
    if missing:
        notes += f"; not in the closure: {', '.join(missing)}"
    if s["wrongly_in"]:
        notes += f"; in the closure but should not be: {', '.join(s['wrongly_in'])}"
    absent = [n for n, paths in s["in_image"].items() if not paths]
    if absent:
        notes += f"; the image has no {' or '.join(absent)}, so keeping it out checks nothing"
    if status == "not_run":
        notes += "; the golden envelope is synthetic, so set PROVBIND_ENVELOPE to the stand-in's for the real test"
    record_result("PH3-07", status,
                  metrics={"python": s["found"]["python"], "libpython": s["found"]["libpython"],
                           "libc": s["found"]["libc"], "ls_or_dash_in_closure": s["wrongly_in"],
                           "closure": s["closure"], "ls_in_image": bool(s["in_image"]["ls"]),
                           "dash_in_image": bool(s["in_image"]["dash"]),
                           "unit_tests_passed": kit["metrics"]["passed"], "unit_tests_failed": kit["metrics"]["failed"]},
                  notes=notes, artifacts=[kit["junit"]] + ([path] if path else []))
    assert ok, notes + "\n" + kit["output"]
