"""PH3-08: every expectation carries an origin (Eq. 36) (Test Plan §3.3). Scan the envelope.

Pass: every capability has an origin label, and the file, package and closure sections come
only from verified evidence. That means:
- the `verification` block is all true;
- the envelope matches contracts/envelope.schema.json;
- those sections agree with each other: every closure path is a file, and every file's layer
  and package are in the envelope.

Envelope: PROVBIND_ENVELOPE; without it, the golden envelope of the compile tests, and the result
is not_run.
"""
import json
import os
from pathlib import Path

import jsonschema

from compiler.compile import validate

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "compiler" / "tests" / "golden" / "envelope.json"
CHECKS = ("v_sig", "v_M", "v_C", "v_B", "v_P")
ORIGINS = ("AUTHENTICATED", "INFERRED", "CONFIGURED")


def scan(env: dict) -> dict:
    """What PH3-08 counts in one envelope."""
    try:
        validate(env)
        schema_errors = 0
    except jsonschema.ValidationError:
        schema_errors = 1
    layers = {entry["index"] for entry in env.get("layers", ())}
    files, packages, caps = env.get("files", {}), env.get("packages", {}), env.get("capabilities", [])
    verification = env.get("verification") or {}
    return {"capabilities": len(caps),
            "capabilities_without_origin": sum(c.get("origin") not in ORIGINS for c in caps),
            "verification_all_true": all(verification.get(k) is True for k in CHECKS),
            "schema_errors": schema_errors,
            "files": len(files),
            "closure_not_in_files": sum(p not in files for p in env.get("closure", ())),
            "files_with_unknown_layer": sum(f.get("layer") not in layers for f in files.values()),
            "files_with_unknown_package": sum(f.get("package") is not None and f["package"] not in packages
                                              for f in files.values())}


def test_ph3_08_every_expectation_carries_an_origin(record_result):
    path = os.environ.get("PROVBIND_ENVELOPE")
    env = json.loads(Path(path or GOLDEN).read_text(encoding="utf-8"))
    m = scan(env)
    problems = [k for k in ("capabilities_without_origin", "schema_errors", "closure_not_in_files",
                            "files_with_unknown_layer", "files_with_unknown_package") if m[k]]
    if not m["verification_all_true"]:
        problems.append("verification block not all true")
    ok = not problems
    status = "pass" if ok and path else ("fail" if not ok else "not_run")
    notes = f"envelope {path or GOLDEN.relative_to(ROOT)}"
    notes += f"; problems: {', '.join(problems)}" if problems else ""
    if status == "not_run":
        notes += "; the golden envelope is synthetic, so set PROVBIND_ENVELOPE for the real test"
    if m["capabilities"] == 0:
        notes += "; the envelope has no capabilities, so the origin check had nothing to check"
    record_result("PH3-08", status, metrics=m, notes=notes, artifacts=[path] if path else [])
    assert ok, notes
