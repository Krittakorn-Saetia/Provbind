"""PH2-06 and PH2-07: the compiler's integrity and binding checks (Test Plan §3.2).

Unit tests on the compile tests' synthetic image, run through the real CLI with a fake registry and a
fake cosign, so they count without a real image, like PH3-01.

- PH2-06 (Eq. 15): v_M catches a changed manifest. Pass: a manifest, or the platform manifest inside
  an image index, whose bytes don't hash to the signed digest makes the compiler exit 2 and write
  nothing; and the T4 unit tests (compiler/tests/test_oci.py) pass.
- PH2-07 (Eqs. 17-18): v_B and v_P catch evidence bound to another image. Pass: an SBOM or a
  provenance statement whose subject is not d_I makes the compiler exit 2 (EvidenceError) and write
  nothing; and the T3 unit tests (compiler/tests/test_evidence.py) pass.

An untampered run of the same image must exit 0 and write its envelope, so a pass can't come from a
harness that fails on everything.
"""
from compiler.compile import EXIT_EVIDENCE, EXIT_OK, main
from compiler.tests.helpers import FakeCosign, FakeRegistry
from compiler.tests.test_compile import PROVENANCE, REPO, SBOM, push_synthetic

from .test_ph3_01_02_06_kit import run_suite

AMD64 = {"os": "linux", "architecture": "amd64"}
OTHER = "sha256:" + "cd" * 32


def compile_once(tmp_path, name, reg, ref, cosign, capsys) -> dict:
    """Run the CLI once: its exit code, the envelopes it wrote, and what it logged."""
    run = tmp_path / name
    code = main([ref, "--run", str(run), "--key", str(tmp_path / "cosign.pub")], crane=reg, cosign=cosign)
    written = sorted(p.name for p in (run / "envelopes").glob("*.json")) if (run / "envelopes").exists() else []
    return {"exit": code, "written": written, "log": capsys.readouterr().err}


def refused(result: dict, check: str) -> bool:
    """Exit 2, nothing written, and the log names the check that failed."""
    return result["exit"] == EXIT_EVIDENCE and not result["written"] and check in result["log"]


def record(record_result, test_id, kit, cases, control):
    ok_cases = [name for name, good in cases.items() if good]
    ok = kit["ok"] and len(ok_cases) == len(cases) and control
    notes = (f"synthetic image through the CLI: {len(ok_cases)} of {len(cases)} tampered cases exit 2 and write "
             f"nothing ({', '.join(cases)}); untampered control {'exits 0' if control else 'FAILED'}; "
             f"{kit['metrics']['passed']} unit tests passed, {kit['metrics']['failed']} failed")
    if not ok:
        notes += "; failed: " + ", ".join([n for n, good in cases.items() if not good] + ([] if control else ["control"])
                                          + ([] if kit["ok"] else ["unit tests"]))
    record_result(test_id, "pass" if ok else "fail",
                  metrics={"cases": len(cases), "refused": len(ok_cases), "control_ok": control,
                           "unit_tests_passed": kit["metrics"]["passed"], "unit_tests_failed": kit["metrics"]["failed"]},
                  notes=notes, artifacts=[kit["junit"]])
    assert ok, notes + "\n" + kit["output"]


def test_ph2_06_v_m_catches_a_changed_manifest(tmp_path, capsys, record_result):
    kit = run_suite("PH2-06", "compiler/tests/test_oci.py")

    reg = FakeRegistry()
    digest = push_synthetic(reg)
    control = compile_once(tmp_path, "control", reg, f"{REPO}@{digest}", FakeCosign(digest, SBOM, PROVENANCE), capsys)
    control_ok = control["exit"] == EXIT_OK and control["written"] == [f"{digest.split(':')[1]}.json"]

    cases = {}
    reg = FakeRegistry()                               # the manifest's bytes change; the signed digest doesn't
    digest = push_synthetic(reg)
    reg.manifests[digest] += b" "
    cases["manifest"] = refused(compile_once(tmp_path, "manifest", reg, f"{REPO}@{digest}",
                                             FakeCosign(digest, SBOM, PROVENANCE), capsys), "v_M: manifest")

    reg = FakeRegistry()                               # the same inside an image index
    digest = push_synthetic(reg)
    index = reg.push_index([(digest, AMD64, None)])
    reg.manifests[digest] += b" "
    cases["platform manifest in an index"] = refused(
        compile_once(tmp_path, "platform", reg, f"{REPO}@{index}", FakeCosign(index, SBOM, PROVENANCE), capsys),
        "v_M: platform manifest")

    record(record_result, "PH2-06", kit, cases, control_ok)


def test_ph2_07_v_b_and_v_p_catch_evidence_for_another_image(tmp_path, capsys, record_result):
    kit = run_suite("PH2-07", "compiler/tests/test_evidence.py")
    reg = FakeRegistry()
    digest = push_synthetic(reg)
    ref = f"{REPO}@{digest}"
    other = FakeCosign(OTHER, SBOM, PROVENANCE)        # statements whose subject is another image

    control = compile_once(tmp_path, "control", reg, ref, FakeCosign(digest, SBOM, PROVENANCE), capsys)
    control_ok = control["exit"] == EXIT_OK and control["written"] == [f"{digest.split(':')[1]}.json"]

    cases = {}
    for name, swap, check in (("SBOM for another image", ("cyclonedx",), "v_B"),
                              ("provenance for another image", ("slsaprovenance1",), "v_P"),
                              ("both for another image", ("cyclonedx", "slsaprovenance1"), "v_B")):
        cosign = FakeCosign(digest, SBOM, PROVENANCE)
        for predicate in swap:
            cosign.out[predicate] = other.out[predicate]
        cases[name] = refused(compile_once(tmp_path, name.replace(" ", "-"), reg, ref, cosign, capsys), check)

    record(record_result, "PH2-07", kit, cases, control_ok)
