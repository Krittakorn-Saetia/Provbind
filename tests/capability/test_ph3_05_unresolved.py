"""PH3-05: packages without dependency edges are marked unresolved, never ⊥ (M16) (Test Plan §3.3).

syft's edges are incomplete, so a package that appears in no dependency edge says nothing about where
it sits. The compiler gives it depth null (compiler/sbom.py), never a number that would make it look
like a top-level package. Pass: every package whose SBOM components are all in no edge has a null
depth in the envelope. unresolved_fraction is recorded with it.

Inputs: the envelope (PROVBIND_ENVELOPE) and the SBOM it was compiled from (PROVBIND_SBOM: the
CycloneDX document, or an in-toto statement holding one, such as run/attest/<name>/sbom.json). The
envelope's packages must equal compiler.sbom.depths of that SBOM; if they don't, the two don't belong
together and the result is blocked. With neither, the compile tests' synthetic SBOM and golden
envelope stand in, and the result is not_run.
"""
import json
import os
from pathlib import Path

from compiler.sbom import depths, package_components
from compiler.tests.test_compile import SBOM as SYNTHETIC_SBOM

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "compiler" / "tests" / "golden" / "envelope.json"


def load_sbom(path: str) -> dict:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if "bomFormat" not in doc and isinstance(doc.get("predicate"), dict):
        doc = doc["predicate"]
    return doc


def inputs():
    """(envelope, SBOM, where they came from, whether they are real)."""
    envelope, sbom = os.environ.get("PROVBIND_ENVELOPE"), os.environ.get("PROVBIND_SBOM")
    if envelope and sbom:
        return (json.loads(Path(envelope).read_text(encoding="utf-8")), load_sbom(sbom),
                f"envelope {envelope} with SBOM {sbom}", True)
    return (json.loads(GOLDEN.read_text(encoding="utf-8")), SYNTHETIC_SBOM,
            "golden envelope with the synthetic SBOM of compiler/tests/test_compile.py", False)


def in_an_edge(bom: dict) -> set[str]:
    """bom-refs at either end of at least one dependency edge."""
    refs = set()
    for d in bom.get("dependencies") or ():
        targets = [t for t in d.get("dependsOn") or () if t]
        if d.get("ref") and targets:
            refs.add(d["ref"])
            refs.update(targets)
    return refs


def scan(env: dict, bom: dict) -> dict:
    """Envelope keys whose every component is in no edge, and their depths. The keys follow
    compiler.sbom.package_components (a purl; a component without one was keyed by its bom-ref until
    29 September 2026, and has no key since). A key with any component in an edge may get a depth through
    it, so it doesn't count."""
    edges = in_an_edge(bom)
    with_edges, without = set(), set()
    for c in package_components(bom):
        key = c.get("purl") or c.get("bom-ref")
        if key:
            (with_edges if c.get("bom-ref") in edges else without).add(key)
    no_edges = without - with_edges
    packages = env.get("packages") or {}
    return {"no_edges": sorted(no_edges),
            "with_a_number": sorted(k for k in no_edges if (packages.get(k) or {}).get("depth") is not None),
            "missing": sorted(k for k in no_edges if k not in packages),
            "null_depths": sum(1 for v in packages.values() if v.get("depth") is None),
            "packages": len(packages)}


def test_ph3_05_packages_without_edges_are_unresolved(record_result):
    env, bom, source, real = inputs()
    s = scan(env, bom)
    belongs = depths(bom)[0] == env.get("packages")
    metrics = {"packages_without_edges": len(s["no_edges"]), "with_a_number": len(s["with_a_number"]),
               "unresolved_fraction": env.get("unresolved_fraction"), "packages": s["packages"],
               "null_depths": s["null_depths"], "missing_from_envelope": len(s["missing"]),
               "sbom_matches_envelope": belongs}
    notes = (f"{source}: {len(s['no_edges'])} of {s['packages']} packages are in no dependency edge; "
             f"{len(s['with_a_number'])} of them have a depth; unresolved_fraction {env.get('unresolved_fraction')}")
    ok = not s["with_a_number"] and not s["missing"]
    if s["with_a_number"]:
        notes += "; given a depth: " + ", ".join(s["with_a_number"][:5])
    if s["missing"]:
        notes += "; not in the envelope: " + ", ".join(s["missing"][:5])
    if not belongs:
        status = "blocked"
        notes += "; the envelope's packages don't match compiler.sbom.depths of this SBOM, so the two don't belong together"
    elif not real:
        status = "not_run"
        notes += "; synthetic, so set PROVBIND_ENVELOPE and PROVBIND_SBOM to the stand-in's for the real test"
    else:
        status = "pass" if ok else "fail"
    record_result("PH3-05", status, metrics=metrics, notes=notes,
                  artifacts=[p for p in (os.environ.get("PROVBIND_ENVELOPE"), os.environ.get("PROVBIND_SBOM")) if p])
    assert belongs and ok, notes
