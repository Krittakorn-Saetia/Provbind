"""PH5-07 (R4, P1): the dependency path (Eqs. 69-70) for a urllib3 file on the stand-in. Test Plan §3.8.

Pass: the alert's `attribution.dependency_path` runs from a root package through requests to
urllib3, and its length is urllib3's depth in the envelope.

The path comes from the SBOM's edges, which the controller stores at admission beside the
verification context (`contexts/<hex>.sbom.json`, alerts.attribute.sbom_graph). This test builds
that file from the SBOM the envelope was compiled from, then runs the alert engine on a D_write of a
urllib3 file.

Inputs: PROVBIND_ENVELOPE and PROVBIND_SBOM (the stand-in's envelope and run/attest/<name>/sbom.json,
as for PH3-04 and PH3-05). Without them, the golden envelope and the compile tests' synthetic SBOM
stand in, and the result is not_run.
"""
import json
import os
from pathlib import Path

from alerts.attribute import Attributor, sbom_graph
from alerts.run import AlertEngine
from compiler.tests.test_compile import SBOM as SYNTHETIC_SBOM

from tests.alerts.helpers import detection, golden, read_jsonl, write_detections, write_run


def load_sbom(path: str) -> dict:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if "bomFormat" not in doc and isinstance(doc.get("predicate"), dict):
        doc = doc["predicate"]
    return doc


def inputs():
    envelope, sbom = os.environ.get("PROVBIND_ENVELOPE"), os.environ.get("PROVBIND_SBOM")
    if envelope and sbom:
        return (json.loads(Path(envelope).read_text(encoding="utf-8")), load_sbom(sbom),
                f"envelope {envelope} with SBOM {sbom}", True)
    return golden(), SYNTHETIC_SBOM, "golden envelope with the synthetic SBOM of compiler/tests/test_compile.py", False


def test_ph5_07_dependency_path(tmp_path, record_result):
    env, bom, source, real = inputs()
    files = sorted(p for p, m in env["files"].items() if str(m.get("package") or "").startswith("pkg:pypi/urllib3@"))
    if not files:
        record_result("PH5-07", "blocked", notes=f"{source}: no file owned by urllib3 in the envelope")
        assert not real, "the stand-in has urllib3"
        return
    path = next((p for p in files if p.endswith("/__init__.py")), files[0])
    run = write_run(tmp_path, env)
    digest = env["image"]["digest"]
    (run / "contexts").mkdir()
    (run / "contexts" / f"{digest.split(':')[1]}.sbom.json").write_text(json.dumps({"digest": digest, **sbom_graph(bom)}))
    write_detections(run, [detection(env, 1, "D_write", "declared_file", path, exe="/tmp/.x9",
                                     detail="write to a file declared in the image")])
    AlertEngine(run, attributor=Attributor(use_neo4j=False)).run_loop(once=True)
    (alert,) = read_jsonl(run / "alerts.jsonl")
    a = alert["attribution"]
    dep = a.get("dependency_path") or []
    names = [p.split("/", 1)[1].split("@", 1)[0].lower() for p in dep]
    ok = (len(dep) >= 2 and names[-1] == "urllib3" and "requests" in names[:-1]
          and a.get("depth") == len(dep) and a.get("package") == dep[-1])
    notes = (f"{source}: D_write of {path}: dependency path {' -> '.join(['(root)'] + dep) if dep else 'none'}; "
             f"package {a.get('package')}, depth {a.get('depth')}")
    status = ("pass" if ok else "fail") if real else ("not_run" if ok else "fail")
    if not real:
        notes += "; synthetic, so set PROVBIND_ENVELOPE and PROVBIND_SBOM to the stand-in's"
    record_result("PH5-07", status, metrics={"dependency_path": dep, "depth": a.get("depth"), "file": path}, notes=notes,
                  artifacts=[p for p in (os.environ.get("PROVBIND_ENVELOPE"), os.environ.get("PROVBIND_SBOM")) if p and real])
    assert ok, notes
