"""PH3-10 (R4, P1): the graph schema matches Eqs. (38)-(48). PH3-11 (R4, P1): two images that share
packages do not mix SBOMs (M4). Test Plan §3.3. Integration: needs Neo4j (`make up` starts it) and
the neo4j Python package; without them the tests skip.

Each test loads its images under digests made for the test ("sha256:" + a random hex), so counting
is exact even in the demo's graph, and deletes them afterwards. File and Package nodes are shared by
design (keyed by path and sha256, and by purl), so only the test's own edges are counted.

- PH3-10: the envelope (PROVBIND_ENVELOPE, with its SBOM in PROVBIND_SBOM; otherwise the golden
  envelope and the compile tests' SBOM, not_run) is loaded with alerts.attribute. Pass: 1 Image;
  CONTAINS = layers; INTRODUCES and File = files with a layer; DECLARES = packages; OWNS = files
  with a package; DEPENDS_ON (tagged with the image) = the SBOM's edges.
- PH3-11: image A has requests -> urllib3; image B shares both packages but reaches urllib3 from
  pip. Pass: A's urllib3 path uses only A's edges ([requests, urllib3]), and an unscoped query
  would have crossed into B's edge (which is M4, and why DEPENDS_ON carries the digest).
  With PROVBIND_ENVELOPE/PROVBIND_SBOM and PROVBIND_DEMO_ENVELOPE/PROVBIND_DEMO_SBOM (the stand-in
  and the demo) the two real images are loaded instead and the result is pass or fail.
"""
import copy
import json
import os
import secrets
from pathlib import Path

import pytest

from alerts.attribute import Attributor, sbom_graph
from compiler.tests.test_compile import PURL, SBOM

from tests.alerts.helpers import golden

pytestmark = pytest.mark.integration


def load_sbom(path):
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return doc["predicate"] if "bomFormat" not in doc and isinstance(doc.get("predicate"), dict) else doc


@pytest.fixture
def neo4j():
    pytest.importorskip("neo4j")
    a = Attributor(use_neo4j=True)
    if a.driver is None:
        pytest.skip(f"Neo4j is not reachable at {a.uri} (make up starts it)")
    made = []
    yield a, made
    with a.driver.session() as s:
        for digest, layers in made:
            s.run("MATCH ()-[e:DEPENDS_ON {image: $d}]->() DELETE e", d=digest)
            s.run("MATCH (i:Image {digest: $d}) DETACH DELETE i", d=digest)
            s.run("MATCH (l:Layer) WHERE l.digest IN $ls DETACH DELETE l", ls=layers)
        s.run("MATCH (n) WHERE (n:File OR n:Package) AND NOT (n)--() DELETE n")
    a.driver.close()


def isolated(env, made):
    """A copy of the envelope under digests made for this test."""
    env = copy.deepcopy(env)
    tag = secrets.token_hex(4)
    env["image"]["digest"] = "sha256:" + secrets.token_hex(32)
    for layer in env["layers"]:
        layer["digest"] = f"sha256:test{tag}{layer['digest'].split(':')[1][12:]}"
    made.append((env["image"]["digest"], [l["digest"] for l in env["layers"]]))
    return env


def count(a, query, digest):
    with a.driver.session() as s:
        return s.run(query, d=digest).single()["n"]


def test_ph3_10_graph_counts_equal_the_envelope(neo4j, record_result):
    a, made = neo4j
    real = bool(os.environ.get("PROVBIND_ENVELOPE") and os.environ.get("PROVBIND_SBOM"))
    env = json.loads(Path(os.environ["PROVBIND_ENVELOPE"]).read_text()) if real else golden()
    bom = load_sbom(os.environ["PROVBIND_SBOM"]) if real else SBOM
    env, graph = isolated(env, made), sbom_graph(bom)
    assert a.ensure_loaded(env, graph)
    d = env["image"]["digest"]
    by_index = {l["index"] for l in env["layers"]}
    with_layer = [m for m in env["files"].values() if m.get("layer") in by_index]
    purls = set(env["packages"]) | {p for s, ts in graph["edges"].items() for p in [s, *ts]}
    want = {"Image": 1, "CONTAINS": len({l["digest"] for l in env["layers"]}),
            "File": len({(p, m["sha256"]) for p, m in env["files"].items() if m.get("layer") in by_index}),
            "INTRODUCES": len(with_layer), "DECLARES": len(purls),
            "OWNS": sum(1 for m in with_layer if m.get("package")),
            "DEPENDS_ON": sum(len(ts) for ts in graph["edges"].values())}
    got = {"Image": count(a, "MATCH (i:Image {digest: $d}) RETURN count(i) AS n", d),
           "CONTAINS": count(a, "MATCH (:Image {digest: $d})-[c:CONTAINS]->() RETURN count(c) AS n", d),
           "File": count(a, "MATCH (:Image {digest: $d})-[:CONTAINS]->()-[:INTRODUCES]->(f) RETURN count(DISTINCT f) AS n", d),
           "INTRODUCES": count(a, "MATCH (:Image {digest: $d})-[:CONTAINS]->()-[r:INTRODUCES]->() RETURN count(r) AS n", d),
           "DECLARES": count(a, "MATCH (:Image {digest: $d})-[r:DECLARES]->() RETURN count(r) AS n", d),
           "OWNS": count(a, "MATCH (i:Image {digest: $d})-[:DECLARES]->(:Package)-[o:OWNS]->(f:File)"
                            "<-[:INTRODUCES]-(:Layer)<-[:CONTAINS]-(i) RETURN count(DISTINCT o) AS n", d),
           "DEPENDS_ON": count(a, "MATCH ()-[e:DEPENDS_ON {image: $d}]->() RETURN count(e) AS n", d)}
    ok = got == want
    notes = (f"{'the envelope ' + os.environ['PROVBIND_ENVELOPE'] if real else 'the golden envelope'} loaded under a "
             f"test digest: counts {got}" + ("" if ok else f", expected {want}"))
    status = ("pass" if ok else "fail") if real else ("not_run" if ok else "fail")
    if not real:
        notes += "; synthetic, so set PROVBIND_ENVELOPE and PROVBIND_SBOM to the demo's"
    record_result("PH3-10", status, metrics={"graph": got, "envelope": want}, notes=notes)
    assert ok, notes


def two_images(made):
    """(A, graph A, B, graph B, file of A owned by urllib3): real if all four variables are set."""
    names = ("PROVBIND_ENVELOPE", "PROVBIND_SBOM", "PROVBIND_DEMO_ENVELOPE", "PROVBIND_DEMO_SBOM")
    if all(os.environ.get(n) for n in names):
        b_env, b_bom, a_env, a_bom = (json.loads(Path(os.environ[n]).read_text()) if "ENVELOPE" in n
                                      else load_sbom(os.environ[n]) for n in names)
        a_env, b_env = isolated(a_env, made), isolated(b_env, made)
        return a_env, sbom_graph(a_bom), b_env, sbom_graph(b_bom), True
    a_env, b_env = isolated(golden(), made), isolated(golden(), made)
    a_graph = sbom_graph(SBOM)
    b_graph = {"roots": sorted({PURL["pip"], PURL["coreutils"], PURL["dash"]}),
               "edges": {PURL["pip"]: [PURL["urllib3"]], PURL["coreutils"]: [PURL["libc6"]],
                         PURL["dash"]: [PURL["libc6"]]}}
    return a_env, a_graph, b_env, b_graph, False


def test_ph3_11_images_sharing_packages_do_not_mix_sboms(neo4j, record_result):
    a, made = neo4j
    a_env, a_graph, b_env, b_graph, real = two_images(made)
    assert a.ensure_loaded(b_env, b_graph) and a.ensure_loaded(a_env, a_graph)
    target = next(m["package"] for m in a_env["files"].values()
                  if str(m.get("package") or "").startswith("pkg:pypi/urllib3@"))
    da, db = a_env["image"]["digest"], b_env["image"]["digest"]
    path = a.dependency_path(a_env, a_graph, da, target)
    with a.driver.session() as s:
        edges = s.run("MATCH (x:Package)-[e:DEPENDS_ON]->(y:Package) WHERE x.purl IN $p AND y.purl IN $p "
                      "RETURN x.purl AS x, y.purl AS y, e.image AS image", p=path or []).data()
        crossing = s.run("MATCH (r:Package)-[e:DEPENDS_ON]->(:Package {purl: $t}) WHERE e.image = $b "
                         "RETURN count(e) AS n", t=target, b=db).single()["n"]
    used = {(e["x"], e["y"]) for e in edges if e["image"] == da}
    steps = set(zip(path or [], (path or [])[1:]))
    ok =bool(path) and steps <= used and path[-1] == target and (real or path == [PURL["requests"], PURL["urllib3"]])
    notes = (f"{'stand-in and demo' if real else 'two images sharing requests, pip and urllib3'}: image A's urllib3 path "
             f"{path}, every step tagged with A's digest; image B has {crossing} edge(s) into urllib3 that an unscoped "
             f"query could have used (M4)")
    status = ("pass" if ok else "fail") if real else ("not_run" if ok else "fail")
    if not real:
        notes += "; synthetic, so set PROVBIND_ENVELOPE/_SBOM (stand-in) and PROVBIND_DEMO_ENVELOPE/_SBOM (demo)"
    record_result("PH3-11", status, metrics={"path": path, "b_edges_into_target": crossing}, notes=notes)
    assert ok, notes
