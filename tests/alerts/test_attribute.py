"""alerts/attribute.py: SBOM edges, the dependency path, Neo4j loading and reconnecting (PH5-07, M4).

Neo4j itself is not needed: a fake driver records the Cypher it is sent. The graph's real
behaviour is PH3-10 and PH3-11 (tests/capability/test_ph3_10_11_graph.py, integration).
"""
import json
import os
import sys
import types

from alerts import attribute
from alerts.attribute import (DEPENDENCY_PATH, IS_ROOT, LAYER_PATH, LOAD_DEPENDS, LOAD_PACKAGES, Attributor,
                              bfs_path, load_graph, load_run, sbom_graph)
from alerts.run import AlertEngine
from compiler.tests.test_compile import PURL, SBOM

from tests.alerts.helpers import detection, golden, read_jsonl, write_detections, write_run

URLLIB3_FILE = "/usr/local/lib/python3.11/site-packages/urllib3-2.2.2.dist-info/METADATA"


class FakeDriver:
    def __init__(self, answers=None):
        self.calls, self.fail, self.answers = [], False, answers or {}

    def session(self):
        return FakeSession(self)

    def verify_connectivity(self):
        pass

    def close(self):
        pass


class FakeSession:
    def __init__(self, driver):
        self.driver = driver

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        self.driver.calls.append((query, params))
        if self.driver.fail:
            raise ConnectionError("Neo4j went away")
        return types.SimpleNamespace(single=lambda: self.driver.answers.get(query))


def graph():
    return sbom_graph(SBOM)


def test_sbom_graph_keys_edges_by_purl():
    g = graph()
    assert g["edges"][PURL["requests"]] == [PURL["urllib3"]]
    assert set(g["roots"]) == {PURL["requests"], PURL["coreutils"], PURL["dash"]}
    assert PURL["urllib3"] not in g["roots"] and PURL["pip"] not in g["edges"]       # pip is in no edge


def test_components_without_a_purl_are_left_out():
    bom = {"components": [{"bom-ref": "a", "purl": "pkg:pypi/a@1"}, {"bom-ref": "b", "name": "cli-64.exe"}],
           "dependencies": [{"ref": "a", "dependsOn": ["b"]}]}
    assert sbom_graph(bom) == {"roots": ["pkg:pypi/a@1"], "edges": {}}


def test_bfs_path_from_the_root_to_the_package():             # PH5-07's shape
    g = graph()
    assert bfs_path(g, PURL["urllib3"]) == [PURL["requests"], PURL["urllib3"]]
    assert bfs_path(g, PURL["requests"]) == [PURL["requests"]]
    assert bfs_path(g, PURL["pip"]) is None and bfs_path(None, PURL["urllib3"]) is None


def test_without_neo4j_the_dependency_path_comes_from_the_stored_edges():
    a = Attributor(use_neo4j=False)
    env = golden()
    assert a.dependency_path(env, graph(), env["image"]["digest"], PURL["urllib3"]) == [PURL["requests"], PURL["urllib3"]]
    assert a.dependency_path(env, None, env["image"]["digest"], PURL["urllib3"]) is None


def test_the_load_scopes_every_dependency_edge_to_its_image():              # M4, PH3-11
    drv = FakeDriver()
    a = Attributor(driver=drv)
    env = golden()
    assert a.ensure_loaded(env, graph())
    depends = [p for q, p in drv.calls if q == LOAD_DEPENDS]
    assert depends and all(p["digest"] == env["image"]["digest"] for p in depends)
    assert {"src": PURL["requests"], "dst": PURL["urllib3"]} in depends[0]["edges"]
    (pkgs,) = [p["packages"] for q, p in drv.calls if q == LOAD_PACKAGES]
    roots = {p["purl"] for p in pkgs if p["root"]}
    assert roots == {PURL["requests"], PURL["coreutils"], PURL["dash"]}
    n = len(drv.calls)
    assert a.ensure_loaded(env, graph()) and len(drv.calls) == n            # once per digest


def test_edges_that_arrive_later_are_still_loaded():
    drv = FakeDriver()
    a = Attributor(driver=drv)
    env = golden()
    a.ensure_loaded(env)                                                     # a layer query came first
    assert not [q for q, _ in drv.calls if q == LOAD_DEPENDS]
    a.ensure_loaded(env, graph())
    assert [q for q, _ in drv.calls if q == LOAD_DEPENDS]


def test_the_dependency_query_is_scoped_to_the_image():
    env = golden()
    drv = FakeDriver({IS_ROOT: {"n": 0}, DEPENDENCY_PATH: {"path": [PURL["requests"], PURL["urllib3"]]}})
    a = Attributor(driver=drv)
    assert a.dependency_path(env, graph(), env["image"]["digest"], PURL["urllib3"]) == [PURL["requests"], PURL["urllib3"]]
    (params,) = [p for q, p in drv.calls if q == DEPENDENCY_PATH]
    assert params == {"digest": env["image"]["digest"], "purl": PURL["urllib3"]}
    assert "e.image = $digest" in DEPENDENCY_PATH


def test_a_lost_connection_falls_back_to_the_envelope(monkeypatch):
    env = golden()
    drv = FakeDriver({LAYER_PATH: {"layer": "sha256:graph", "idx": 9}})
    a = Attributor(driver=drv)
    assert a.layer_of(env, env["image"]["digest"], "/usr/bin/ls") == ("sha256:graph", 9)
    drv.fail = True
    a.loaded.clear()
    monkeypatch.setattr(a, "connected", lambda: a.driver is not None)       # no reconnect in this test
    layer = env["layers"][env["files"]["/usr/bin/ls"]["layer"]]["digest"]
    assert a.layer_of(env, env["image"]["digest"], "/usr/bin/ls")[0] == layer
    assert a.driver is None                                                   # dropped; retried later


def test_the_connection_is_retried(monkeypatch):
    attempts = []

    class GraphDatabase:
        @staticmethod
        def driver(uri, auth, connection_timeout):
            attempts.append(uri)
            if len(attempts) == 1:
                raise OSError("Neo4j is still starting")
            return FakeDriver()

    monkeypatch.setitem(sys.modules, "neo4j", types.SimpleNamespace(GraphDatabase=GraphDatabase))
    clock = [1000.0]
    monkeypatch.setattr(attribute.time, "monotonic", lambda: clock[0])
    a = Attributor(use_neo4j=True)
    assert a.driver is None and len(attempts) == 1
    assert not a.connected() and len(attempts) == 1                         # not before RETRY_S
    clock[0] += attribute.RETRY_S + 1
    assert a.connected() and len(attempts) == 2


def test_without_the_neo4j_package_it_stops_trying(monkeypatch):
    monkeypatch.setitem(sys.modules, "neo4j", None)
    a = Attributor(use_neo4j=True)
    assert not a.enabled and not a.connected()


def test_load_run_loads_each_envelope_once_and_again_when_recompiled(tmp_path):
    env = golden()
    run = write_run(tmp_path, env)
    drv = FakeDriver()
    a = Attributor(driver=drv)
    done = {}
    assert load_run(run, a, done) == [env["image"]["digest"]]
    assert load_run(run, a, done) == []
    path = run / "envelopes" / f"{env['image']['digest'].split(':')[1]}.json"
    path.write_text(json.dumps(env) + "\n")
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    assert load_run(run, a, done) == [env["image"]["digest"]]


def test_the_alert_engine_loads_envelopes_before_any_alert(tmp_path):      # demo step 1
    env = golden()
    run = write_run(tmp_path, env)
    drv = FakeDriver()
    engine = AlertEngine(run, attributor=Attributor(driver=drv))
    engine.run_loop(once=True)                                               # no detections.jsonl yet
    assert env["image"]["digest"] in engine.attributor.loaded


def test_alerts_carry_the_dependency_path(tmp_path):                        # PH5-07
    env = golden()
    run = write_run(tmp_path, env)
    digest = env["image"]["digest"]
    (run / "contexts").mkdir()
    (run / "contexts" / f"{digest.split(':')[1]}.sbom.json").write_text(json.dumps({"digest": digest, **graph()}))
    assert load_graph(run, digest)["edges"]
    write_detections(run, [detection(env, 1, "D_write", "declared_file", URLLIB3_FILE, exe="/tmp/.x9")])
    AlertEngine(run, attributor=Attributor(use_neo4j=False)).run_loop(once=True)
    (a,) = read_jsonl(run / "alerts.jsonl")
    assert a["attribution"]["package"] == PURL["urllib3"] and a["attribution"]["depth"] == 2
    assert a["attribution"]["dependency_path"] == [PURL["requests"], PURL["urllib3"]]


def test_the_cli_says_when_neo4j_is_not_there(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PROVBIND_NEO4J", "off")
    run = write_run(tmp_path, golden())
    assert attribute.main(["--run", str(run)]) == 3
    assert json.loads(capsys.readouterr().out) == {"neo4j": False, "loaded": []}
