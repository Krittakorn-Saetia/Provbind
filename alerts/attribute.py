"""Phase 5 Step 3: attribution (Sprint Handoff §8 "Neo4j load and layer query"; Eqs. 69-74).

    python -m alerts.attribute --run $PROVBIND_RUN [--watch]     # load every envelope into Neo4j

Two paths answer where a file came from:

- **The layer path** (Eqs. 71-72): which layer of this image introduced the file. Each envelope is
  loaded into Neo4j once, with the Cypher from the Sprint Handoff; the layer query then answers for
  display. When Neo4j is down or not installed, the answer comes from the envelope's own
  `files[path].layer` (the fallback §8 names). Both give the same answer: the envelope is the
  graph's source. An empty layer path is itself the finding: nothing signed ever claimed that file
  exists (PH5-08).
- **The dependency path** (Eqs. 69-70, PH5-07): root package -> ... -> the package that owns the
  file. It needs the SBOM's edges, which the envelope does not hold, so the controller stores them
  at admission beside the verification context, `contexts/<hex>.sbom.json` (`sbom_graph`). The
  path starts at a package with no incoming edge (depth 1; the application root at depth 0 is
  implicit, as in `compiler.sbom.depths`), so its length is the package's depth.

The graph is the draft's Fig. 2 at compile time: Image -CONTAINS-> Layer -INTRODUCES-> File, and
Package -OWNS-> File, Package -DEPENDS_ON-> Package. Two changes follow fail point M4 (Explanation
§6; Test Plan §10): Image -DECLARES-> Package carries the image's depth and root flag, and every
DEPENDS_ON edge carries the image digest, so two images that share a package never mix their SBOMs
(PH3-11). Package nodes are keyed by purl and shared, as File nodes are.

Neo4j is optional and never on the event path (M3): the connection is retried at most every
RETRY_S seconds, and alerts.run loads each new envelope as it appears, so the graph is there for
demo step 1 before any alert.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time
from collections import deque
from pathlib import Path

from .common import hex_of, load_envelope, load_json, logger

log = logger("attribute")

RETRY_S = 15
MAX_DEPTH = 8

LOAD_IMAGE = """
MERGE (i:Image {digest: $digest})
  SET i.builder_id = $builder_id, i.source_commit = $source_commit
WITH i
UNWIND $layers AS l
  MERGE (x:Layer {digest: l.digest})
  MERGE (i)-[c:CONTAINS]->(x) SET c.index = l.index
"""
LOAD_FILES = """
UNWIND $files AS f
  MATCH (x:Layer {digest: f.layer_digest})
  MERGE (fl:File {path: f.path, sha256: f.sha256})
  MERGE (x)-[:INTRODUCES]->(fl)
"""
LOAD_PACKAGES = """
MATCH (i:Image {digest: $digest})
UNWIND $packages AS p
  MERGE (pk:Package {purl: p.purl})
  MERGE (i)-[d:DECLARES]->(pk) SET d.depth = p.depth, d.root = p.root
"""
LOAD_OWNS = """
UNWIND $files AS f
  MATCH (pk:Package {purl: f.package})
  MATCH (fl:File {path: f.path, sha256: f.sha256})
  MERGE (pk)-[:OWNS]->(fl)
"""
LOAD_DEPENDS = """
UNWIND $edges AS e
  MATCH (a:Package {purl: e.src}), (b:Package {purl: e.dst})
  MERGE (a)-[:DEPENDS_ON {image: $digest}]->(b)
"""
LAYER_PATH = """
MATCH (:Image {digest: $digest})-[c:CONTAINS]->(l:Layer)-[:INTRODUCES]->(:File {path: $path})
RETURN l.digest AS layer, c.index AS idx ORDER BY idx DESC LIMIT 1
"""
IS_ROOT = """
MATCH (:Image {digest: $digest})-[:DECLARES {root: true}]->(:Package {purl: $purl})
RETURN count(*) AS n
"""
DEPENDENCY_PATH = """
MATCH (:Image {digest: $digest})-[:DECLARES {root: true}]->(r:Package)
MATCH (pk:Package {purl: $purl})
MATCH p = shortestPath((r)-[:DEPENDS_ON*1..%d]->(pk))
WHERE all(e IN relationships(p) WHERE e.image = $digest)
RETURN [n IN nodes(p) | n.purl] AS path
ORDER BY length(p), r.purl LIMIT 1
""" % MAX_DEPTH


# --- the SBOM's edges ------------------------------------------------------------------------------------

def sbom_graph(bom: dict | None) -> dict:
    """{"roots": [purl], "edges": {purl: [purl]}} from a CycloneDX BOM, keyed by purl as the envelope's
    packages are. Components without a purl are left out, as `compiler.sbom.package_components` does;
    roots are the packages with outgoing edges and no incoming one, as in `compiler.sbom.depths`."""
    purl_of: dict[str, str] = {}

    def walk(components):
        for c in components or ():
            if c.get("bom-ref") and c.get("purl"):
                purl_of[c["bom-ref"]] = c["purl"]
            walk(c.get("components"))
    walk((bom or {}).get("components"))
    raw: dict[str, list[str]] = {}
    for d in (bom or {}).get("dependencies") or ():
        if d.get("ref"):
            raw.setdefault(d["ref"], []).extend(d.get("dependsOn") or ())
    has_in = {t for targets in raw.values() for t in targets}
    edges: dict[str, set[str]] = {}
    for ref, targets in raw.items():
        src = purl_of.get(ref)
        if src:
            dst = {purl_of[t] for t in targets if t in purl_of and purl_of[t] != src}
            if dst:
                edges.setdefault(src, set()).update(dst)
    roots = sorted({purl_of[r] for r, t in raw.items() if t and r not in has_in and r in purl_of})
    return {"roots": roots, "edges": {k: sorted(v) for k, v in sorted(edges.items())}}


def graph_path(run: str | Path, digest: str) -> Path:
    return Path(run) / "contexts" / f"{hex_of(digest)}.sbom.json"


def load_graph(run: str | Path, digest: str | None) -> dict | None:
    if not digest:
        return None
    doc = load_json(graph_path(run, digest))
    return doc if isinstance(doc, dict) and isinstance(doc.get("edges"), dict) else None


def bfs_path(graph: dict | None, purl: str | None) -> list[str] | None:
    """The shortest path from a root to `purl` over the stored edges (ties: roots and edges in
    sorted order), or None when no root reaches it."""
    if not graph or not purl:
        return None
    edges = graph.get("edges") or {}
    roots = sorted(graph.get("roots") or [])
    prev: dict[str, str | None] = {r: None for r in roots}
    depth = {r: 1 for r in roots}
    queue = deque(roots)
    while queue:
        u = queue.popleft()
        if u == purl:
            path = [u]
            while prev[path[-1]] is not None:
                path.append(prev[path[-1]])
            return path[::-1]
        if depth[u] > MAX_DEPTH:                     # the graph query's DEPENDS_ON*1..MAX_DEPTH
            continue
        for v in sorted(edges.get(u) or ()):
            if v not in prev:
                prev[v], depth[v] = u, depth[u] + 1
                queue.append(v)
    return None


# --- Neo4j ---------------------------------------------------------------------------------------------------

class Attributor:
    def __init__(self, uri: str | None = None, user: str = "neo4j", password: str | None = None,
                 use_neo4j: bool | None = None, driver=None):
        self.driver = driver
        self.loaded: set[str] = set()                   # digests in the graph
        self.with_edges: set[str] = set()               # ... with their SBOM edges too
        if use_neo4j is None:
            use_neo4j = os.environ.get("PROVBIND_NEO4J", "on") != "off"
        self.enabled = bool(use_neo4j) or driver is not None
        self.uri = uri or os.environ.get("PROVBIND_NEO4J_URI", "bolt://localhost:7687")
        self.user = user
        self.password = password or os.environ.get("PROVBIND_NEO4J_PASSWORD", "provbind-demo")
        self._next_try = 0.0
        if self.driver is None and self.enabled:
            self.connected()

    def connected(self) -> bool:
        """True when a driver is ready; otherwise try to connect, at most every RETRY_S seconds."""
        if self.driver is not None:
            return True
        if not self.enabled or time.monotonic() < self._next_try:
            return False
        self._next_try = time.monotonic() + RETRY_S
        try:
            from neo4j import GraphDatabase
        except ImportError:
            self.enabled = False                    # it will not appear while we run
            log.info("the neo4j package is not installed; layer paths come from the envelope")
            return False
        try:
            driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password), connection_timeout=3)
            driver.verify_connectivity()
        except Exception as e:                     # not running yet, wrong password
            log.info("Neo4j at %s unavailable (%s); retrying in %d s, using the envelope meanwhile",
                     self.uri, type(e).__name__, RETRY_S)
            return False
        self.driver, self.loaded, self.with_edges = driver, set(), set()   # a restarted Neo4j may have lost it
        log.info("Neo4j at %s: attribution paths come from the graph", self.uri)
        return True

    def _lost(self, what: str, e: Exception) -> None:
        log.warning("Neo4j %s failed (%s); using the envelope until it reconnects", what, type(e).__name__)
        try:
            self.driver.close()
        except Exception:
            pass
        self.driver = None
        self._next_try = time.monotonic() + RETRY_S

    def ensure_loaded(self, envelope: dict | None, graph: dict | None = None) -> bool:
        """Load an envelope's image, layers, files and packages (and the SBOM's edges, if given)
        into Neo4j, once per digest. True if the image is in the graph."""
        digest = ((envelope or {}).get("image") or {}).get("digest")
        if not digest or not self.connected():
            return False
        if digest in self.loaded and (graph is None or digest in self.with_edges):
            return True
        layers = envelope.get("layers") or []
        by_index = {l.get("index"): l.get("digest") for l in layers}
        files = [{"path": p, "sha256": m.get("sha256"), "layer_digest": by_index.get(m.get("layer")),
                  "package": m.get("package")}
                 for p, m in (envelope.get("files") or {}).items() if by_index.get(m.get("layer"))]
        roots = set((graph or {}).get("roots") or ())
        edges = [{"src": a, "dst": b} for a, bs in ((graph or {}).get("edges") or {}).items() for b in bs]
        purls = dict.fromkeys(envelope.get("packages") or {})
        purls.update(dict.fromkeys(p for e in edges for p in (e["src"], e["dst"])))
        packages = [{"purl": p, "depth": ((envelope.get("packages") or {}).get(p) or {}).get("depth"),
                     "root": p in roots} for p in purls]
        owned = [f for f in files if f["package"]]
        try:
            with self.driver.session() as s:
                s.run(LOAD_IMAGE, digest=digest, builder_id=envelope["image"].get("builder_id"),
                      source_commit=envelope["image"].get("source_commit"),
                      layers=[{"index": l.get("index"), "digest": l.get("digest")} for l in layers])
                for i in range(0, len(files), 1000):                    # batched MERGE
                    s.run(LOAD_FILES, files=files[i:i + 1000])
                for i in range(0, len(packages), 1000):
                    s.run(LOAD_PACKAGES, digest=digest, packages=packages[i:i + 1000])
                for i in range(0, len(owned), 1000):
                    s.run(LOAD_OWNS, files=owned[i:i + 1000])
                for i in range(0, len(edges), 1000):
                    s.run(LOAD_DEPENDS, digest=digest, edges=edges[i:i + 1000])
        except Exception as e:
            self._lost(f"load of {hex_of(digest)[:12]}", e)
            return False
        self.loaded.add(digest)
        if graph is not None:
            self.with_edges.add(digest)
        log.info("loaded %s into Neo4j: %d layers, %d files, %d packages, %d dependency edges",
                 hex_of(digest)[:12], len(layers), len(files), len(packages), len(edges))
        return True

    def layer_of(self, envelope: dict | None, digest: str, path: str | None) -> tuple[str | None, int | None]:
        """(layer digest, layer index) that introduced `path` in image `digest`, or (None, None)."""
        if not path:
            return None, None
        if envelope is not None and self.ensure_loaded(envelope):
            try:
                with self.driver.session() as s:
                    rec = s.run(LAYER_PATH, digest=digest, path=path).single()
                if rec:
                    return rec["layer"], rec["idx"]
                return None, None
            except Exception as e:
                self._lost("layer query", e)
        if envelope is None:
            return None, None
        meta = (envelope.get("files") or {}).get(path)
        if not meta or meta.get("layer") is None:
            return None, None
        for layer in envelope.get("layers") or []:
            if layer.get("index") == meta["layer"]:
                return layer.get("digest"), meta["layer"]
        return None, meta["layer"]

    def dependency_path(self, envelope: dict | None, graph: dict | None, digest: str,
                        package: str | None) -> list[str] | None:
        """[root purl, ..., package] for image `digest` (Eqs. 69-70), or None when the SBOM gives no
        path (no stored edges, no package, or a package no root reaches)."""
        if not package or graph is None:
            return None
        if envelope is not None and self.ensure_loaded(envelope, graph):
            try:
                with self.driver.session() as s:
                    if s.run(IS_ROOT, digest=digest, purl=package).single()["n"]:
                        return [package]
                    rec = s.run(DEPENDENCY_PATH, digest=digest, purl=package).single()
                return list(rec["path"]) if rec else None
            except Exception as e:
                self._lost("dependency query", e)
        return bfs_path(graph, package)


def load_run(run: str | Path, attributor: Attributor, done: dict | None = None) -> list[str]:
    """Load every envelope of the run folder (with its stored SBOM edges) that is new or changed
    since `done` ({path: mtime}). Returns the digests loaded now."""
    done = done if done is not None else {}
    loaded = []
    for path in sorted(glob.glob(str(Path(run) / "envelopes" / "*.json"))):
        try:
            mtime = os.stat(path).st_mtime_ns
        except OSError:
            continue
        if done.get(path) == mtime:
            continue
        env = load_envelope(run, "sha256:" + Path(path).stem)
        if env is None:
            continue
        digest = env["image"]["digest"]
        if done.get(path) is not None:
            attributor.loaded.discard(digest)          # recompiled: MERGE it again
            attributor.with_edges.discard(digest)
        if attributor.ensure_loaded(env, load_graph(run, digest)):
            done[path] = mtime
            loaded.append(digest)
    return loaded


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m alerts.attribute", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"), help="run folder (default $PROVBIND_RUN or ./run)")
    ap.add_argument("--watch", action="store_true", help="keep loading envelopes as they appear")
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between scans with --watch")
    args = ap.parse_args(argv)
    attributor = Attributor()
    done: dict = {}
    loaded = load_run(args.run, attributor, done)
    if not args.watch:
        print(json.dumps({"neo4j": attributor.driver is not None, "loaded": loaded}))
        return 0 if attributor.driver is not None else 3
    try:
        while True:
            time.sleep(args.interval)
            load_run(args.run, attributor, done)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
