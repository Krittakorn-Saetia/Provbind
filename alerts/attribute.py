"""Phase 5 Step 3: attribution (Sprint Handoff §8 "Neo4j load and layer query"; Eqs. 69-74).

The layer path: which layer of this image introduced the file. Each new envelope is loaded into
Neo4j once, with the Cypher from the Sprint Handoff; the layer query then answers for display.
When Neo4j is down or not installed, the answer comes from the envelope's own `files[path].layer`
(the fallback §8 names). Both give the same answer: the envelope is the graph's source.

An empty layer path is itself the finding: nothing signed ever claimed that file exists (PH5-08).
The dependency path (Eqs. 69-70, PH5-07) needs the SBOM's edges, which the envelope does not hold;
it is not attempted here, and `depth` from the envelope stands in.
"""
from __future__ import annotations

import os

from .common import hex_of, logger

log = logger("attribute")

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
LAYER_PATH = """
MATCH (:Image {digest: $digest})-[c:CONTAINS]->(l:Layer)-[:INTRODUCES]->(:File {path: $path})
RETURN l.digest AS layer, c.index AS idx ORDER BY idx DESC LIMIT 1
"""


class Attributor:
    def __init__(self, uri: str | None = None, user: str = "neo4j", password: str | None = None,
                 use_neo4j: bool | None = None):
        self.driver = None
        self.loaded: set[str] = set()
        if use_neo4j is None:
            use_neo4j = os.environ.get("PROVBIND_NEO4J", "on") != "off"
        if not use_neo4j:
            return
        uri = uri or os.environ.get("PROVBIND_NEO4J_URI", "bolt://localhost:7687")
        password = password or os.environ.get("PROVBIND_NEO4J_PASSWORD", "provbind-demo")
        try:
            from neo4j import GraphDatabase
            driver = GraphDatabase.driver(uri, auth=(user, password), connection_timeout=3)
            driver.verify_connectivity()
            self.driver = driver
            log.info("Neo4j at %s: layer paths come from the graph", uri)
        except Exception as e:                     # not installed, not running, wrong password
            log.info("Neo4j unavailable (%s); layer paths come from the envelope", type(e).__name__)

    def ensure_loaded(self, envelope: dict) -> None:
        """Load an envelope's image, layers and files into Neo4j, once per digest."""
        digest = envelope.get("image", {}).get("digest")
        if self.driver is None or not digest or digest in self.loaded:
            return
        layers = envelope.get("layers") or []
        by_index = {l.get("index"): l.get("digest") for l in layers}
        files = [{"path": p, "sha256": m.get("sha256"), "layer_digest": by_index.get(m.get("layer"))}
                 for p, m in (envelope.get("files") or {}).items() if by_index.get(m.get("layer"))]
        try:
            with self.driver.session() as s:
                s.run(LOAD_IMAGE, digest=digest, builder_id=envelope["image"].get("builder_id"),
                      source_commit=envelope["image"].get("source_commit"),
                      layers=[{"index": l.get("index"), "digest": l.get("digest")} for l in layers])
                for i in range(0, len(files), 1000):                    # batched MERGE
                    s.run(LOAD_FILES, files=files[i:i + 1000])
            self.loaded.add(digest)
            log.info("loaded %s into Neo4j: %d layers, %d files", hex_of(digest)[:12], len(layers), len(files))
        except Exception as e:
            log.warning("Neo4j load of %s failed (%s); using the envelope", hex_of(digest)[:12], e)

    def layer_of(self, envelope: dict | None, digest: str, path: str | None) -> tuple[str | None, int | None]:
        """(layer digest, layer index) that introduced `path` in image `digest`, or (None, None)."""
        if not path:
            return None, None
        if self.driver is not None and envelope is not None:
            self.ensure_loaded(envelope)
            try:
                with self.driver.session() as s:
                    rec = s.run(LAYER_PATH, digest=digest, path=path).single()
                if rec:
                    return rec["layer"], rec["idx"]
                return None, None
            except Exception as e:
                log.warning("Neo4j query failed (%s); using the envelope", e)
        if envelope is None:
            return None, None
        meta = (envelope.get("files") or {}).get(path)
        if not meta or meta.get("layer") is None:
            return None, None
        for layer in envelope.get("layers") or []:
            if layer.get("index") == meta["layer"]:
                return layer.get("digest"), meta["layer"]
        return None, meta["layer"]
