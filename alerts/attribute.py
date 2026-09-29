#!/usr/bin/env python3
"""
alerts/attribute.py
Graph-based root-cause layer attribution engine.
Queries Neo4j database for (Image)-[:CONTAINS]->(Layer)-[:INTRODUCES]->(File) relationships.
Falls back gracefully to local envelopes/<digest>.json if Neo4j is offline.
"""

import os
import json

class LayerAttributor:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="provbind-demo"):
        self.driver = None
        try:
            from neo4j import GraphDatabase
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            print("🔗 [Attributor] Connected to Neo4j graph database.")
        except Exception:
            print("ℹ️ [Attributor] Neo4j unavailable. Using local envelope fallback for layer attribution.")
            self.driver = None

    def load_envelope_into_neo4j(self, envelope):
        """Loads compiled envelope layers and files into Neo4j graph store."""
        if not self.driver:
            return

        digest = envelope["image"]["digest"]
        builder_id = envelope["image"].get("builder_id", "unknown")
        commit = envelope["image"].get("source_commit", "unknown")
        layers = envelope.get("layers", [])
        files_data = [{"path": p, "sha256": meta.get("sha256"), "layer_digest": layers[meta["layer"]]["digest"] if meta.get("layer") is not None and meta["layer"] < len(layers) else None} 
                      for p, meta in envelope.get("files", {}).items()]

        cypher_image = """
        MERGE (i:Image {digest: $digest})
        SET i.builder_id = $builder_id, i.source_commit = $source_commit
        WITH i
        UNWIND $layers AS l
        MERGE (x:Layer {digest: l.digest})
        MERGE (i)-[c:CONTAINS]->(x) SET c.index = l.index
        """

        cypher_files = """
        UNWIND $files AS f
        MATCH (x:Layer {digest: f.layer_digest})
        MERGE (fl:File {path: f.path, sha256: f.sha256})
        MERGE (x)-[:INTRODUCES]->(fl)
        """

        try:
            with self.driver.session() as session:
                session.run(cypher_image, digest=digest, builder_id=builder_id, source_commit=commit, layers=layers)
                if files_data:
                    session.run(cypher_files, files=files_data)
            print(f"📊 [Attributor] Ingested envelope for {digest[:16]}... into Neo4j graph.")
        except Exception as e:
            print(f"⚠️ [Attributor] Neo4j load failed: {e}")

    def attribute_file(self, image_digest, file_path, run_dir="./run"):
        """
        Attributes a file path to its introducing OCI image layer digest and index.
        Returns: (layer_digest, layer_index, process_chain)
        """
        if self.driver:
            cypher = """
            MATCH (:Image {digest: $digest})-[c:CONTAINS]->(l:Layer)-[:INTRODUCES]->(:File {path: $path})
            RETURN l.digest AS layer, c.index AS idx ORDER BY idx DESC LIMIT 1
            """
            try:
                with self.driver.session() as session:
                    res = session.run(cypher, digest=image_digest, path=file_path)
                    rec = res.single()
                    if rec:
                        return rec["layer"], rec["idx"]
            except Exception:
                pass

        # Fallback to local envelope JSON
        digest_clean = image_digest.replace(":", "_")
        env_path = os.path.join(run_dir, "envelopes", f"{digest_clean}.json")
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                envelope = json.load(f)
                file_meta = envelope.get("files", {}).get(file_path)
                if file_meta and "layer" in file_meta:
                    idx = file_meta["layer"]
                    layers = envelope.get("layers", [])
                    if idx < len(layers):
                        return layers[idx]["digest"], idx

        return None, None

if __name__ == "__main__":
    attributor = LayerAttributor()
    layer, idx = attributor.attribute_file("sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff", "/usr/bin/ls")
    print(f"Attribution result for /usr/bin/ls: layer={layer}, idx={idx}")
