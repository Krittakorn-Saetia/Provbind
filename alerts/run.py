#!/usr/bin/env python3
"""
alerts/run.py
Main alert processing engine for PROVBIND Role 4.
Tails detections.jsonl, groups process ancestry chains, invokes multi-factor scoring and layer attribution,
and appends formatted alerts to alerts.jsonl and log/violations.jsonl.
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime, timezone

# Ensure local directory is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from alerts.score import calculate_severity
    from alerts.attribute import LayerAttributor
    from alerts.log import ViolationLogger
except ImportError:
    from score import calculate_severity
    from attribute import LayerAttributor
    from log import ViolationLogger

def parse_args():
    parser = argparse.ArgumentParser(description="PROVBIND Alert Processing Engine")
    parser.add_argument("--run", default="./run", help="Path to run directory")
    parser.add_argument("--once", action="store_true", help="Process existing detections and exit (non-tailing mode)")
    return parser.parse_args()

class AlertEngine:
    def __init__(self, run_dir="./run"):
        self.run_dir = run_dir
        self.det_path = os.path.join(run_dir, "detections.jsonl")
        self.alerts_path = os.path.join(run_dir, "alerts.jsonl")
        self.attributor = LayerAttributor()
        self.logger = ViolationLogger(run_dir)
        self.active_chains = {}  # chain_id -> {'pids': set(), 'last_time': float}
        self.alert_counter = 0
        self.chain_counter = 0

    def _get_chain_id(self, pid, ppid, event_time_sec):
        """Groups process ancestry into chains if pid/ppid match within 60 seconds."""
        stale_keys = [cid for cid, cinfo in self.active_chains.items() if event_time_sec - cinfo["last_time"] > 60]
        for cid in stale_keys:
            del self.active_chains[cid]

        for cid, cinfo in self.active_chains.items():
            if pid in cinfo["pids"] or ppid in cinfo["pids"]:
                cinfo["pids"].add(pid)
                cinfo["last_time"] = event_time_sec
                return cid

        self.chain_counter += 1
        cid = f"chain-{self.chain_counter:04d}"
        self.active_chains[cid] = {
            "pids": {pid, ppid},
            "last_time": event_time_sec
        }
        return cid

    def _get_signing_identity(self, image_digest):
        """Extracts builder_id, source_commit, and rekor_log_index from compiled envelope."""
        digest_clean = image_digest.replace(":", "_")
        env_path = os.path.join(self.run_dir, "envelopes", f"{digest_clean}.json")
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                envelope = json.load(f)
                img = envelope.get("image", {})
                return {
                    "builder_id": img.get("builder_id", "sf9-26/local-build"),
                    "source_commit": img.get("source_commit", "unknown"),
                    "rekor_log_index": img.get("rekor_log_index", 123456789)
                }
        return {
            "builder_id": "sf9-26/local-build",
            "source_commit": "unknown",
            "rekor_log_index": 123456789
        }

    def process_detection(self, detection):
        self.alert_counter += 1
        alert_id = f"alr-{self.alert_counter:04d}"
        det_id = detection.get("id", f"det-{self.alert_counter:04d}")

        det_class = detection.get("class", "D_exec")
        subclass = detection.get("subclass", "undeclared")
        origin = detection.get("origin", "AUTHENTICATED")
        image_digest = detection.get("image_digest", "sha256:unknown")
        exe_path = detection.get("exe") or detection.get("clause", {}).get("path", "/unknown")
        pid = detection.get("pid", 0)
        ppid = detection.get("ppid", 0)

        time_str = detection.get("time", datetime.now(timezone.utc).isoformat())
        try:
            event_sec = datetime.fromisoformat(time_str.replace("Z", "+00:00")).timestamp()
        except ValueError:
            event_sec = time.time()

        chain_id = self._get_chain_id(pid, ppid, event_sec)

        layer_digest, layer_index = self.attributor.attribute_file(image_digest, exe_path, self.run_dir)

        in_no_layer = (layer_digest is None and subclass == "undeclared")
        score, bucket = calculate_severity(
            detection_class=det_class,
            subclass=subclass,
            origin=origin,
            depth=detection.get("context", {}).get("depth"),
            in_no_layer=in_no_layer,
            is_root=True,
            privileged=False
        )

        signing_id = self._get_signing_identity(image_digest)

        clause_info = detection.get("clause", {})
        violated_clause_str = f"{clause_info.get('kind', 'file_set')}: {clause_info.get('path', exe_path)} is {clause_info.get('detail', 'contradicts signed attestation')}"

        alert = {
            "alert_id": alert_id,
            "detection_id": det_id,
            "time": time_str,
            "image_digest": image_digest,
            "container": f"{detection.get('namespace', 'demo')}/{detection.get('pod', 'pod')}/{detection.get('container', 'app')}",
            "class": det_class,
            "subclass": subclass,
            "violated_clause": violated_clause_str,
            "origin": origin,
            "score": score,
            "bucket": bucket,
            "attribution": {
                "layer": layer_digest,
                "package": detection.get("context", {}).get("package"),
                "depth": detection.get("context", {}).get("depth"),
                "process_chain": [detection.get("parent_exe", "unknown"), exe_path]
            },
            "signing_identity": signing_id,
            "chain_id": chain_id,
            "log_k": 0
        }

        k, leaf_hash = self.logger.append_alert(alert)
        alert["log_k"] = k

        with open(self.alerts_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")

        print(f"🚨 [AlertEngine] Fired [{bucket.upper()}] Alert {alert_id} ({det_class}/{subclass}, Score: {score}) -> Chain: {chain_id}")

    def run(self, once=False):
        print(f"⚙️ [AlertEngine] Starting alert engine on {self.det_path}...")
        
        while not os.path.exists(self.det_path):
            if once:
                print("ℹ️ [AlertEngine] detections.jsonl not found.")
                return
            time.sleep(0.5)

        with open(self.det_path, "r", encoding="utf-8") as f:
            while True:
                line = f.readline()
                if not line:
                    if once:
                        break
                    time.sleep(0.2)
                    continue

                if line.strip():
                    try:
                        detection = json.loads(line)
                        self.process_detection(detection)
                    except json.JSONDecodeError:
                        continue

if __name__ == "__main__":
    args = parse_args()
    engine = AlertEngine(args.run)
    engine.run(args.once)
