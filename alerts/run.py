"""Phase 5: detections -> score -> attribute -> chain -> alert -> log (Sprint Handoff §3.3, §8).

    python -m alerts.run --run $PROVBIND_RUN [--once]

Tails `<run>/detections.jsonl` (Role 3) and writes one alert per detection to `<run>/alerts.jsonl`
(§4.5) and the hash-chained `<run>/log/violations.jsonl` (§4.6), through alerts.log.

- **Once per detection.** Detections already in the log are skipped, so a restart or a second
  `--once` never alerts one twice.
- **Complete lines only.** A line is read only once its newline is there (Role 3 writes each line in
  one call; a reader can still catch it half-written).
- **Attribution** is for the file the clause names (`clause.path`: the written file for D_write,
  the library for D_load), not the process that acted. Package and depth come from the detection's
  context, else from the envelope.
- **Signing identity** comes from the envelope (`envelopes/<hex>.json`). Without one, its fields are
  null: nothing unsigned is presented as signed.
- **Chains** (§8): a detection joins an open chain of the same container if its pid or ppid is a pid
  already in the chain and its `time` is within 60 s of the chain's last detection. Times are the
  events' own times, not arrival order (Role 3's handoff §2). The chain ID is taken from the first
  detection's number, so it is stable across restarts.

stdout: one JSON summary when `--once` finishes; logs go to stderr.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

from .attribute import Attributor
from .common import container_label, load_envelope, load_json, logger, now_iso, parse_time
from .log import ViolationLog
from .score import score_detection

log = logger("alerts")

CHAIN_WINDOW_S = 60
FILE_CLASSES = {"D_exec", "D_write", "D_hash", "D_load"}


class Chains:
    def __init__(self, window: float = CHAIN_WINDOW_S):
        self.window = window
        self.open: dict[str, list[dict]] = {}          # container_id -> chains
        self.counter = 0

    def assign(self, detection: dict) -> str:
        cid = detection.get("container_id") or ""
        pid, ppid = detection.get("pid"), detection.get("ppid")
        t = parse_time(detection.get("time"))
        t = time.time() if t is None else t
        for chain in self.open.setdefault(cid, []):
            if abs(t - chain["last"]) <= self.window and (pid in chain["pids"] or ppid in chain["pids"]):
                if pid is not None:
                    chain["pids"].add(pid)
                chain["last"] = max(chain["last"], t)
                return chain["id"]
        m = re.search(r"(\d+)$", str(detection.get("id") or ""))
        self.counter += 1
        chain_id = f"chain-{m.group(1)}" if m else f"chain-x{self.counter:04d}"
        self.open[cid].append({"id": chain_id, "pids": {pid} if pid is not None else set(), "last": t})
        return chain_id


class AlertEngine:
    def __init__(self, run: str | Path, attributor: Attributor | None = None):
        self.run = Path(run)
        self.det_path = self.run / "detections.jsonl"
        self.log = ViolationLog(self.run)
        self.attributor = attributor if attributor is not None else Attributor()
        self.chains = Chains()
        self.done = self.log.detection_ids()
        self.envelopes: dict[str, dict | None] = {}
        self._bindings: dict = {}
        self._bindings_stamp = None
        self.written = 0

    # --- inputs -------------------------------------------------------------------------------------

    def bindings(self) -> dict:
        path = self.run / "bindings.json"
        try:
            st = path.stat()
            stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
        except OSError:
            return self._bindings
        if stamp != self._bindings_stamp:
            doc = load_json(path, {})
            if isinstance(doc, dict):
                self._bindings, self._bindings_stamp = doc, stamp
        return self._bindings

    def envelope(self, digest: str | None) -> dict | None:
        if not digest:
            return None
        if self.envelopes.get(digest) is None:          # retry until the compiler has written it
            self.envelopes[digest] = load_envelope(self.run, digest)
        return self.envelopes[digest]

    # --- one detection ------------------------------------------------------------------------------

    def alert_for(self, det: dict) -> dict:
        digest = det.get("image_digest")
        env = self.envelope(digest)
        binding = self.bindings().get(det.get("container_id"))
        clause = det.get("clause") or {}
        ctx = det.get("context") or {}
        cls = det.get("class")
        path = clause.get("path") if cls in FILE_CLASSES and clause.get("path") else det.get("exe")

        layer_digest, _ = self.attributor.layer_of(env, digest, path)
        package, depth = ctx.get("package"), ctx.get("depth")
        if env is not None and path in (env.get("files") or {}):
            package = package if package is not None else env["files"][path].get("package")
            if depth is None and package:
                depth = (env.get("packages") or {}).get(package, {}).get("depth")

        score, bucket, parts = score_detection(det, binding)
        if parts.get("unknown_class"):
            log.warning("%s: class %s/%s has no s_type; scored with %s", det.get("id"), cls,
                        det.get("subclass"), parts["s_type"])
        image = (env or {}).get("image") or {}
        chain = [x for x in (det.get("parent_exe"), det.get("exe")) if x]
        return {
            "detection_id": det.get("id"),
            "time": det.get("time") or now_iso(),
            "image_digest": digest,
            "container": container_label(det),
            "class": cls,
            "subclass": det.get("subclass"),
            "violated_clause": f"{clause.get('kind', '')}: {clause.get('path', '')}: {clause.get('detail', '')}",
            "origin": det.get("origin"),
            "score": score,
            "bucket": bucket,
            "attribution": {"layer": layer_digest, "package": package, "depth": depth, "process_chain": chain},
            "signing_identity": {"builder_id": image.get("builder_id"), "source_commit": image.get("source_commit"),
                                 "rekor_log_index": image.get("rekor_log_index")},
            "chain_id": self.chains.assign(det),
            # Additions readers may ignore (§4): where it happened, and how the score was made.
            "namespace": det.get("namespace"), "pod": det.get("pod"), "container_id": det.get("container_id"),
            "pid": det.get("pid"), "ppid": det.get("ppid"), "score_parts": parts,
        }

    def handle(self, line: str) -> None:
        try:
            det = json.loads(line)
        except ValueError:
            log.warning("skipped a detection line that is not JSON: %.80s", line)
            return
        if not isinstance(det, dict):
            return
        if det.get("id") in self.done:
            self.chains.assign(det)                        # rebuild chain state after a restart
            return
        alert = self.log.append(self.alert_for(det))
        self.done.add(det.get("id"))
        self.written += 1
        log.info("%s %s %s/%s %d %s %s", alert["alert_id"], alert["detection_id"], alert["class"],
                 alert["subclass"], alert["score"], alert["bucket"], alert["chain_id"])

    # --- the loop -------------------------------------------------------------------------------------

    def run_loop(self, once: bool = False, poll: float = 0.2) -> None:
        while not self.det_path.exists():
            if once:
                log.info("no %s yet", self.det_path)
                return
            time.sleep(0.5)
        buf = ""
        with open(self.det_path, encoding="utf-8") as f:
            while True:
                chunk = f.read(65536)
                if chunk:
                    buf += chunk
                    *lines, buf = buf.split("\n")
                    for line in lines:
                        if line.strip():
                            self.handle(line)
                    continue
                if once:
                    if buf.strip():
                        log.warning("the last detection line has no newline yet; left for the next run")
                    return
                time.sleep(poll)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m alerts.run", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"), help="run folder (default $PROVBIND_RUN or ./run)")
    ap.add_argument("--once", action="store_true", help="process the detections written so far, then exit")
    args = ap.parse_args(argv)
    engine = AlertEngine(args.run)
    try:
        engine.run_loop(once=args.once)
    except KeyboardInterrupt:
        pass
    print(json.dumps({"alerts_written": engine.written, "detections_seen": len(engine.done)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
