"""python -m node.run: Phase 4 on the node (Sprint Handoff §3.3, §7).

    kubectl logs -n kube-system ds/tetragon -c export-stdout -f | python -m node.run --run $PROVBIND_RUN
    python -m node.run --run $PROVBIND_RUN --replay recording.jsonl

It reads Tetragon's JSON export, or events.jsonl lines, on stdin or from --replay. It appends every
normalised event to <run>/events.jsonl and every detection to <run>/detections.jsonl. Logs go to
stderr; at the end, one JSON summary line goes to stdout.

- **Live (stdin).** Bindings and envelopes are reloaded every --tick seconds, even while no
  events arrive. Held events are released as soon as their envelope is ready.
- **Replay (--replay).** Bindings and envelopes are read once. Time is the events' own time, so
  a replay gives the same detections every time.
- **ML-B (--mlb).** Conforming events also go into per-process windows, scored with the model
  beside each envelope (node/mlb.py). --windows-out records every closed window, for dataset D2.

Exit codes: 0 done · 2 bad arguments · 3 bad input (the replay file is missing, or it is the
events.jsonl this run appends to).
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import select
import signal
import sys
import time
from pathlib import Path

from .mlb import Behaviour, ModelCache
from .normalize import Normalizer
from .output import DetectionWriter, EventWriter, JsonlWriter, dumps
from .pipeline import Pipeline
from .store import Store
from .verify import Egress, Verifier

log = logging.getLogger("provbind.node")


def build(run_dir: Path, args, on_event, on_detection, on_window=None) -> tuple[Store, Pipeline]:
    store = Store(run_dir)
    store.refresh()
    egress = Egress.load(args.egress) if args.egress else None
    behaviour = None
    if args.mlb or on_window is not None:
        behaviour = Behaviour(model_for=ModelCache(run_dir) if args.mlb else None, on_window=on_window)
    pipeline = Pipeline(store, Verifier(egress), grace=args.grace, envelope_timeout=args.envelope_timeout,
                        on_event=on_event, on_detection=on_detection, behaviour=behaviour)
    return store, pipeline


def summary(normalizer: Normalizer, store: Store, pipeline: Pipeline, started: float) -> dict:
    by = lambda prefix, c: {k[len(prefix):]: v for k, v in sorted(c.items()) if k.startswith(prefix)}
    verdicts = dict(sorted(pipeline.verifier.stats.items()))
    return {"events": pipeline.stats["events"], "detections": pipeline.stats["detections"],
            "kinds": by("kind:", pipeline.stats), "verdicts": verdicts,
            "dropped": by("drop:", normalizer.stats),
            "held": {k: pipeline.stats[k] for k in ("held", "released", "lost", "unverified_at_close",
                                                     "after_unbind", "unbound_events")},
            "cold_start_s": {cid: c["window_s"] for cid, c in pipeline.cold.items()},
            "envelopes": {"cached": sorted(store.cache), **{k: store.stats[k] for k in
                          ("loads", "reloads", "evictions", "bad_envelopes", "hits", "misses")}},
            "mlb": dict(sorted(pipeline.behaviour.stats.items())) if pipeline.behaviour is not None else None,
            "seconds": round(time.monotonic() - started, 3)}


def replay(path: Path, normalizer: Normalizer, pipeline: Pipeline) -> None:
    with open(path, encoding="utf-8", errors="replace") as f:     # a bad byte is one bad line
        for line in f:
            if not line.strip():
                continue
            ev = normalizer(line)
            if ev is None:
                continue
            pipeline.feed(ev)
            if pipeline.held:
                pipeline.tick()
    pipeline.close()


def live(fd: int, normalizer: Normalizer, store: Store, pipeline: Pipeline, tick: float, stop) -> None:
    buf, last = b"", time.monotonic()
    while not stop():
        try:
            ready, _, _ = select.select([fd], [], [], tick)
        except InterruptedError:
            continue
        if ready:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            *lines, buf = (buf + chunk).split(b"\n")
            for line in lines:
                ev = normalizer(line) if line.strip() else None
                if ev is not None:
                    pipeline.feed(ev)
        if time.monotonic() - last >= tick:
            store.refresh()
            pipeline.tick(time.time_ns())
            last = time.monotonic()
    if buf.strip():
        ev = normalizer(buf)
        if ev is not None:
            pipeline.feed(ev)
    store.refresh()
    pipeline.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m node.run", description=__doc__.split("\n\n")[0])
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"), help="run folder")
    ap.add_argument("--replay", metavar="FILE", help="read events from FILE instead of stdin")
    ap.add_argument("--namespace", action="append", help="namespace to monitor (repeatable; default demo)")
    ap.add_argument("--all-namespaces", action="store_true", help="monitor every namespace")
    ap.add_argument("--grace", type=float, default=30.0, help="seconds to wait for a binding (default 30)")
    ap.add_argument("--envelope-timeout", type=float, default=300.0,
                    help="seconds before a bound container without an envelope is reported (default 300)")
    ap.add_argument("--egress", metavar="FILE", help='egress allow list for D_net: {"allow": ["10.0.0.0/8", …]}')
    ap.add_argument("--no-events", action="store_true", help="do not write events.jsonl")
    ap.add_argument("--mlb", action="store_true",
                    help="ML-B: score windows with the model beside each envelope (<hex>.mlb/model.json)")
    ap.add_argument("--windows-out", metavar="FILE", help="ML-B: append every closed window to FILE (dataset D2)")
    ap.add_argument("--tick", type=float, default=0.5, help="live mode: seconds between reloads (default 0.5)")
    ap.add_argument("--summary", metavar="FILE", help="also write the summary JSON to FILE")
    ap.add_argument("--log-level", default="INFO")
    args = ap.parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    run_dir = Path(args.run)
    events_path = run_dir / "events.jsonl"
    if args.replay:
        src = Path(args.replay)
        if not src.is_file():
            log.error("replay file %s does not exist", src)
            return 3
        if not args.no_events and events_path.exists() and src.resolve() == events_path.resolve():
            log.error("%s is the events file this run appends to; use --no-events to replay it", src)
            return 3
    namespaces = None if args.all_namespaces else tuple(args.namespace or ("demo",))

    started = time.monotonic()
    normalizer = Normalizer(namespaces)
    events = None if args.no_events else EventWriter(events_path)
    detections = DetectionWriter(run_dir / "detections.jsonl")
    windows = JsonlWriter(args.windows_out) if args.windows_out else None
    try:
        store, pipeline = build(run_dir, args, events, detections, windows.write if windows else None)
    except (OSError, ValueError) as e:
        log.error("cannot start: %s", e)
        return 2
    stopping = []
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stopping.append(True))
    log.info("monitoring %s; run folder %s; %d bindings", ", ".join(namespaces) if namespaces else "every namespace",
             run_dir, len(store.bindings))
    try:
        if args.replay:
            replay(Path(args.replay), normalizer, pipeline)
        else:
            live(sys.stdin.fileno(), normalizer, store, pipeline, args.tick, lambda: bool(stopping))
    finally:
        for writer in (events, detections, windows):
            if writer is not None:
                writer.close()
    out = summary(normalizer, store, pipeline, started)
    if args.summary:
        Path(args.summary).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
