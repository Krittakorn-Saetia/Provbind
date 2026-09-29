"""Replay a stream through Phase 4 and judge it per scenario (Test Plan §7).

On the demo PC, a Tetragon recording made while Role 1's scenario scripts ran is replayed
together with ground_truth.csv (Sprint Handoff §4.7), whose rows give each scenario's pod
prefix and time window. In the cloud, node/synth.py's library stands in for both. Replays use
the events' own time, so they are deterministic.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from .normalize import Event, Normalizer, parse_time
from .output import Collector
from .pipeline import Pipeline
from .store import Store
from .verify import Egress, Verifier

GROUND_TRUTH_FIELDS = ("scenario", "label", "namespace", "pod_prefix", "start", "end", "expected")


@dataclass(frozen=True)
class Row:
    """One ground-truth row: a scenario run in a pod and a time window."""
    scenario: str
    label: str
    namespace: str
    pod_prefix: str
    start: str
    end: str
    expected: str
    start_t: int
    end_t: int

    @classmethod
    def of(cls, d: dict) -> Row:
        start_t, end_t = parse_time(d.get("start")), parse_time(d.get("end"))
        if start_t is None or end_t is None:
            raise ValueError(f"ground truth row {d.get('scenario')!r}: start and end must be UTC ISO 8601")
        return cls(scenario=d.get("scenario", ""), label=d.get("label", ""), namespace=d.get("namespace", ""),
                   pod_prefix=d.get("pod_prefix", ""), start=d["start"], end=d["end"],
                   expected=d.get("expected", ""), start_t=start_t, end_t=end_t)

    def holds(self, item) -> bool:
        """Is an Event or a detection inside this row's namespace, pod prefix and window?"""
        if isinstance(item, Event):
            ns, pod, t = item.namespace, item.pod, item.t
        else:
            ns, pod, t = item.get("namespace"), item.get("pod") or "", parse_time(item.get("time"))
        return ns == self.namespace and pod.startswith(self.pod_prefix) and t is not None \
            and self.start_t <= t <= self.end_t


def read_ground_truth(path: str | Path) -> list[Row]:
    with open(path, newline="", encoding="utf-8") as f:
        return [Row.of(d) for d in csv.DictReader(f)]


def rows_of(rows, scenario: str) -> list[Row]:
    return [r for r in rows if r.scenario == scenario]


@dataclass
class Replay:
    events: list
    detections: list
    pipeline: Pipeline
    normalizer: Normalizer
    store: Store

    def within(self, row: Row) -> tuple[list, list]:
        """(events, detections) inside one ground-truth row."""
        return [e for e in self.events if row.holds(e)], [d for d in self.detections if row.holds(d)]


def replay(lines, store: Store, *, egress: Egress | None = None, hasher=None, behaviour=None,
           grace: float = 30.0, namespaces=("demo",), timing: bool = False, strip_hashes: bool = False,
           keep=None) -> Replay:
    """Normalise, bind, verify and collect a whole stream, as `python -m node.run --replay` does.

    `strip_hashes` replays in path-only mode even if the stream carries hashes (PH4-09).
    `keep(event)` limits which events are kept in memory; every event is still verified."""
    normalizer = Normalizer(namespaces)
    events, detections = Collector(), Collector()
    on_event = events if keep is None else (lambda e: keep(e) and events(e))
    pipeline = Pipeline(store, Verifier(egress), grace=grace, on_event=on_event, on_detection=detections,
                        behaviour=behaviour, timing=timing, hasher=hasher)
    for line in lines:
        if isinstance(line, (str, bytes)) and not line.strip():
            continue
        ev = normalizer(line)
        if ev is None:
            continue
        if strip_hashes:
            ev.hash = None
        pipeline.feed(ev)
        if pipeline.held:
            pipeline.tick()
    pipeline.close()
    return Replay(events.items, detections.items, pipeline, normalizer, store)


@dataclass
class Evidence:
    """What the PH4 capability tests judge: one replay with runtime hashes where the stream has
    them, one in path-only mode, and the ground-truth rows."""
    real: bool
    source: str
    rows: list
    main: Replay
    path_only: Replay
    artifacts: list
    egress: bool

    def scenario(self, name: str) -> list:
        return rows_of(self.rows, name)


def synthetic_evidence() -> Evidence:
    """node/synth.py's library: every Test Plan §7 scenario once, with runtime hashes."""
    from .synth import library
    lib = library()
    rows = [Row.of(d) for d in lib.ground_truth]
    egress = Egress(lib.egress)

    def store():
        return Store.static([lib.envelope], lib.bindings)

    main = replay(lib.lines, store(), egress=egress, hasher=lambda e: lib.hashes.get((e.container_id, e.pid)))
    path_only = replay(lib.lines, store(), egress=egress)
    return Evidence(False, "synthetic library (node/synth.py)", rows, main, path_only, [], True)


def recorded_evidence(recording, run_dir, ground_truth=None, egress_file=None) -> Evidence:
    """A demo-PC recording (Tetragon JSON or events.jsonl) with the run folder's bindings and
    envelopes and ground_truth.csv. Only events inside a ground-truth row are kept in memory."""
    run_dir = Path(run_dir)
    gt = Path(ground_truth) if ground_truth else run_dir / "ground_truth.csv"
    rows = read_ground_truth(gt) if gt.is_file() else []
    egress = Egress.load(egress_file) if egress_file else None

    def keep(e):
        return any(r.holds(e) for r in rows)

    def run(strip):
        store = Store(run_dir)
        store.refresh()
        with open(recording, encoding="utf-8", errors="replace") as f:
            return replay(f, store, egress=egress, strip_hashes=strip, keep=keep)

    artifacts = [str(recording)] + ([str(gt)] if gt.is_file() else []) + ([str(egress_file)] if egress_file else [])
    return Evidence(True, str(recording), rows, run(False), run(True), artifacts, egress is not None)
