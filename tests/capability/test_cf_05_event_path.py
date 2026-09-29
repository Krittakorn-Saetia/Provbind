"""CF-05 (P1): the Cuckoo filter's effect on the real event path (M15; Test Plan §6).

A recorded event stream is replayed with the filter on and off, five times each, interleaved.
For each mode:
- the per-event verification latency (p50, p99, mean), timed around the verifier as
  `node.run` times it;
- the CPU time of the whole replay.

The detections must be identical in both modes: the filter may save time, never change a verdict.

**Keep or drop (§6.3).** Keep the filter only if it lowers the per-event latency (p50 and mean).
Otherwise drop it and update the draft to a hash-table index (M15). The memory half of the rule
needs OH-05 (index memory per envelope), so the filter's bytes are recorded next to the index's.

**Evidence.** PROVBIND_RECORDING with the run folder (demo PC). Otherwise the synthetic scenario
library plus an hour of synthetic benign load, and the result is not_run.

The filter-off p50 and p99 are also what OH-01 asks for; OH-01 has no test file yet
(ROLE3_STATUS.md, Q2).
"""
from __future__ import annotations

import os
import statistics
import sys
import time
from pathlib import Path

from node.scenarios import replay
from node.store import Store
from node.synth import benign_session, library
from node.verify import Egress

RUN = Path(os.environ.get("PROVBIND_RUN", "./run"))
REPS = 5


def evidence():
    rec = os.environ.get("PROVBIND_RECORDING")
    egress_file = os.environ.get("PROVBIND_EGRESS")
    if rec:
        def store(cuckoo):
            s = Store(RUN, cuckoo=cuckoo)
            s.refresh()
            return s
        lines = Path(rec).read_text(encoding="utf-8", errors="replace").splitlines()
        return lines, store, Egress.load(egress_file) if egress_file else None, rec, True
    lib = library()
    lines = lib.lines + benign_session(3600, seed=11, start="2026-09-28T10:05:00Z")
    return lines, lambda cuckoo: Store.static([lib.envelope], lib.bindings, cuckoo=cuckoo), Egress(lib.egress), \
        "synthetic library and a benign hour", False


def percentile(values, q):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q / 100 * (len(ordered) - 1))))] if ordered else None


def test_cf_05_filter_on_the_event_path(record_result):
    lines, store, egress, source, real = evidence()
    lat, cpu, dets, stores = {False: [], True: []}, {False: [], True: []}, {False: [], True: []}, {}
    for _ in range(REPS):
        for cuckoo in (False, True):
            s = store(cuckoo)
            t0 = time.process_time()
            r = replay(lines, s, egress=egress, timing=True, keep=lambda e: False)
            cpu[cuckoo].append(time.process_time() - t0)
            lat[cuckoo] += r.pipeline.latencies
            dets[cuckoo].append(r.detections)
            stores[cuckoo] = s
    identical = all(d == dets[False][0] for mode in (False, True) for d in dets[mode])
    stats = {}
    for cuckoo, name in ((False, "index_only"), (True, "filter_then_index")):
        stats[name] = {"events_verified": len(lat[cuckoo]) // REPS, "p50_ns": percentile(lat[cuckoo], 50),
                       "p99_ns": percentile(lat[cuckoo], 99), "mean_ns": round(statistics.fmean(lat[cuckoo]), 1)
                       if lat[cuckoo] else None, "cpu_s_median": round(statistics.median(cpu[cuckoo]), 4)}
    off, on = stats["index_only"], stats["filter_then_index"]
    envs = list(stores[True].cache.values())
    filter_bytes = sum(e.filter.nbytes() for e in envs if e.filter is not None)
    index_bytes = sum(sys.getsizeof(e.j.path) for e in stores[False].cache.values())
    faster = on["p50_ns"] is not None and on["p50_ns"] < off["p50_ns"] and on["mean_ns"] < off["mean_ns"]
    decision = "keep" if faster else "drop"
    reason = ("the filter lowered the per-event latency" if faster else
              f"the filter did not lower the per-event latency (p50 {off['p50_ns']} ns without, {on['p50_ns']} ns "
              f"with; mean {off['mean_ns']} against {on['mean_ns']}): replace it with a hash-table index (M15), "
              "unless OH-05 shows index memory limits the node")
    ok = identical and off["events_verified"] > 0
    notes = (f"{source}: {off['events_verified']} events verified per replay, {REPS} replays per mode; "
             f"detections identical in both modes: {identical}; decision: {decision}, {reason}; filter "
             f"{filter_bytes} bytes against the path index's table {index_bytes} bytes (the path strings exist "
             "either way; memory per envelope is OH-05)")
    status = ("pass" if ok else "fail") if real else ("not_run" if ok else "fail")
    if not real:
        notes += "; synthetic, so not a project result: set PROVBIND_RECORDING on the demo PC"
    record_result("CF-05", status,
                  metrics={**stats, "detections_identical": identical, "decision": decision,
                           "filter_bytes": filter_bytes, "index_table_bytes": index_bytes,
                           "filter_full": sum(e.filter_full for e in envs)},
                  notes=notes, artifacts=[source] if real else [])
    assert ok, notes
