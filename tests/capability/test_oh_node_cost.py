"""OH-01, OH-02, OH-03 (R3, P1) and OH-06 (R3, P2): the node's cost (Test Plan §3.12).

| ID | Measures | Real input (demo PC) |
|---|---|---|
| OH-01 | per-event verification latency, p50 and p99, over >= 100,000 events | PROVBIND_RECORDING |
| OH-02 | the node's CPU and memory on top of Tetragon alone | PROVBIND_RECORDING, plus PROVBIND_TETRAGON_CPU_S and PROVBIND_TETRAGON_RSS_KB measured under the same load without the node |
| OH-03 | ring-buffer drops under an exec storm of 10,000 short processes | PROVBIND_OH03_STORM (the storm's recording), PROVBIND_OH03_EXPECTED (default 10000) |
| OH-06 | the envelope cache's hit rate at 1, 10 and 50 replicas | PROVBIND_OH06_SUMMARIES="<1>,<10>,<50>" (node.run --summary files from the scale test) |

Without real input each test measures the node on a synthetic stream and records not_run: laptop
numbers on synthetic events are not a project result (§3.12).

Written by Role 2 for Role 3, at Korn's request (the test files were outside Role 3's session scope, Q2).
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from node.scenarios import replay
from node.store import Store, hex_of
from node.synth import DIGEST, Session, benign_session, demo_envelope, library
from node.verify import Egress

ROOT = Path(__file__).resolve().parents[2]
RUN = Path(os.environ.get("PROVBIND_RUN", "./run"))


def percentile(values, q):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(q / 100 * (len(ordered) - 1))))] if ordered else None


def recording():
    rec = os.environ.get("PROVBIND_RECORDING")
    if rec:
        return Path(rec).read_text(encoding="utf-8", errors="replace").splitlines(), None, rec, True
    lib = library(attack2_files=30)
    lines = lib.lines + benign_session(7200, seed=5, start="2026-09-28T10:05:00Z", rate=1.0)
    return lines, lib, "synthetic library and two hours of benign load", False


def store_for(lib):
    if lib is None:
        s = Store(RUN)
        s.refresh()
        return s
    return Store.static([lib.envelope], lib.bindings)


def status_of(ok, real):
    return ("pass" if ok else "fail") if real else ("not_run" if ok else "fail")


def test_oh_01_per_event_latency(record_result):
    lines, lib, source, real = recording()
    r = replay(lines, store_for(lib), egress=Egress(lib.egress) if lib else None, timing=True, keep=lambda e: False)
    lat = r.pipeline.latencies
    enough = len(lat) >= 100_000
    ok = bool(lat) and (enough or not real)
    notes = (f"{source}: {len(lat)} events verified; p50 {percentile(lat, 50)} ns, p99 {percentile(lat, 99)} ns"
             + ("" if enough else "; fewer than the 100,000 events the plan asks for"))
    if not real:
        notes += "; synthetic, so set PROVBIND_RECORDING to a demo-PC recording"
    record_result("OH-01", status_of(ok, real), metrics={"events": len(lat), "p50_ns": percentile(lat, 50),
                                                          "p99_ns": percentile(lat, 99)}, notes=notes)
    assert ok, notes


@pytest.mark.skipif(not hasattr(os, "wait4"), reason="os.wait4 is POSIX-only")
def test_oh_02_node_cpu_and_memory(tmp_path, record_result):
    lines, lib, source, real = recording()
    rec = Path(os.environ["PROVBIND_RECORDING"]) if real else tmp_path / "rec.jsonl"
    run = RUN if real else tmp_path
    if not real:
        rec.write_text("\n".join(lines) + "\n")
        (tmp_path / "envelopes").mkdir()
        (tmp_path / "envelopes" / f"{hex_of(DIGEST)}.json").write_text(json.dumps(lib.envelope))
        (tmp_path / "bindings.json").write_text(json.dumps(lib.bindings))
    out_dir = Path(tempfile.mkdtemp(dir=tmp_path))                     # never write into the real run's files
    for name in ("envelopes", "bindings.json"):
        src = run / name
        if src.exists() and not (out_dir / name).exists():
            (out_dir / name).symlink_to(src.resolve())
    with open(tmp_path / "node.log", "wb") as log:                     # a file, not a pipe: no deadlock
        child = subprocess.Popen([sys.executable, "-m", "node.run", "--run", str(out_dir), "--replay", str(rec),
                                  "--no-events"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=log)
        _, status, usage = os.wait4(child.pid, 0)
    cpu_s = round(usage.ru_utime + usage.ru_stime, 3)
    rss_kb = usage.ru_maxrss
    base_cpu, base_rss = os.environ.get("PROVBIND_TETRAGON_CPU_S"), os.environ.get("PROVBIND_TETRAGON_RSS_KB")
    metrics = {"events": len(lines), "node_cpu_s": cpu_s, "node_max_rss_kb": rss_kb}
    ok = os.waitstatus_to_exitcode(status) == 0
    have_base = bool(base_cpu and base_rss)
    if have_base:
        metrics.update(cpu_overhead_pct=round(100 * cpu_s / float(base_cpu), 1),
                       rss_overhead_pct=round(100 * rss_kb / float(base_rss), 1))
    notes = (f"{source}: node.run replaying {len(lines)} lines used {cpu_s} s of CPU and {rss_kb} KB at most"
             + (f"; {metrics['cpu_overhead_pct']}% CPU and {metrics['rss_overhead_pct']}% memory on top of Tetragon"
                if have_base else "; the percentages need Tetragon's own numbers under the same load"))
    real_enough = real and have_base
    if not real_enough:
        notes += " (not_run: needs a demo-PC recording and PROVBIND_TETRAGON_CPU_S / _RSS_KB)"
    record_result("OH-02", status_of(ok, real_enough), metrics=metrics, notes=notes)
    assert ok, notes


def exec_storm(n: int) -> tuple[list, object]:
    """The app starts n short processes in a row (/usr/bin/true, exec then exit)."""
    lib = library(attack2_files=0)
    s = Session(start="2026-09-28T12:00:00Z", step_ms=1)
    shim = s.proc("/usr/local/bin/containerd-shim-runc-v2", pid=4100, pod=None)
    app = s.proc("/usr/local/bin/python3.11", pid=4402, parent=shim)
    s.exec(app)
    for i in range(n):
        p = s.proc("/usr/bin/true", pid=20000 + i, parent=app)
        s.exec(p)
        s.exit(p)
    return s.lines(), lib


def test_oh_03_drops_under_an_exec_storm(record_result):
    storm = os.environ.get("PROVBIND_OH03_STORM")
    expected = int(os.environ.get("PROVBIND_OH03_EXPECTED", "10000"))
    if storm:
        lines, store, source, real = (Path(storm).read_text(encoding="utf-8", errors="replace").splitlines(),
                                      store_for(None), storm, True)
    else:
        lines, lib = exec_storm(expected)
        store, source, real = store_for(lib), f"synthetic storm of {expected} short processes", False
    r = replay(lines, store, keep=lambda e: e.kind == "exec")
    execs = sum(1 for e in r.events if e.kind == "exec" and e.exe != "/usr/local/bin/python3.11")
    node_dropped = sum(r.normalizer.stats[k] for k in r.normalizer.stats if k.startswith("drop:"))
    rate = round(1 - min(execs, expected) / expected, 4) if expected else None
    ok = execs > 0
    notes = (f"{source}: {execs} of {expected} execs reached the node (drop rate {rate}); "
             f"the node itself dropped {node_dropped} lines")
    if not real:
        notes += "; synthetic, so Tetragon's ring buffer is not involved: run the storm on the demo PC"
    record_result("OH-03", status_of(ok, real), metrics={"expected": expected, "seen": execs, "drop_rate": rate,
                                                          "node_dropped_lines": node_dropped}, notes=notes)
    assert ok, notes


def replicas(n: int) -> tuple[list, dict]:
    """n containers of the demo image, each running the app and writing its log five times."""
    s = Session(start="2026-09-28T13:00:00Z", step_ms=1)
    shim = s.proc("/usr/local/bin/containerd-shim-runc-v2", pid=4100, pod=None)
    bindings = {}
    for i in range(n):
        cid = "containerd://" + f"{i:04x}" * 16
        pod = f"demo-app-{i:04x}"
        bindings[cid] = {"namespace": "demo", "pod": pod, "container": "app", "image_digest": DIGEST,
                         "verified": True, "run_as_root": True, "privileged": False, "mounts": [], "envelope_ready": True}
        app = s.proc("/usr/local/bin/python3.11", pid=30000 + 10 * i, parent=shim, pod=pod, container_id=cid)
        s.exec(app)
        for j in range(5):
            s.write(app, "/tmp/app.log")
    return s.lines(), bindings


def test_oh_06_cache_hit_rate(record_result):
    summaries = os.environ.get("PROVBIND_OH06_SUMMARIES")
    rates = {}
    if summaries:
        for n, path in zip((1, 10, 50), summaries.split(",")):
            env = json.loads(Path(path.strip()).read_text())["envelopes"]
            rates[n] = round(env["hits"] / max(1, env["hits"] + env["misses"]), 4)
        source, real = summaries, True
    else:
        for n in (1, 10, 50):
            lines, bindings = replicas(n)
            store = Store.static([demo_envelope()], bindings)
            replay(lines, store, keep=lambda e: False)
            rates[n] = round(store.stats["hits"] / max(1, store.stats["hits"] + store.stats["misses"]), 4)
        source, real = "synthetic replicas, one image", False
    ok = len(rates) == 3
    notes = f"{source}: envelope cache hit rate at 1, 10 and 50 replicas: {rates}"
    if not real:
        notes += "; synthetic, so run the scale test (PH4-04) on the demo PC with node.run --summary"
    record_result("OH-06", status_of(ok, real), metrics={"hit_rate": {str(k): v for k, v in rates.items()}}, notes=notes)
    assert ok, notes
