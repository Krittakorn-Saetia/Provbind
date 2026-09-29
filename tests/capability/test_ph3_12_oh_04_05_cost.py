"""PH3-12, OH-04 and OH-05: what compiling and indexing an image costs (Test Plan §§3.3, 3.12).

- PH3-12: the time of each compiler step, and the envelope's size. The CLI records every step in the
  envelope's timings_ms; the size is the file's. Pass: both reported for a real envelope.
- OH-04: compile and index time per image: the compile time (the sum of the steps) and the time to
  build the runtime indices J_I (compiler/indices.py) from the envelope, the median of 5 builds.
  Pass: both reported for every real envelope.
- OH-05: index memory per envelope, as bytes per 1,000 files. Two numbers: what building J_I
  allocates on top of the loaded envelope (tracemalloc; the path and hash strings are shared with the
  envelope), and the deep size of every object J_I holds, strings included, which is what a node pays
  if it keeps only J_I. Pass: both reported for every real envelope.

Envelopes: PROVBIND_ENVELOPE, or else every *.json in $PROVBIND_RUN/envelopes/ (every test image, as
OH-04 and OH-05 ask). With none, the golden envelope stands in and the results are not_run. Laptop
numbers are indicative only (Test Plan §3.12).
"""
import dataclasses
import gc
import json
import os
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

from compiler.indices import build

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "compiler" / "tests" / "golden" / "envelope.json"
BUILDS = 5


def sources() -> tuple[list[Path], bool]:
    """The envelope files to measure, and whether they are real ones."""
    one = os.environ.get("PROVBIND_ENVELOPE")
    if one:
        return [Path(one)], True
    found = sorted((Path(os.environ.get("PROVBIND_RUN", "./run")) / "envelopes").glob("*.json"))
    return (found, True) if found else ([GOLDEN], False)


def label(env: dict, path: Path, taken: set) -> str:
    """The image's repository name (standin-app, demo-app), made unique with the digest if needed."""
    ref = (env.get("image") or {}).get("ref") or path.stem
    name = ref.split("@", 1)[0].rsplit("/", 1)[-1].split(":", 1)[0]
    if name in taken:
        name = f"{name}@{path.stem[:12]}"
    taken.add(name)
    return name


def envelopes() -> tuple[dict, bool]:
    """label -> (path, envelope), and whether they are real."""
    paths, real = sources()
    out, taken = {}, set()
    for p in paths:
        env = json.loads(p.read_text(encoding="utf-8"))
        out[label(env, p, taken)] = (p, env)
    return out, real


def deep_size(root) -> int:
    """sys.getsizeof over every distinct object reachable from `root` through containers."""
    seen, stack, total = set(), [root], 0
    while stack:
        obj = stack.pop()
        if id(obj) in seen:
            continue
        seen.add(id(obj))
        total += sys.getsizeof(obj)
        if isinstance(obj, dict):
            stack.extend(obj.keys())
            stack.extend(obj.values())
        elif isinstance(obj, (list, tuple, set, frozenset)):
            stack.extend(obj)
        elif dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            stack.extend(getattr(obj, f.name) for f in dataclasses.fields(obj))
    return total


def index_memory(env: dict) -> tuple[int, int]:
    """(bytes that building J_I allocates on top of the envelope, deep bytes of J_I)."""
    gc.collect()
    tracemalloc.start()
    try:
        indices = build(env)
        allocated, _ = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return allocated, deep_size(indices)


def index_ms(env: dict) -> float:
    times = []
    for _ in range(BUILDS):
        start = time.perf_counter()
        build(env)
        times.append((time.perf_counter() - start) * 1000)
    return round(statistics.median(times), 2)


def compile_s(env: dict) -> float | None:
    steps = env.get("timings_ms")
    return round(sum(steps.values()) / 1000, 2) if steps else None


def status(real: bool, measured: bool) -> str:
    return "pass" if real and measured else ("fail" if real else "not_run")


def synthetic_note(real: bool) -> str:
    return "" if real else "; the golden envelope is synthetic, so compile an image (or set PROVBIND_ENVELOPE) for the real test"


def test_ph3_12_compile_time_and_envelope_size(record_result):
    envs, real = envelopes()
    per = {name: {"compile_s": compile_s(env), "size_bytes": path.stat().st_size, "files": len(env.get("files") or {}),
                  "steps_ms": env.get("timings_ms")} for name, (path, env) in envs.items()}
    measured = all(v["compile_s"] is not None for v in per.values())
    notes = "; ".join(f"{name}: {v['compile_s']} s over {len(v['steps_ms'] or {})} steps, "
                      f"{v['size_bytes']:,} bytes, {v['files']:,} files" for name, v in per.items())
    if real and not measured:
        notes += "; an envelope has no timings_ms (not written by the CLI?)"
    record_result("PH3-12", status(real, measured),
                  metrics={"images": len(per), "compile_s": {n: v["compile_s"] for n, v in per.items()},
                           "size_bytes": {n: v["size_bytes"] for n, v in per.items()},
                           "files": {n: v["files"] for n, v in per.items()},
                           "steps_ms": {n: v["steps_ms"] for n, v in per.items()}},
                  notes=notes + synthetic_note(real), artifacts=[str(p) for p, _ in envs.values()] if real else [])
    assert measured or not real, notes


def test_oh_04_compile_and_index_time_per_image(record_result):
    envs, real = envelopes()
    per = {name: {"compile_s": compile_s(env), "index_ms": index_ms(env), "files": len(env.get("files") or {})}
           for name, (_, env) in envs.items()}
    measured = all(v["compile_s"] is not None for v in per.values())
    notes = "; ".join(f"{name}: compile {v['compile_s']} s, J_I built in {v['index_ms']} ms (median of {BUILDS}) "
                      f"for {v['files']:,} files" for name, v in per.items())
    record_result("OH-04", status(real, measured),
                  metrics={"images": len(per), "compile_s": {n: v["compile_s"] for n, v in per.items()},
                           "index_ms": {n: v["index_ms"] for n, v in per.items()},
                           "files": {n: v["files"] for n, v in per.items()}},
                  notes=notes + synthetic_note(real), artifacts=[str(p) for p, _ in envs.values()] if real else [])
    assert measured or not real, notes


def test_oh_05_index_memory_per_envelope(record_result):
    envs, real = envelopes()
    per = {}
    for name, (_, env) in envs.items():
        allocated, deep = index_memory(env)
        files = len(env.get("files") or {})
        per[name] = {"files": files, "index_bytes": allocated, "deep_bytes": deep,
                     "index_bytes_per_1000_files": round(allocated * 1000 / files) if files else None,
                     "deep_bytes_per_1000_files": round(deep * 1000 / files) if files else None}
    measured = all(v["files"] for v in per.values())
    notes = "; ".join(f"{name}: J_I adds {v['index_bytes']:,} bytes to the loaded envelope "
                      f"({v['index_bytes_per_1000_files']:,} per 1,000 files) and holds {v['deep_bytes']:,} bytes "
                      f"with its strings ({v['deep_bytes_per_1000_files']:,} per 1,000 files), {v['files']:,} files"
                      for name, v in per.items() if v["files"])
    notes += f"; Python {sys.version.split()[0]}"
    record_result("OH-05", status(real, measured),
                  metrics={"images": len(per),
                           "index_bytes_per_1000_files": {n: v["index_bytes_per_1000_files"] for n, v in per.items()},
                           "deep_bytes_per_1000_files": {n: v["deep_bytes_per_1000_files"] for n, v in per.items()},
                           "files": {n: v["files"] for n, v in per.items()},
                           "index_bytes": {n: v["index_bytes"] for n, v in per.items()},
                           "deep_bytes": {n: v["deep_bytes"] for n, v in per.items()}},
                  notes=notes + synthetic_note(real), artifacts=[str(p) for p, _ in envs.values()] if real else [])
    assert measured or not real, notes
