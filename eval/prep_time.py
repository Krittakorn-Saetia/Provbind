"""Measured preparation time per system: how long each system needs, on our VM, before it can protect a
new image, and how many operations that took (the supervisor asked for exact times, not design minimums).

    python -m eval.prep_time provbind --ref <ref@digest> --runs 5 --work DIR --out prep.jsonl
    python -m eval.prep_time confine  --binaries DIR --startup TRACE --export-s S --out prep.jsonl
    python -m eval.prep_time desfam   --binaries DIR --benign 'GLOB' --requests N --out prep.jsonl
    python -m eval.prep_time falco    --ready-s S [S ...] --out prep.jsonl
    python -m eval.prep_time report   --prep prep.jsonl --out DIR       # PREP.md and PREP.json

- PROVBIND: wall-clock time of `python -m compiler.compile` on the image, cold (a fresh run folder each
  time, so nothing is cached), repeated --runs times; the step timings come from the envelope.
- Confine-E: the start-up observation actually recorded (span of the start-up trace) + exporting the
  image's binaries from the pod + the static analysis (timed here).
- DeSFAM-E: the benign profiling actually recorded (span of the baseline traces) + its allow list and
  Isolation Forest training (timed here); the counts are the requests, system calls and windows it saw.
- PROVBIND + ML-B (only for D_beh, the in-envelope detector): the benign load recorded for ML-B's dataset
  D2 (from scripts/record-d2.sh's log) + training the model (timed here); held-out data is evaluation, not
  preparation, and is left out.
- Falco: no per-image step (generic rules); the time its DaemonSet takes to become ready after a restart,
  measured by scripts/overhead-run.sh each time it switches Falco on, is reported beside it.
Every row carries its count (`n`) and what was counted.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _append(out, row):
    with open(out, "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    print(json.dumps(row))


def _trace_span_s(path):
    first = last = None
    n = 0
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                head = line.split("\t", 1)[0].strip()
                if head.isdigit():
                    n += 1
                    first = int(head) if first is None else first
                    last = int(head)
    except OSError:
        return 0.0, 0
    return ((last - first) / 1e9 if first is not None else 0.0), n


def provbind(args):
    times, steps, files, packages = [], {}, None, None
    for i in range(args.runs):
        work = Path(tempfile.mkdtemp(prefix=f"prep-{i}-", dir=args.work))
        t0 = time.perf_counter()
        proc = subprocess.run([sys.executable, "-m", "compiler.compile", args.ref, "--run", str(work),
                               "--key", args.key], capture_output=True, text=True)
        took = time.perf_counter() - t0
        if proc.returncode != 0:
            print(f"prep_time: compile {i + 1} failed: {proc.stderr[-400:]}", file=sys.stderr)
            continue
        times.append(took)
        hexd = args.ref.split("@sha256:")[-1]
        env = json.loads((work / "envelopes" / f"{hexd}.json").read_text())
        files = len(env.get("files") or {})
        packages = len(env.get("packages") or {})
        for k, v in (env.get("timings_ms") or {}).items():
            if isinstance(v, (int, float)):
                steps.setdefault(k, []).append(v)
    _append(args.out, {"system": "PROVBIND", "what": "compile the envelope (cold, fresh run folder)",
                       "seconds": round(statistics.median(times), 3) if times else None,
                       "seconds_all": [round(t, 3) for t in times], "n": len(times), "n_what": "compiles",
                       "files": files, "packages": packages, "steps_ms": {k: round(statistics.median(v), 1) for k, v in steps.items()}})


def _static(binaries):
    """Confine's static analysis in two timed parts: ELF import extraction, then mapping to system calls."""
    from eval.baselines.syscalls import LIBC_RUNTIME, syscalls_for
    from eval.baselines.trace import imports_under
    t0 = time.perf_counter()
    funcs, n_elf = imports_under(binaries)
    t_imports = time.perf_counter() - t0
    t0 = time.perf_counter()
    allow = syscalls_for(funcs) | (LIBC_RUNTIME if n_elf else set())
    t_map = time.perf_counter() - t0
    return allow, funcs, n_elf, t_imports, t_map


def _packages(args):
    return {"packages": args.packages, "files_outside_packages": args.unowned}


def confine(args):
    span, events = _trace_span_s(args.startup)
    # Confine watches a container's first seconds; the comparison run recorded for --startup-seconds
    # (STARTUP_SECONDS, 30), so that window is the time the method spends, even if the trace came out short
    observed = max(span, args.startup_seconds or 0.0)
    allow, funcs, n_elf, t_imports, t_map = _static(args.binaries)
    parts = {"startup_observation": round(observed, 3), "export_binaries": args.export_s,
             "elf_import_extraction": round(t_imports, 3), "syscall_mapping": round(t_map, 3)}
    _append(args.out, {"system": "Confine-E", "what": "start-up observation + export binaries + static analysis",
                       "seconds": round(sum(v for v in parts.values() if v), 3), "parts_s": parts,
                       "n": n_elf, "n_what": "ELF files analysed", **_packages(args),
                       "imported_functions": len(funcs), "allow_list": len(allow),
                       "startup_syscalls": events, "startup_trace_span_s": round(span, 3)})


def desfam(args):
    from eval.baselines.desfam_estimate import Detector, final_set
    from eval.baselines.trace import read_trace, syscalls_in
    paths = sorted(glob.glob(args.benign))
    spans = [_trace_span_s(p) for p in paths]
    profile = sum(s for s, _ in spans)
    _, _, n_elf, t_imports, t_map = _static(args.binaries)               # S_static, as Confine-E
    t0 = time.perf_counter()
    for path in paths:                                                   # S_dynamic from the profiling traces
        syscalls_in(read_trace(path))
    t_dynamic = time.perf_counter() - t0
    t0 = time.perf_counter()
    s_final, _ = final_set(args.binaries, paths, args.docker_seccomp)    # the whole Eq. 1 (for its size)
    t_final = time.perf_counter() - t0 - t_imports - t_map - t_dynamic   # what Eq. 1 adds on top
    t0 = time.perf_counter()
    det = Detector.train(paths)
    train_s = time.perf_counter() - t0
    parts = {"profiling": round(profile, 3), "static_allow_list": round(t_imports + t_map, 3),
             "dynamic_allow_list": round(t_dynamic, 3), "combine_eq1": round(max(0.0, t_final), 3),
             "isolation_forest_training": round(train_s, 3)}
    _append(args.out, {"system": "DeSFAM-E", "what": "benign profiling + allow list + Isolation Forest training",
                       "seconds": round(sum(parts.values()), 3), "parts_s": parts,
                       "n": args.requests, "n_what": "benign requests during profiling", **_packages(args),
                       "elf_files": n_elf, "profiling_runs": len(paths), "syscalls": sum(e for _, e in spans),
                       "windows": det.n_train, "allow_list": len(s_final)})


def mlb(args):
    import re
    text = Path(args.log).read_text(encoding="utf-8", errors="replace") if os.path.exists(args.log) else ""
    m = re.search(r"loadgen: (\d+) requests in (\d+)s", text)        # the first run is D2's training load
    load_s, requests = (float(m.group(2)), int(m.group(1))) if m else (None, None)
    windows = sum(sum(1 for line in open(Path(args.data) / f, encoding="utf-8") if line.strip())
                  for f in ("train.jsonl", "validation.jsonl") if (Path(args.data) / f).exists())
    work = Path(tempfile.mkdtemp(prefix="prep-mlb-", dir=args.work))
    t0 = time.perf_counter()
    proc = subprocess.run([sys.executable, "-m", "node.mlb", "train", "--data", args.data, "--run", str(work)],
                          capture_output=True, text=True)
    train_s = time.perf_counter() - t0 if proc.returncode == 0 else None
    _append(args.out, {"system": "PROVBIND + ML-B", "what": "benign load for D2 + model training",
                       "seconds": round((load_s or 0) + (train_s or 0), 3) if load_s else None,
                       "parts_s": {"benign_load": load_s, "training": round(train_s, 3) if train_s else None},
                       "n": requests, "n_what": "benign requests during D2", "windows": windows})


def falco(args):
    vals = [float(v) for v in args.ready_s]
    _append(args.out, {"system": "Falco", "what": "no per-image step (generic rules)", "seconds": 0.0,
                       "n": 0, "n_what": "per-image steps",
                       "restart_ready_s": round(statistics.median(vals), 3) if vals else None,
                       "restart_ready_all": vals, "restarts": len(vals)})


def _fmt(s):
    if s is None:
        return "—"
    return f"{s:.2f} s" if s < 60 else f"{s / 60:.1f} min ({s:.0f} s)"


def report(args):
    rows = {}
    for line in Path(args.prep).read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            rows[r["system"]] = r                      # the last row per system wins
    order = [s for s in ("PROVBIND", "PROVBIND + ML-B", "Falco", "Confine-E", "DeSFAM-E") if s in rows]
    out = ["# Preparation time per system (measured on the demo VM)", "",
           "| System | Time before a new image is protected | Made of | Count |", "|---|---|---|---|"]
    for s in order:
        r = rows[s]
        parts = r.get("parts_s") or {}
        made = ", ".join(f"{k.replace('_', ' ')} {_fmt(v)}" for k, v in parts.items() if v is not None) or r["what"]
        count = f"{r['n']} {r['n_what']}"
        if s == "PROVBIND":
            count += (f"; {r.get('packages')} packages, {r.get('files')} files per image; "
                      f"all: {r.get('seconds_all')}")
        elif s == "Confine-E":
            count += (f" from {r.get('packages')} packages (+{r.get('files_outside_packages')} outside any package), "
                      f"{r.get('imported_functions')} imported functions, {r.get('startup_syscalls')} start-up system calls")
        elif s == "PROVBIND + ML-B":
            count += f", {r.get('windows')} training windows"
        elif s == "DeSFAM-E":
            count += (f", {r.get('profiling_runs')} profiling runs, {r.get('syscalls')} system calls, "
                      f"{r.get('windows')} windows; {r.get('elf_files')} ELF files from {r.get('packages')} packages")
        elif s == "Falco":
            made = "no per-image step: generic rules apply at once"
            count = (f"DaemonSet ready after a restart in {_fmt(r.get('restart_ready_s'))} "
                     f"(median of {r.get('restarts')} restarts)")
        out.append(f"| {s} | {_fmt(r['seconds'])} | {made} | {count} |")
    Path(args.out).mkdir(parents=True, exist_ok=True)
    (Path(args.out) / "PREP.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    text = "\n".join(out) + "\n"
    (Path(args.out) / "PREP.md").write_text(text, encoding="utf-8")
    print(text)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.prep_time", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("provbind")
    p.add_argument("--ref", required=True)
    p.add_argument("--runs", type=int, default=5)
    p.add_argument("--work", required=True)
    p.add_argument("--key", default="pipeline/keys/cosign.pub")
    c = sub.add_parser("confine")
    c.add_argument("--binaries", required=True)
    c.add_argument("--startup", required=True)
    c.add_argument("--export-s", type=float)
    c.add_argument("--startup-seconds", type=float, default=30.0,
                   help="the start-up recording window the comparison run used (STARTUP_SECONDS, default 30)")
    c.add_argument("--packages", type=int, help="distinct packages owning the analysed ELF files")
    c.add_argument("--unowned", type=int, help="analysed files no package owns (e.g. a source-built runtime)")
    d = sub.add_parser("desfam")
    d.add_argument("--binaries", required=True)
    d.add_argument("--benign", required=True)
    d.add_argument("--requests", type=int)
    d.add_argument("--docker-seccomp")
    d.add_argument("--packages", type=int)
    d.add_argument("--unowned", type=int)
    m = sub.add_parser("mlb")
    m.add_argument("--log", required=True, help="scripts/record-d2.sh's log (run/record-d2.log)")
    m.add_argument("--data", required=True, help="ml/data/mlb/<hex>")
    m.add_argument("--work", required=True)
    f = sub.add_parser("falco")
    f.add_argument("--ready-s", nargs="*", default=[])
    for s in (p, c, d, m, f):
        s.add_argument("--out", required=True)
    r = sub.add_parser("report")
    r.add_argument("--prep", required=True)
    r.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    if args.cmd in ("provbind", "confine", "desfam", "mlb", "falco"):
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    {"provbind": provbind, "confine": confine, "desfam": desfam, "mlb": mlb, "falco": falco,
     "report": report}[args.cmd](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
