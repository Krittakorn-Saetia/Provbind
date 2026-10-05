"""The overhead test (scripts/overhead-run.sh): what PROVBIND costs at runtime, against no monitoring
and against Falco, and whether that cost stays within the 20% the supervisor set.

    python -m eval.overhead sample > before.json                      # CPU and memory of every monitor
    python -m eval.overhead cpu --before before.json --after after.json --seconds 300
    python -m eval.overhead record --out R --config provbind --rep 2 --kind mix < client.json
    python -m eval.overhead report --dir run-overhead/results [--comparison run/results/COMPARISON.json]
                                   [--oh01 run/results/OH-01.json] [--threshold 20]

Configurations (each run several times, in shuffled order, on the same VM and the same demo pod):
- `none`: no runtime monitor (Tetragon and Falco stopped);
- `falco`: Falco only, its default rules;
- `tetragon`: Tetragon with PROVBIND's five tracing policies, its output read and thrown away (the
  sensor's share of PROVBIND's cost);
- `provbind`: the whole of PROVBIND (Tetragon with the policies, controller, node with ML-B and the egress
  list, alert engine, trust loop).

Workloads: `mix` (the load generator's request mix, in-cluster client), `cache` (only the app's file-
writing endpoint), and `micro` (the worst case: tight loops of file writes and process spawns, every
one a hooked event). Overhead = (config - none) / none for times, and the loss of throughput for rps.
The report also states PROVBIND's overhead minus Falco's, and puts the cost beside each system's
detection results (F1, false-positive rate) when a COMPARISON.json is given.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from pathlib import Path

GROUPS = {
    "tetragon": lambda comm, cmd: comm == "tetragon",
    "falco": lambda comm, cmd: comm == "falco",
    "provbind": lambda comm, cmd: "python" in comm and any(m in cmd for m in
                                                           ("node.run", "controller.watch", "alerts.run",
                                                            "alerts.trust")),
    "export": lambda comm, cmd: (comm == "kubectl" and "ds/tetragon" in cmd)
                                or (comm in ("docker", "tail") and "tetragon.log" in cmd),
    "app": lambda comm, cmd: "python" in comm and "app.py" in cmd,
}
MONITOR_GROUPS = ("tetragon", "falco", "provbind", "export")
CONFIGS = ("none", "falco", "tetragon", "provbind")
TICK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100


# --- sampling -------------------------------------------------------------------------------------

def _read(path: str) -> str:
    try:
        with open(path, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def sample(proc: str = "/proc") -> dict:
    """CPU seconds (utime + stime) and RSS of every process in a group, plus the host's CPU counters."""
    pids, others = {}, {}
    for name in os.listdir(proc):
        if not name.isdigit():
            continue
        stat = _read(f"{proc}/{name}/stat")
        if not stat or ")" not in stat:
            continue
        comm = stat[stat.index("(") + 1:stat.rindex(")")]
        fields = stat[stat.rindex(")") + 2:].split()
        cmd = _read(f"{proc}/{name}/cmdline").replace("\0", " ")
        group = next((g for g, match in GROUPS.items() if match(comm, cmd)), None)
        cpu = (int(fields[11]) + int(fields[12])) / TICK         # utime, stime (fields 14 and 15)
        if group is None:                                         # everything else: for "where the time goes"
            others[name] = {"comm": comm, "cmd": cmd[:80], "cpu_s": cpu}
            continue
        rss = 0
        for line in _read(f"{proc}/{name}/status").splitlines():
            if line.startswith("VmRSS:"):
                rss = int(line.split()[1])
        pids[name] = {"group": group, "cpu_s": cpu, "rss_kb": rss}
    cpu_line = next((ln for ln in _read(f"{proc}/stat").splitlines() if ln.startswith("cpu ")), "cpu 0 0 0 0")
    vals = [int(x) for x in cpu_line.split()[1:]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    return {"time": time.time(), "pids": pids, "others": others, "host": {"total": sum(vals), "idle": idle}}


def cpu_delta(before: dict, after: dict, seconds: float | None = None) -> dict:
    elapsed = seconds or max(1e-9, after["time"] - before["time"])
    out = {}
    for g in GROUPS:
        cpu, rss = 0.0, 0
        for pid, p in after["pids"].items():
            if p["group"] != g:
                continue
            prev = before["pids"].get(pid)
            cpu += p["cpu_s"] - (prev["cpu_s"] if prev and prev["group"] == g else 0.0)
            rss += p["rss_kb"]
        out[g] = {"cpu_pct": round(100.0 * cpu / elapsed, 2), "rss_mb": round(rss / 1024, 1)}
    dt = after["host"]["total"] - before["host"]["total"]
    di = after["host"]["idle"] - before["host"]["idle"]
    out["host_busy_pct"] = round(100.0 * (dt - di) / dt, 2) if dt > 0 else None
    out["monitor_cpu_pct"] = round(sum(out[g]["cpu_pct"] for g in MONITOR_GROUPS), 2)
    out["monitor_rss_mb"] = round(sum(out[g]["rss_mb"] for g in MONITOR_GROUPS), 1)
    out["seconds"] = round(elapsed, 1)
    # the top CPU users over the window, monitors or not (kubelet, apiserver, containerd, the app...)
    top = {}
    for pid, p in list(after.get("others", {}).items()) + [(k, {"comm": v["group"], "cpu_s": v["cpu_s"]})
                                                            for k, v in after["pids"].items()]:
        prev = before.get("others", {}).get(pid) or before["pids"].get(pid)
        d = p["cpu_s"] - (prev["cpu_s"] if prev else 0.0)
        top[p["comm"]] = top.get(p["comm"], 0.0) + d
    out["top"] = [[k, round(100.0 * v / elapsed, 2)] for k, v in sorted(top.items(), key=lambda kv: -kv[1])[:10]]
    return out


# --- report ---------------------------------------------------------------------------------------

METRICS = [  # (kind, field, label, lower_is_better)
    ("mix", "p50_ms", "request latency p50, mix (ms)", True),
    ("mix", "p95_ms", "request latency p95, mix (ms)", True),
    ("mix", "rps", "throughput, mix (req/s)", False),
    ("cache", "p50_ms", "request latency p50, /cache (ms)", True),
    ("cache", "p95_ms", "request latency p95, /cache (ms)", True),
    ("cache", "rps", "throughput, /cache (req/s)", False),
    ("micro", "file_op_us", "file write, worst case (us/op)", True),
    ("micro", "spawn_ms", "process spawn, worst case (ms/op)", True),
]


def load_rows(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
    return rows


def spread_of(rows, config, kind, field):
    vals = [r[field] for r in rows if r.get("config") == config and r.get("kind") == kind
            and isinstance(r.get(field), (int, float))]
    return (min(vals), max(vals)) if vals else (None, None)


def median_of(rows, config, kind, field):
    vals = [r[field] for r in rows if r.get("config") == config and r.get("kind") == kind
            and isinstance(r.get(field), (int, float))]
    return (statistics.median(vals), len(vals)) if vals else (None, 0)


def overhead_pct(value, base, lower_is_better=True):
    if value is None or base in (None, 0):
        return None
    return round(100.0 * ((value - base) / base if lower_is_better else (base - value) / base), 1)


def build(rows, threshold=20.0, comparison=None, oh01=None) -> dict:
    configs = [c for c in CONFIGS if any(r.get("config") == c for r in rows)]
    table = []
    for kind, field, label, lower in METRICS:
        base, _ = median_of(rows, "none", kind, field)
        entry = {"metric": label, "kind": kind, "field": field, "values": {}, "overhead_pct": {}, "spread": {}}
        for c in configs:
            v, n = median_of(rows, c, kind, field)
            entry["values"][c] = v
            entry["spread"][c] = spread_of(rows, c, kind, field)
            entry["overhead_pct"][c] = overhead_pct(v, base, lower) if c != "none" else 0.0
        table.append(entry)
    cpu = {}
    for c in configs:
        for f in ("monitor_cpu_pct", "monitor_rss_mb", "host_busy_pct"):
            cpu.setdefault(c, {})[f] = median_of(rows, c, "cpu", f)[0]
        tops = [r.get("top") for r in rows if r.get("config") == c and r.get("kind") == "cpu" and r.get("top")]
        cpu[c]["top"] = tops[-1] if tops else None
    reps = {c: len({r.get("rep") for r in rows if r.get("config") == c}) for c in configs}
    failed = sorted({(r.get("config"), r.get("kind")) for r in rows if r.get("failed")})
    failed = [{"config": c, "kind": k, "count": sum(1 for r in rows if r.get("failed") and r.get("config") == c
                                                    and r.get("kind") == k)} for c, k in failed]

    def worst(config, kinds):
        vals = [e["overhead_pct"].get(config) for e in table if e["kind"] in kinds]
        vals = [v for v in vals if v is not None]
        return max(vals) if vals else None

    verdict = {}
    for c in ("provbind", "falco", "tetragon"):
        if c in configs:
            app = worst(c, ("mix", "cache"))
            micro = worst(c, ("micro",))
            verdict[c] = {"worst_app_overhead_pct": app, "worst_micro_overhead_pct": micro,
                          "app_within_threshold": app is not None and app <= threshold,
                          "micro_within_threshold": micro is not None and micro <= threshold}
    vs_falco = None
    if "provbind" in configs and "falco" in configs:
        vs_falco = {e["metric"]: (None if e["overhead_pct"].get("provbind") is None
                                  or e["overhead_pct"].get("falco") is None
                                  else round(e["overhead_pct"]["provbind"] - e["overhead_pct"]["falco"], 1))
                    for e in table}
        pc, fc = cpu["provbind"]["monitor_cpu_pct"], cpu["falco"]["monitor_cpu_pct"]
        vs_falco["monitor CPU, PROVBIND / Falco"] = round(pc / fc, 2) if pc is not None and fc else None
    vs_tetragon = None                 # the paper's own baseline: overhead over the existing runtime collection
    if "provbind" in configs and "tetragon" in configs:
        vs_tetragon = {}
        for kind, field, label, lower in METRICS:
            t, _ = median_of(rows, "tetragon", kind, field)
            p, _ = median_of(rows, "provbind", kind, field)
            vs_tetragon[label] = overhead_pct(p, t, lower)
    trade = None
    if comparison:
        systems = comparison.get("tables", {}).get("systems", {})
        trade = []
        for name, cfg in (("PROVBIND", "provbind"), ("Falco", "falco")):
            s = systems.get(name, {})
            v = verdict.get(cfg, {})
            trade.append({"system": name, "f1": s.get("f1"), "fpr": s.get("fpr"), "fp": s.get("FP"),
                          "tp": s.get("TP"), "worst_app_overhead_pct": v.get("worst_app_overhead_pct"),
                          "worst_micro_overhead_pct": v.get("worst_micro_overhead_pct"),
                          "monitor_cpu_pct": cpu.get(cfg, {}).get("monitor_cpu_pct")})
    return {"threshold_pct": threshold, "configs": configs, "repetitions": reps, "table": table, "cpu": cpu,
            "verdict": verdict, "provbind_minus_falco": vs_falco, "provbind_over_tetragon": vs_tetragon,
            "tradeoff": trade, "oh01": oh01, "failed": failed}


def fmt(v, unit=""):
    return "—" if v is None else (f"{v:.2f}{unit}" if isinstance(v, float) else f"{v}{unit}")


def render(doc) -> str:
    cs = doc["configs"]
    th = doc["threshold_pct"]
    out = ["# PROVBIND runtime overhead", "",
           f"Configurations: {', '.join(cs)}; repetitions: "
           + ", ".join(f"{c} {n}" for c, n in doc["repetitions"].items())
           + ". Values are medians over repetitions; overhead is against `none` (no monitor).", "",
           "| Metric | " + " | ".join(cs) + " | " + " | ".join(f"{c} overhead" for c in cs if c != "none") + " |",
           "|---|" + "---|" * (len(cs) * 2 - 1)]
    if doc.get("failed"):
        out[-2:-2] = ["**Failed workloads (no numbers; a — below may come from these):** "
                      + ", ".join(f"{f['config']} {f['kind']} x{f['count']}" for f in doc["failed"]) + ".", ""]
    for e in doc["table"]:
        out.append(f"| {e['metric']} | " + " | ".join(fmt(e["values"].get(c)) for c in cs) + " | "
                   + " | ".join(fmt(e["overhead_pct"].get(c), "%") for c in cs if c != "none") + " |")
    out += ["", "Spread over repetitions (min – max):", "", "| Metric | " + " | ".join(cs) + " |",
            "|---|" + "---|" * len(cs)]
    for e in doc["table"]:
        out.append(f"| {e['metric']} | " + " | ".join(
            f"{fmt((e.get('spread') or {}).get(c, (None, None))[0])} – {fmt((e.get('spread') or {}).get(c, (None, None))[1])}"
            for c in cs) + " |")
    out += ["", "| Configuration | monitor CPU (% of one core) | monitor memory (MB) | host CPU busy (%) |",
            "|---|---|---|---|"]
    for c in cs:
        m = doc["cpu"].get(c, {})
        out.append(f"| {c} | {fmt(m.get('monitor_cpu_pct'))} | {fmt(m.get('monitor_rss_mb'))} | "
                   f"{fmt(m.get('host_busy_pct'))} |")
    if any(doc["cpu"].get(c, {}).get("top") for c in cs):
        out += ["", "Top CPU users in the last repetition of each configuration (% of one core):", ""]
        for c in cs:
            t = doc["cpu"].get(c, {}).get("top")
            if t:
                out.append(f"- **{c}**: " + ", ".join(f"{k} {v:.1f}" for k, v in t))
    out += ["", f"## Against the {th:.0f}% limit", ""]
    for c, v in doc["verdict"].items():
        ok_app = "within" if v["app_within_threshold"] else "OVER"
        ok_mic = "within" if v["micro_within_threshold"] else "over"
        app_s = (f"{fmt(v['worst_app_overhead_pct'], '%')} ({ok_app} {th:.0f}%)"
                 if v["worst_app_overhead_pct"] is not None else "no data (the workloads failed)")
        mic_s = (f"{fmt(v['worst_micro_overhead_pct'], '%')} ({ok_mic} {th:.0f}%)"
                 if v["worst_micro_overhead_pct"] is not None else "no data (the workload failed)")
        out.append(f"- **{c}**: worst application overhead {app_s}; worst-case micro-benchmark {mic_s}.")
    if doc["provbind_minus_falco"]:
        out += ["", "## PROVBIND against Falco", "", "| Metric | PROVBIND overhead minus Falco overhead |",
                "|---|---|"]
        for k, v in doc["provbind_minus_falco"].items():
            out.append(f"| {k} | {fmt(v, '' if 'CPU,' in k else ' points')} |")
    if doc.get("provbind_over_tetragon"):
        out += ["", "## PROVBIND over the existing runtime collection (Tetragon with the same policies)", "",
                "The paper's evaluation plan reports overhead relative to the runtime collection, not to an "
                "unmonitored host: this is PROVBIND's own userspace cost.", "",
                "| Metric | PROVBIND vs Tetragon alone |", "|---|---|"]
        for k, v in doc["provbind_over_tetragon"].items():
            out.append(f"| {k} | {fmt(v, '%')} |")
    if doc["tradeoff"]:
        out += ["", "## Cost beside accuracy", "",
                "| System | TP | FP | F1 | FPR | worst app overhead | worst micro overhead | monitor CPU |",
                "|---|---|---|---|---|---|---|---|"]
        for t in doc["tradeoff"]:
            out.append(f"| {t['system']} | {fmt(t['tp'])} | {fmt(t['fp'])} | {fmt(t['f1'])} | {fmt(t['fpr'])} | "
                       f"{fmt(t['worst_app_overhead_pct'], '%')} | {fmt(t['worst_micro_overhead_pct'], '%')} | "
                       f"{fmt(t['monitor_cpu_pct'], '%')} |")
    if doc["oh01"]:
        m = doc["oh01"].get("metrics", doc["oh01"])
        out += ["", f"PROVBIND node, per-event verification (OH-01, replay of the comparison recording): "
                    f"p50 {fmt(m.get('p50_ns'))} ns, p99 {fmt(m.get('p99_ns'))} ns over {fmt(m.get('events'))} events."]
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.overhead", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sample")
    c = sub.add_parser("cpu")
    c.add_argument("--before", required=True)
    c.add_argument("--after", required=True)
    c.add_argument("--seconds", type=float)
    r = sub.add_parser("record")
    r.add_argument("--out", required=True)
    r.add_argument("--config", required=True, choices=CONFIGS)
    r.add_argument("--rep", type=int, required=True)
    r.add_argument("--kind", required=True, choices=("mix", "cache", "micro", "cpu"))
    p = sub.add_parser("report")
    p.add_argument("--dir", required=True, help="the results folder with overhead.jsonl")
    p.add_argument("--comparison", help="COMPARISON.json of the comparison run (accuracy beside cost)")
    p.add_argument("--oh01", help="OH-01.json (per-event verification latency)")
    p.add_argument("--threshold", type=float, default=20.0)
    args = ap.parse_args(argv)

    if args.cmd == "sample":
        print(json.dumps(sample()))
    elif args.cmd == "cpu":
        print(json.dumps(cpu_delta(json.load(open(args.before)), json.load(open(args.after)), args.seconds)))
    elif args.cmd == "record":
        text = sys.stdin.read().strip().splitlines()
        obj = json.loads(text[-1]) if text else {"failed": True}
        if not text:
            print(f"overhead: {args.config} rep {args.rep} {args.kind}: the workload printed nothing (failed)",
                  file=sys.stderr)
        obj.update({"config": args.config, "rep": args.rep, "kind": args.kind, "recorded": time.time()})
        with open(args.out, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj) + "\n")
    else:
        d = Path(args.dir)
        rows = load_rows(d / "overhead.jsonl")
        if not rows:
            print(f"overhead: no rows in {d / 'overhead.jsonl'}", file=sys.stderr)
            return 1
        comp = json.load(open(args.comparison)) if args.comparison and os.path.exists(args.comparison) else None
        oh01 = json.load(open(args.oh01)) if args.oh01 and os.path.exists(args.oh01) else None
        doc = build(rows, args.threshold, comp, oh01)
        (d / "OVERHEAD.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
        text = render(doc)
        (d / "OVERHEAD.md").write_text(text, encoding="utf-8")
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
