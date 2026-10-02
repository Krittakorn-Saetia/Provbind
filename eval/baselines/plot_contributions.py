"""Figures for the paper, one per contribution (C1-C4), plus a per-scenario detail figure, from one run
folder. PNG at 300 dpi, sized for the IEEE page (7.16 in across two columns, 3.5 in for one).

    python -m eval.baselines.plot_contributions --run "$PROVBIND_RUN" [--out <run>/results/figures] [--dpi 300]

| File | Contribution | (a) comparison | (b) PROVBIND's cost |
|---|---|---|---|
| fig1_c1_specification.png | C1 specification compilation | time until each system can protect a new image | compile time per step; runtime index |
| fig2_c2_verification.png | C2 runtime verification | detection rate and false-positive rate (runtime and benign scenarios) | per-event check latency (OH-01) |
| fig3_c3_attribution.png | C3 attribution | share of each system's detections that name container, process, rule, package, layer, dependency path | - |
| fig4_c4_trust.png | C4 trust re-evaluation | admission and trust scenarios: runs caught per system, Sig-only included | trust-loop reaction time |
| fig5_scenarios.png | detail | every scenario x system: runs flagged / runs | - |

Measured, estimated, by design. PROVBIND and Falco are measured from the run's files. Confine-E and
DeSFAM-E are estimated (their published design applied to our traces) and marked *; Sig-only is derived
from binding records and marked with a dagger. A value taken from a system's published design rather than
from any run is labelled "by design" and hatched. A panel whose input is missing says "not measured" and
how to measure it: nothing is invented.

Inputs, all in the run folder: results/COMPARISON.json (eval.baselines.aggregate --write),
ground_truth.csv, alerts.jsonl, falco.jsonl, envelopes/*.json, traces/baseline/benign-*.txt,
results/desfam.json, and results/OH-01.json, OH-04.json, OH-05.json (capability tests run on this run
folder; comparison-run.sh does it). The figure data is plain Python (and unit-tested); drawing needs
matplotlib. Prints the written paths on stdout; logs go to stderr.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from collections import Counter
from pathlib import Path

from eval.compare import alert_pod, confusion, falco_pod, load_ground_truth, load_jsonl, metrics, parse_time

# --- what is compared ---------------------------------------------------------------------------------
SYSTEMS = ("PROVBIND", "Falco", "Confine-E", "DeSFAM-E")           # figures 1-3; figure 4 adds Sig-only
KIND = {"PROVBIND": "measured", "Falco": "measured", "Confine-E": "estimated", "DeSFAM-E": "estimated",
        "Sig-only": "derived"}
MARK = {"measured": "", "estimated": "*", "derived": "†"}
NOT_DETECTION = {"tamper-1"}                    # a log-integrity check, not a detection run
C4_SCENARIOS = ("ak-1", "ak-2", "ak-3", "trust-1", "trust-2")   # threats that live in trust, not behaviour
C4_LABELS = {"ak-1": "A-K1  advisory before deploy", "ak-2": "A-K2  unsigned image",
             "ak-3": "A-K3  key revoked before deploy", "trust-1": "R-K1  advisory while running",
             "trust-2": "key revoked while running"}
CONFINE_STARTUP_S = 30.0                        # Confine watches a container's first 30 s (its design)
DEFAULT_PROFILE_S = 3 * 600.0                   # DeSFAM profiles 3 workload cycles; 3 x 10 min in our run
FIELDS = ("Container / pod", "Process", "Rule / clause / technique", "Package", "Image layer",
          "Dependency path")
BY_DESIGN_FIELDS = {"Confine-E": (0, 0, 0, 0, 0, 0),      # seccomp denies; no alert, no attribution
                    "DeSFAM-E": (1, 1, 1, 0, 0, 0)}       # container, process, MITRE technique

# scenario -> (comparison-grid id, cell); dict order is the order inside a cell (figure 5)
SCENARIOS = {
    "ak-1": ("A-K1", "Admission, known"), "ak-2": ("A-K2", "Admission, known"),
    "ak-3": ("A-K3", "Admission, known"), "au-2": ("A-U2", "Admission, unknown"),
    "trust-1": ("R-K1", "Runtime, known"), "trust-2": ("", "Runtime, known"),
    "rk-2": ("R-K2", "Runtime, known"), "rk-3": ("R-K3", "Runtime, known"),
    "attack-1": ("R-U1", "Runtime, unknown"), "attack-2": ("R-U2", "Runtime, unknown"),
    "ru-3": ("R-U3", "Runtime, unknown"), "ru-4": ("R-U4", "Runtime, unknown"),
    "ru-5": ("R-U5", "Runtime, unknown"),
    "benign-1": ("B1", "Benign"), "benign-traffic": ("B2", "Benign"), "ph4-14": ("B3", "Benign"),
    "benign-3": ("B4", "Benign"), "benign-4": ("B5", "Benign"),
}
CELLS = ("Admission, known", "Admission, unknown", "Runtime, known", "Runtime, unknown", "Benign", "Other")

# --- colours: the dataviz reference palette (light surface; categorical pair validated) ---------------
SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
S1, S2 = "#2a78d6", "#eb6834"                   # categorical slots 1 and 2
BLUE_RAMP = ("#fcfcfb", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b")
ORANGE_RAMP = ("#fcfcfb", "#fbdccd", "#f6b090", "#eb6834", "#b84a1f", "#7d3010")


# --- loading ------------------------------------------------------------------------------------------

def _json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _trace_span_s(path):
    """Seconds between the first and last event of a recorded trace (<nsecs>\\t...), or 0."""
    first = last = None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                head = line.split("\t", 1)[0].strip()
                if head.isdigit():
                    first = int(head) if first is None else first
                    last = int(head)
    except OSError:
        return 0.0
    return (last - first) / 1e9 if first is not None and last is not None else 0.0


def load_run(run):
    run = Path(run)
    doc = _json(run / "results" / "COMPARISON.json") or {}
    envs = [e for e in (_json(p) for p in sorted((run / "envelopes").glob("*.json"))) if isinstance(e, dict)]
    profile = sum(_trace_span_s(p) for p in sorted((run / "traces" / "baseline").glob("benign-*.txt")))
    return {"run": run, "rows": doc.get("rows") or [], "tables": doc.get("tables") or {},
            "gt": load_ground_truth(run / "ground_truth.csv"),
            "alerts": load_jsonl(run / "alerts.jsonl"), "falco": load_jsonl(run / "falco.jsonl"),
            "envelopes": envs, "profile_s": profile,
            "desfam": _json(run / "results" / "desfam.json") or {},
            "results": {i: _json(run / "results" / f"{i}.json") for i in ("OH-01", "OH-04", "OH-05")}}


def _real(result):
    """A capability result measured on real input (not the synthetic stand-in), or None."""
    if not isinstance(result, dict) or result.get("status") == "not_run":
        return None
    return None if "synthetic" in (result.get("notes") or "") else result


# --- figure data (no matplotlib) ----------------------------------------------------------------------

def compile_seconds(env):
    t = env.get("timings_ms") or {}
    return round(sum(v for v in t.values() if isinstance(v, (int, float))) / 1000, 2) if t else None


def c1_readiness(d):
    """Figure 1a: time until each system can protect a new image."""
    comp = [s for s in (compile_seconds(e) for e in d["envelopes"]) if s]
    profile = d["profile_s"] or DEFAULT_PROFILE_S
    return [
        {"system": "PROVBIND", "seconds": statistics.median(comp) if comp else None, "how": "measured",
         "note": f"compile, median of {len(comp)} image{'s' if len(comp) != 1 else ''}" if comp else "not measured"},
        {"system": "Falco", "seconds": None, "how": "none", "note": "generic rules: no image-specific specification"},
        {"system": "Confine-E", "seconds": CONFINE_STARTUP_S, "how": "by design",
         "note": "≥ 30 s start-up observation, plus static analysis"},
        {"system": "DeSFAM-E", "seconds": profile, "how": "by design",
         "note": f"≥ {profile / 60:.0f} min benign profiling" + (" (our run)" if d["profile_s"] else "")
                 + ", plus training"},
    ]


def c1_steps(d):
    """Figure 1b: median time per compiler step over the run's envelopes, and the runtime index."""
    per = {}
    for e in d["envelopes"]:
        for k, v in (e.get("timings_ms") or {}).items():
            if isinstance(v, (int, float)):
                per.setdefault(k, []).append(v)
    steps = sorted(((k, statistics.median(v)) for k, v in per.items()), key=lambda kv: -kv[1])
    files = [len(e.get("files") or {}) for e in d["envelopes"]]
    oh4, oh5 = _real(d["results"].get("OH-04")), _real(d["results"].get("OH-05"))
    index_ms = statistics.median((oh4["metrics"].get("index_ms") or {}).values()) if oh4 and \
        (oh4["metrics"].get("index_ms") or {}) else None
    kb_per_1000 = statistics.median((oh5["metrics"].get("index_bytes_per_1000_files") or {}).values()) / 1024 \
        if oh5 and (oh5["metrics"].get("index_bytes_per_1000_files") or {}) else None
    return {"steps": steps, "total_s": round(sum(v for _, v in steps) / 1000, 2) if steps else None,
            "images": len(d["envelopes"]), "files": int(statistics.median(files)) if files else None,
            "index_ms": index_ms, "index_kb_per_1000_files": kb_per_1000}


def c2_rows(rows):
    """Runtime and benign scenario runs: everything but the trust/admission-trust cell and tamper-1."""
    return [r for r in rows if r.get("label") in ("malicious", "benign")
            and r.get("scenario") not in NOT_DETECTION and r.get("scenario") not in C4_SCENARIOS]


def c2_metrics(rows):
    """Figure 2a: detection rate (recall) and false-positive rate per system."""
    sel = c2_rows(rows)
    out = []
    for s in SYSTEMS:
        c = confusion(sel, s)
        m = metrics(c)
        out.append({"system": s, "kind": KIND[s], "recall": m["recall"], "fpr": m["fpr"],
                    "attack_runs": c["TP"] + c["FN"], "benign_runs": c["FP"] + c["TN"]})
    return out


def c2_latency(d):
    """Figure 2b: per-event check latency from OH-01 on a real recording, or None."""
    r = _real(d["results"].get("OH-01"))
    if not r or r["metrics"].get("p50_ns") is None:
        return None
    m = r["metrics"]
    return {"p50_us": m["p50_ns"] / 1000, "p99_us": m["p99_ns"] / 1000, "events": m.get("events", 0),
            "short": m.get("events", 0) < 100_000}


def _attack_windows(gt):
    return [(g.get("namespace", ""), g.get("pod_prefix", ""), parse_time(g.get("start")), parse_time(g.get("end")))
            for g in gt if g.get("label") == "malicious" and g.get("scenario") not in NOT_DETECTION]


def _in_any(windows, ns, pod, t):
    return t is not None and any(ns == w_ns and prefix and pod.startswith(prefix) and s and e and s <= t <= e
                                 for w_ns, prefix, s, e in windows)


def _prov_fields(a):
    at = a.get("attribution") or {}
    clause = (a.get("violated_clause") or "").replace(":", "").strip()
    return (bool(a.get("container") or a.get("pod")), bool(at.get("process_chain")), bool(clause),
            at.get("package") not in (None, ""), at.get("layer") not in (None, ""), bool(at.get("dependency_path")))


def _falco_fields(line):
    f = line.get("output_fields") or {}
    return (bool(f.get("k8s.pod.name") or f.get("container.id") or f.get("container.name")),
            bool(f.get("proc.name") or f.get("proc.exepath") or f.get("proc.cmdline")),
            bool(line.get("rule")), False, False, False)


def c3_attribution(d):
    """Figure 3: share of each system's runtime detections in attack runs that name each field."""
    w = _attack_windows(d["gt"])
    prov = [a for a in d["alerts"] if str(a.get("class", "")).startswith("D_")
            and str(a.get("bucket", "")).lower() in ("critical", "high", "medium")
            and _in_any(w, *alert_pod(a), parse_time(a.get("time")))]
    falco = [x for x in d["falco"] if _in_any(w, *falco_pod(x), parse_time(x.get("time")))]
    share, n, how = {}, {}, {}
    for name, items, fn in (("PROVBIND", prov, _prov_fields), ("Falco", falco, _falco_fields)):
        n[name], how[name] = len(items), "measured"
        share[name] = [sum(fn(x)[i] for x in items) / len(items) for i in range(len(FIELDS))] if items else None
    for name, flags in BY_DESIGN_FIELDS.items():
        n[name], how[name], share[name] = None, "by design", [float(v) for v in flags]
    return {"fields": FIELDS, "systems": SYSTEMS, "share": share, "n": n, "how": how}


def c4_matrix(rows):
    """Figure 4a: for each admission/trust scenario, runs caught per system (Sig-only included)."""
    systems = SYSTEMS + ("Sig-only",)
    out = []
    for s in C4_SCENARIOS:
        rs = [r for r in rows if r.get("scenario") == s]
        if not rs:
            continue
        stages = Counter(r.get("PROVBIND_stage") for r in rs if r.get("PROVBIND"))
        out.append({"scenario": s, "label": C4_LABELS[s], "runs": len(rs),
                    "caught": [sum(bool(r.get(m)) for r in rs) for m in systems],
                    "provbind_stage": stages.most_common(1)[0][0] if stages else None})
    return systems, out


def c4_trust_latency(alerts):
    """Figure 4b: trust-loop reaction time (input change -> trust alert), grouped by what changed."""
    groups = {"Key revoked": [], "Advisory\n(component)": [], "Other": []}
    for a in alerts:
        if a.get("class") != "trust" or not isinstance(a.get("latency_s"), (int, float)):
            continue
        sub = str(a.get("subclass") or "")
        key = "Key revoked" if "key" in sub else "Advisory\n(component)" if "comp" in sub else "Other"
        groups[key].append(float(a["latency_s"]))
    return {k: v for k, v in groups.items() if v}


def _place(s):
    pid, cell = SCENARIOS.get(s["scenario"], ("", None))
    if cell is None:
        cell = "Benign" if s.get("label") == "benign" else "Other"
    order = list(SCENARIOS).index(s["scenario"]) if s["scenario"] in SCENARIOS else len(SCENARIOS)
    return CELLS.index(cell), order, pid, cell


def heatmap(tables):
    """Figure 5: (system names, rows in grid order) with runs flagged / runs per system."""
    names = list((tables.get("systems") or {}).keys())
    placed = []
    for s in tables.get("per_scenario") or []:
        if s["scenario"] in NOT_DETECTION or not s.get("runs"):
            continue
        ci, order, pid, cell = _place(s)
        placed.append(((ci, order, s["scenario"]), pid, cell, s))
    placed.sort(key=lambda p: p[0])
    rows = []
    for _, pid, cell, s in placed:
        n = s["runs"]
        rows.append({"scenario": s["scenario"], "label": f"{pid}  {s['scenario']}" if pid else s["scenario"],
                     "cell": cell, "truth": s.get("label"), "runs": n,
                     "fraction": [s.get(m, 0) / n for m in names], "counts": [f"{s.get(m, 0)}/{n}" for m in names]})
    return names, rows


# --- drawing ------------------------------------------------------------------------------------------

def _plt():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "font.family": "sans-serif", "font.sans-serif": ["DejaVu Sans"], "font.size": 7.5,
        "text.color": INK, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
        "axes.edgecolor": AXIS, "axes.linewidth": 0.6, "xtick.major.width": 0.6, "ytick.major.width": 0.6,
        "xtick.major.size": 2.5, "ytick.major.size": 2.5, "axes.spines.top": False, "axes.spines.right": False,
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "legend.frameon": False, "hatch.linewidth": 0.7, "hatch.color": SURFACE})
    return plt


def _cmap(colours, name):
    from matplotlib.colors import LinearSegmentedColormap
    return LinearSegmentedColormap.from_list(name, colours)


def _grid(ax, axis="y"):
    ax.grid(axis=axis, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)


def _panel(ax, letter, title):
    ax.set_title(f"({letter})  {title}", loc="left", fontsize=8, color=INK, pad=6)


def _empty(ax, text):
    ax.set_axis_off()
    ax.text(0.5, 0.5, text, ha="center", va="center", fontsize=7.5, color=INK2, transform=ax.transAxes)


def _tick(name, kind):
    return name + MARK.get(kind, "")


def _footer(fig, lines):
    fig.text(0.0, -0.02, "\n".join(lines), ha="left", va="top", fontsize=6.3, color=INK2, transform=fig.transFigure)


def _save(plt, fig, path, dpi):
    tmp = str(path) + ".tmp"                    # whole-file output: temp file, then rename (CLAUDE.md)
    fig.savefig(tmp, dpi=dpi, bbox_inches="tight", format="png")
    plt.close(fig)
    os.replace(tmp, path)
    return str(path)


def _fmt_s(s):
    if s < 10:
        return f"{s:.1f} s"
    return f"{s:.0f} s" if s < 60 else f"{s / 60:.0f} min" if s < 3600 else f"{s / 3600:.1f} h"


def _note_below(ax, text, y=-0.36):
    """A one-line note under a panel's x-axis label, so it never sits on the data."""
    ax.text(0.0, y, text, transform=ax.transAxes, ha="left", va="top", fontsize=6.3, color=INK2)


def fig1_c1(d, path, dpi):
    plt = _plt()
    from matplotlib.patches import Patch
    fig, (a, b) = plt.subplots(1, 2, figsize=(7.16, 2.5), gridspec_kw={"width_ratios": [1.1, 1]})
    ready = c1_readiness(d)
    ys = list(range(len(ready)))[::-1]
    vals = [r["seconds"] for r in ready if r["seconds"]]
    lo, hi = (min(vals) / 3 if vals else 1), (max(vals) * 6 if vals else 3600)
    for y, r in zip(ys, ready):
        if r["seconds"] is None:
            a.text(lo * 1.15, y, r["note"] if r["how"] == "none" else "not measured", va="center", fontsize=6.8,
                   color=INK2, style="italic")
            continue
        a.barh(y, r["seconds"] - lo, height=0.5, left=lo, color=S1, edgecolor=SURFACE, linewidth=1,
               hatch="///" if r["how"] == "by design" else None)        # from the axis edge to the value
        label = ("≥ " if r["how"] == "by design" else "") + _fmt_s(r["seconds"])
        a.text(r["seconds"] * 1.12, y, label, va="center", fontsize=7, color=INK)
    a.set_xscale("log")
    a.set_xlim(lo, hi)
    ticks = [t for t in (1, 10, 60, 600, 3600, 36000) if lo <= t <= hi]
    a.set_xticks(ticks)
    a.set_xticklabels([{1: "1 s", 10: "10 s", 60: "1 min", 600: "10 min", 3600: "1 h", 36000: "10 h"}[t] for t in ticks])
    a.minorticks_off()
    a.set_yticks(ys)
    a.set_yticklabels([_tick(r["system"], KIND[r["system"]]) for r in ready])
    a.tick_params(axis="y", length=0)
    _grid(a, "x")
    _panel(a, "a", "Time until a new image is protected")
    a.legend(handles=[Patch(facecolor=S1, edgecolor=SURFACE, label="measured in this run"),
                      Patch(facecolor=S1, edgecolor=SURFACE, hatch="///", label="by design (minimum the method needs)")],
             loc="upper center", bbox_to_anchor=(0.5, -0.17), ncol=2, fontsize=6.5)

    st = c1_steps(d)
    if not st["steps"]:
        _empty(b, "Not measured: no envelope in this run folder.")
    else:
        names = [k for k, _ in st["steps"]][::-1]
        ms = [v for _, v in st["steps"]][::-1]
        b.barh(range(len(ms)), ms, height=0.55, color=S1, edgecolor=SURFACE, linewidth=1)
        for i, v in enumerate(ms):
            b.text(v + max(ms) * 0.02, i, f"{v / 1000:.2f} s" if v >= 100 else f"{v:.0f} ms", va="center",
                   fontsize=6.5, color=INK)
        b.set_yticks(range(len(ms)))
        b.set_yticklabels(names)
        b.tick_params(axis="y", length=0)
        b.set_xlim(0, max(ms) * 1.22)
        b.set_xlabel("ms (median over images)")
        _grid(b, "x")
        _panel(b, "b", f"PROVBIND compile, per step: {st['total_s']:.1f} s for {st['files']:,} files")
        idx = ("Runtime index: " + (f"built in {st['index_ms']:.1f} ms" if st["index_ms"] is not None else "build time not measured")
               + (f", {st['index_kb_per_1000_files']:.0f} KB per 1,000 files" if st["index_kb_per_1000_files"] is not None
                  else ", memory not measured") + "  (OH-04, OH-05)")
        _note_below(b, idx)
    fig.tight_layout(w_pad=2.5)
    _footer(fig, ["C1. PROVBIND's specification is compiled from signed build evidence, so it exists before the workload runs; "
                  "the compile is paid once per image digest, not per pod.",
                  "Falco uses hand-written generic rules. * Confine-E and DeSFAM-E: estimated systems; their bars are the "
                  "observation their published design needs before it can protect a new image."])
    return _save(plt, fig, path, dpi)


def fig2_c2(d, path, dpi):
    plt = _plt()
    from matplotlib.patches import Patch
    fig, (a, b) = plt.subplots(1, 2, figsize=(7.16, 2.5), gridspec_kw={"width_ratios": [2.2, 1]})
    data = c2_metrics(d["rows"])
    w = 0.36
    for i, m in enumerate(data):
        hatch = "///" if m["kind"] != "measured" else None
        for off, key, col in ((-w / 2, "recall", S1), (w / 2, "fpr", S2)):
            v = m[key]
            if v is None:
                a.text(i + off, 0.02, "n/a", ha="center", va="bottom", fontsize=6, color=MUTED, rotation=90)
                continue
            a.bar(i + off, v, w, color=col, edgecolor=SURFACE, linewidth=1, hatch=hatch)
            a.text(i + off, v + 0.02, f"{v:.2f}", ha="center", va="bottom", fontsize=6.5, color=INK)
    a.set_xticks(range(len(data)))
    a.set_xticklabels([_tick(m["system"], m["kind"]) for m in data], fontsize=7)
    a.tick_params(axis="x", length=0)
    a.set_ylim(0, 1.15)
    a.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    a.set_ylabel("share of runs")
    _grid(a, "y")
    _panel(a, "a", "Detection rate vs false-positive rate")
    a.legend(handles=[Patch(facecolor=S1, edgecolor=SURFACE, label="detection rate (attack runs)"),
                      Patch(facecolor=S2, edgecolor=SURFACE, label="false-positive rate (benign runs)"),
                      Patch(facecolor="#d9d8d3", edgecolor=SURFACE, hatch="///", label="* estimated system")],
             loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=3, fontsize=6.5)

    lat = c2_latency(d)
    if lat is None:
        _empty(b, "(b)  Per-event check latency\n\nNot measured.\nRun OH-01 on this run's rec.jsonl\n"
                  "(comparison-run.sh does it).")
    else:
        vals = [lat["p50_us"], lat["p99_us"]]
        b.barh([1, 0], vals, height=0.32, color=S1, edgecolor=SURFACE, linewidth=1)
        for y, v in zip([1, 0], vals):
            b.text(v + max(vals) * 0.03, y, f"{v:.1f} µs", va="center", fontsize=7, color=INK)
        b.set_yticks([1, 0])
        b.set_yticklabels(["p50", "p99"])
        b.tick_params(axis="y", length=0)
        b.set_xlim(0, max(vals) * 1.3)
        b.set_xlabel("µs per event")
        _grid(b, "x")
        _panel(b, "b", "PROVBIND per-event check latency")
        note = f"{lat['events']:,} real events (OH-01)" + ("; the plan asks for ≥ 100,000" if lat["short"] else "")
        _note_below(b, note)
    fig.tight_layout(w_pad=2.5)
    n_att = data[0]["attack_runs"] if data else 0
    n_ben = data[0]["benign_runs"] if data else 0
    pub = (d["desfam"].get("published_reference") or {})
    foot = [f"C2. Runtime and benign scenarios ({n_att} attack runs, {n_ben} benign runs); the admission and trust "
            "scenarios are in Figure 4. PROVBIND checks events against its signed specification instead of a learned baseline."]
    if pub:
        foot.append(f"* Estimated systems. DeSFAM's own published operating point (its data, not ours): detection "
                    f"{pub.get('recall')}, false-positive rate {pub.get('fpr')}.")
    _footer(fig, foot)
    return _save(plt, fig, path, dpi)


def fig3_c3(d, path, dpi):
    plt = _plt()
    import numpy as np
    att = c3_attribution(d)
    systems, fields = att["systems"], att["fields"]
    cmap = _cmap(BLUE_RAMP, "blue")
    grid = np.full((len(fields), len(systems)), np.nan)
    for j, s in enumerate(systems):
        if att["share"][s] is not None:
            grid[:, j] = att["share"][s]
    fig, ax = plt.subplots(figsize=(3.5, 2.55))
    shown = np.where(np.isnan(grid), 0, grid)
    rgba = cmap(0.06 + 0.86 * shown)
    rgba[np.isnan(grid)] = (0.94, 0.94, 0.93, 1)
    ax.imshow(rgba, aspect="auto")
    for i in range(len(fields)):
        for j in range(len(systems)):
            v = grid[i, j]
            txt = "n/a" if np.isnan(v) else f"{v * 100:.0f}%"
            ax.text(j, i, txt, ha="center", va="center", fontsize=6.8,
                    color=SURFACE if (not np.isnan(v) and v > 0.55) else INK)
    labels = []
    for s in systems:
        sub = f"n = {att['n'][s]}" if att["how"][s] == "measured" else "by design"
        labels.append(f"{_tick(s, KIND[s])}\n{sub}")
    ax.set_xticks(range(len(systems)))
    ax.set_xticklabels(labels, fontsize=6.8)
    ax.xaxis.tick_top()
    ax.set_yticks(range(len(fields)))
    ax.set_yticklabels(fields)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_xticks(np.arange(-0.5, len(systems)), minor=True)
    ax.set_yticks(np.arange(-0.5, len(fields)), minor=True)
    ax.grid(which="minor", color=SURFACE, linewidth=2)
    ax.tick_params(which="minor", length=0)
    _footer(fig, ["C3. Share of each system's runtime detections in attack runs that name each item.",
                  "PROVBIND and Falco: measured from their alert files (n = detections).",
                  "* Confine-E, DeSFAM-E: estimated systems; their published design."])
    return _save(plt, fig, path, dpi)


def fig4_c4(d, path, dpi):
    plt = _plt()
    import numpy as np
    fig, (a, b) = plt.subplots(1, 2, figsize=(7.16, 2.4), gridspec_kw={"width_ratios": [1.6, 1]})
    systems, rows = c4_matrix(d["rows"])
    if not rows:
        _empty(a, "(a)  Admission and trust scenarios\n\nNo A-K or trust rows in this run.")
    else:
        cmap = _cmap(BLUE_RAMP, "blue")
        frac = np.array([[c / r["runs"] for c in r["caught"]] for r in rows])
        a.imshow(cmap(0.06 + 0.86 * frac), aspect="auto")
        for i, r in enumerate(rows):
            for j, c in enumerate(r["caught"]):
                txt = f"{c}/{r['runs']}"
                if systems[j] == "PROVBIND" and c and r["provbind_stage"]:
                    txt += "\n" + {"trust": "trust loop", "admission": "admission"}.get(r["provbind_stage"],
                                                                                    r["provbind_stage"])
                a.text(j, i, txt, ha="center", va="center", fontsize=6.3,
                       color=SURFACE if frac[i, j] > 0.55 else INK)
        a.set_xticks(range(len(systems)))
        a.set_xticklabels([_tick(s, KIND[s]) for s in systems], fontsize=6.8)
        a.xaxis.tick_top()
        a.set_yticks(range(len(rows)))
        a.set_yticklabels([r["label"] for r in rows])
        a.tick_params(length=0)
        for sp in a.spines.values():
            sp.set_visible(False)
        a.set_xticks(np.arange(-0.5, len(systems)), minor=True)
        a.set_yticks(np.arange(-0.5, len(rows)), minor=True)
        a.grid(which="minor", color=SURFACE, linewidth=2)
        a.tick_params(which="minor", length=0)
        a.set_title("(a)  Threats that live in trust, not behaviour: runs caught", loc="left", fontsize=8, pad=24)

    lat = c4_trust_latency(d["alerts"])
    if not lat:
        _empty(b, "(b)  Trust-loop reaction time\n\nNot measured: no trust alert\nwith latency_s in this run.")
    else:
        import random
        rnd = random.Random(7)
        top = max(max(v) for v in lat.values())
        for x, (name, vals) in enumerate(lat.items()):
            xs = [x + rnd.uniform(-0.12, 0.12) for _ in vals]
            b.scatter(xs, vals, s=14, color=S1, edgecolors=SURFACE, linewidths=0.8, zorder=3)
            med = statistics.median(vals)
            b.plot([x - 0.25, x + 0.25], [med, med], color=INK, linewidth=1.2, zorder=4)
            b.text(x, top * 1.08, f"median {med:.1f} s\nn = {len(vals)}", ha="center", va="bottom", fontsize=6.3,
                   color=INK)                    # above its own group, clear of the dots
        b.set_xticks(range(len(lat)))
        b.set_xticklabels(list(lat))
        b.set_xlim(-0.6, len(lat) - 0.4)
        b.set_ylim(0, top * 1.45)
        b.set_ylabel("seconds to alert")
        b.tick_params(axis="x", length=0)
        _grid(b, "y")
        _panel(b, "b", "PROVBIND trust-loop reaction time")
    fig.tight_layout(w_pad=2.5)
    _footer(fig, ["C4. A-K: the trust problem exists before deploy; R-K1 and key revocation: it appears while the pod runs, "
                  "with no change in behaviour.",
                  "PROVBIND cells show the stage that caught it. † Sig-only: signature check at admission, derived from "
                  "binding records. * Estimated systems."])
    return _save(plt, fig, path, dpi)


def fig5_scenarios(d, path, dpi):
    plt = _plt()
    import numpy as np
    names, rows = heatmap(d["tables"])
    if not rows:
        raise ValueError("no scenario rows in COMPARISON.json")
    blues, oranges = _cmap(BLUE_RAMP, "blue"), _cmap(ORANGE_RAMP, "orange")
    rgba = np.zeros((len(rows), len(names), 4))
    for i, r in enumerate(rows):
        cm = oranges if r["truth"] == "benign" else blues
        for j, f in enumerate(r["fraction"]):
            rgba[i, j] = cm(0.06 + 0.86 * f)
    fig, ax = plt.subplots(figsize=(3.5, 0.2 * len(rows) + 0.9))
    ax.imshow(rgba, aspect="auto")
    for i, r in enumerate(rows):
        for j, (f, c) in enumerate(zip(r["fraction"], r["counts"])):
            ax.text(j, i, c, ha="center", va="center", fontsize=6, color=SURFACE if f > 0.55 else INK)
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels([_tick(n, KIND.get(n, "measured")) for n in names], rotation=30, ha="left", fontsize=6.8)
    ax.xaxis.tick_top()
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([r["label"] for r in rows], fontsize=6.8)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_xticks(np.arange(-0.5, len(names)), minor=True)
    ax.set_yticks(np.arange(-0.5, len(rows)), minor=True)
    ax.grid(which="minor", color=SURFACE, linewidth=1.5)
    ax.tick_params(which="minor", length=0)
    spans = {}
    for i, r in enumerate(rows):
        spans.setdefault(r["cell"], [i, i])[1] = i
    for cell, (s, e) in spans.items():
        if s:
            ax.axhline(s - 0.5, color=INK2, linewidth=0.8)
        ax.text(len(names) - 0.35, (s + e) / 2, cell, va="center", ha="left", fontsize=6.3, color=INK2,
                style="italic", clip_on=False)
    _footer(fig, ["Cell: runs flagged / runs. Blue rows: attacks (flagged = detected).",
                  "Orange rows: benign (flagged = false alarm).",
                  "* estimated systems; † Sig-only, derived from binding records."])
    return _save(plt, fig, path, dpi)


FIGURES = (("fig1_c1_specification.png", fig1_c1), ("fig2_c2_verification.png", fig2_c2),
           ("fig3_c3_attribution.png", fig3_c3), ("fig4_c4_trust.png", fig4_c4),
           ("fig5_scenarios.png", fig5_scenarios))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.baselines.plot_contributions", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"))
    ap.add_argument("--out", help="output directory (default <run>/results/figures)")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args(argv)
    d = load_run(args.run)
    if not d["rows"]:
        print(f"plot_contributions: no rows in {args.run}/results/COMPARISON.json "
              "(run eval.baselines.aggregate --write first)", file=sys.stderr)
        return 1
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        print("plot_contributions: matplotlib is not installed (pip install -r requirements.txt)", file=sys.stderr)
        return 3
    out = Path(args.out or Path(args.run) / "results" / "figures")
    out.mkdir(parents=True, exist_ok=True)
    for name, fn in FIGURES:
        print(fn(d, out / name, args.dpi))
    return 0


if __name__ == "__main__":
    sys.exit(main())
