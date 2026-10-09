"""Figures for the paper, one per contribution (C1-C4), plus a per-scenario detail figure, from one run
folder. PNG at 300 dpi, sized for the IEEE page (7.16 in across two columns, 3.5 in for one).

    python -m eval.baselines.plot_contributions --run "$PROVBIND_RUN" [--out <run>/results/figures] [--dpi 300]
        [--overhead <overhead run> [--history LABEL=<overhead run> ...]]

Two steps when the run folder lives on another machine (docs/FIGURES-HOWTO.md):

    # where the run folder is (the demo VM), once: every figure's numbers into one data file
    python -m eval.baselines.plot_contributions --run run-final --overhead run-overhead-opt5 \
        --history "Original policies=run-overhead-orig4" ... --export docs/figures/data/<dated>/figures.json
    # anywhere, from the repository alone
    python -m eval.baselines.plot_contributions --data docs/figures/data/<dated> --out figures

| File | Contribution | (a) comparison | (b) PROVBIND's cost |
|---|---|---|---|
| fig1_c1_specification.png | C1 specification compilation | time until each system can protect a new image (exact, measured, with package counts, when results/PREP.json exists) | compile time per step; runtime index (without PREP.json) |
| fig1b_c1_components.png | C1, optional | each system's preparation split into its timed components | - |
| fig2_c2_verification.png | C2 runtime verification | detection rate and false-positive rate (runtime and benign scenarios) | per-event check latency (OH-01) |
| fig3_c3_attribution.png | C3 attribution | share of each system's detections that name container, process, rule, package, layer, dependency path | - |
| fig4_c4_trust.png | C4 trust re-evaluation | admission and trust scenarios: runs caught per system, Sig-only included | trust-loop reaction time |
| fig5_scenarios.png | detail | every scenario x system: runs flagged / runs | - |
| fig6_runtime_cost.png | runtime cost | PROVBIND and Falco against no monitoring, per application metric, with the 20% limit | - |
| fig7_cost_history.png | runtime cost | PROVBIND's overhead in each overhead run given with --history | - |

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
KIND = {"PROVBIND": "measured", "PROVBIND + ML-B": "measured", "Falco": "measured", "Confine-E": "estimated", "DeSFAM-E": "estimated",
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
    "benign-3": ("B4", "Benign"), "benign-4": ("B5", "Benign"), "ab-1": ("A-B1", "Benign"),
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
            "prep": _json(run / "results" / "PREP.json") or {},          # eval/prep_time.py (overhead run)
            "results": {i: _json(run / "results" / f"{i}.json") for i in ("OH-01", "OH-04", "OH-05")}}


def _pre(d, key, compute):
    """A figure's data: from the data file when drawing with --data, else computed from the run folder."""
    pre = d.get("precomputed")
    return pre[key] if pre is not None and key in pre else compute(d)


def _real(result):
    """A capability result measured on real input (not the synthetic stand-in), or None."""
    if not isinstance(result, dict) or result.get("status") == "not_run":
        return None
    return None if "synthetic" in (result.get("notes") or "") else result


# --- figure data (no matplotlib) ----------------------------------------------------------------------

def compile_seconds(env):
    t = env.get("timings_ms") or {}
    return round(sum(v for v in t.values() if isinstance(v, (int, float))) / 1000, 2) if t else None


def _count(n, what):
    return f"n = {n:,} {what}" if isinstance(n, int) else ""


def c1_readiness_measured(prep):
    """Figure 1a from eval/prep_time.py: every system's preparation time measured on the VM, with counts."""
    rows = []
    p = prep.get("PROVBIND")
    if p:
        rows.append({"system": "PROVBIND", "seconds": p.get("seconds"), "how": "measured",
                     "note": f"{p.get('packages') or 0:,} packages, {p.get('files') or 0:,} files; "
                             f"median of {_count(p.get('n'), 'cold compiles')}"})
    m = prep.get("PROVBIND + ML-B")
    if m and m.get("seconds"):
        parts = m.get("parts_s") or {}
        rows.append({"system": "PROVBIND + ML-B", "seconds": m.get("seconds"), "how": "measured",
                     "note": f"trained on {_count(m.get('n'), 'requests')}, {m.get('windows') or 0:,} windows"})
    f = prep.get("Falco")
    if f:
        rows.append({"system": "Falco", "seconds": None, "how": "none",
                     "note": "0 s: no per-image step (generic rules)"
                             + (f"\nDaemonSet restart {f['restart_ready_s']:.0f} s, n = {f.get('restarts')} restarts"
                                if f.get("restart_ready_s") is not None else "")})
    c = prep.get("Confine-E")
    if c:
        parts = c.get("parts_s") or {}
        rows.append({"system": "Confine-E", "seconds": c.get("seconds"), "how": "measured",
                     "note": f"{c.get('packages') or 0:,} packages ({c.get('n') or 0:,} ELF files"
                             + (f", +{c['files_outside_packages']} outside packages" if c.get("files_outside_packages") else "")
                             + ")"})
    s_ = prep.get("DeSFAM-E")
    if s_:
        parts = s_.get("parts_s") or {}
        rows.append({"system": "DeSFAM-E", "seconds": s_.get("seconds"), "how": "measured",
                     "note": f"{s_.get('packages') or 0:,} packages; profiled on {_count(s_.get('n'), 'requests')}, "
                             f"{s_.get('windows') or 0:,} windows"})
    return rows


def c1_readiness(d):
    """Figure 1a: time until each system can protect a new image (measured when PREP.json exists)."""
    if d.get("prep"):
        return c1_readiness_measured(d["prep"])
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


ORIGIN_FIELDS = ("Package", "Image layer", "Dependency path")    # exist only for a file that is in the image
NO_FILE_IN_IMAGE = ("undeclared", "anomalous_window")          # a dropped file, or a behaviour window


def _in_image(a):
    """Whether a PROVBIND alert is about a file that is in the image (so it has a package, layer, path)."""
    return str(a.get("class", "")) in ("D_exec", "D_load", "D_write", "D_cap", "D_hash") \
        and str(a.get("subclass", "")) not in NO_FILE_IN_IMAGE


def c3_attribution(d):
    """Figure 3: share of each system's runtime detections in attack runs that name each field. `counts`
    gives (named, out of) per field: the origin fields count only alerts about a file in the image."""
    w = _attack_windows(d["gt"])
    prov = [a for a in d["alerts"] if str(a.get("class", "")).startswith("D_")
            and str(a.get("bucket", "")).lower() in ("critical", "high", "medium")
            and _in_any(w, *alert_pod(a), parse_time(a.get("time")))]
    falco = [x for x in d["falco"] if _in_any(w, *falco_pod(x), parse_time(x.get("time")))]
    share, n, how, counts = {}, {}, {}, {}
    for name, items, fn in (("PROVBIND", prov, _prov_fields), ("Falco", falco, _falco_fields)):
        n[name], how[name] = len(items), "measured"
        share[name] = [sum(fn(x)[i] for x in items) / len(items) for i in range(len(FIELDS))] if items else None
        in_image = [x for x in items if _in_image(x)] if name == "PROVBIND" else items
        counts[name] = [(sum(fn(x)[i] for x in (in_image if f in ORIGIN_FIELDS else items)),
                         len(in_image) if f in ORIGIN_FIELDS else len(items)) for i, f in enumerate(FIELDS)]
    for name, flags in BY_DESIGN_FIELDS.items():
        n[name], how[name], share[name] = None, "by design", [float(v) for v in flags]
    n_image = sum(1 for x in prov if _in_image(x))
    return {"fields": FIELDS, "systems": SYSTEMS, "share": share, "n": n, "how": how, "counts": counts,
            "n_image": n_image}


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


LABELS = {"startup_observation": "start-up recording", "export_binaries": "export binaries from the pod",
          "elf_import_extraction": "read ELF imports", "syscall_mapping": "map imports to system calls",
          "static_analysis": "static analysis", "profiling": "benign profiling",
          "static_allow_list": "static allow list", "dynamic_allow_list": "dynamic allow list",
          "combine_eq1": "combine (Eq. 1)", "isolation_forest_training": "Isolation Forest training",
          "allow_list": "allow list", "training": "model training", "benign_load": "benign load (D2)"}


def c1_components(prep, keep=5):
    """Figure 1b: each system's preparation split into its timed components (seconds)."""
    out = []
    p = prep.get("PROVBIND")
    if p and p.get("steps_ms"):
        steps = sorted(((k, v / 1000) for k, v in p["steps_ms"].items()), key=lambda kv: -kv[1])
        head, tail = steps[:keep], steps[keep:]
        if tail:
            head.append((f"other {len(tail)} steps", sum(v for _, v in tail)))
        out.append(("PROVBIND", p.get("seconds"), head))
    for name in ("PROVBIND + ML-B", "Confine-E", "DeSFAM-E"):
        r = prep.get(name)
        if r and r.get("parts_s"):
            parts = [(LABELS.get(k, k.replace("_", " ")), v) for k, v in r["parts_s"].items() if v is not None]
            out.append((name, r.get("seconds"), parts))
    return out


def _fmt_exact(s):
    if s is None:
        return "—"
    if s < 1:
        return f"{s * 1000:.0f} ms"
    if s < 60:
        return f"{s:.2f} s"
    if s < 3600:
        return f"{s:,.0f} s ({s / 60:.1f} min)"
    return f"{s:,.0f} s ({s / 3600:.2f} h)"


def fig1_c1_measured(d, path, dpi):
    """Figure 1 when every system's preparation was measured (results/PREP.json from eval/prep_time.py):
    the time until a new image is protected, exact, with the packages and repetitions behind it. The
    component breakdown is a separate image (fig1b_c1_components.png)."""
    plt = _plt()
    ready = c1_readiness_measured(d["prep"])
    fig, a = plt.subplots(figsize=(3.6, 0.62 * len(ready) + 0.9))
    ys = list(range(len(ready)))[::-1]
    vals = [r["seconds"] for r in ready if r["seconds"]]
    lo, hi = (min(vals) / 3 if vals else 1), (max(vals) * 40 if vals else 3600)
    for y, r in zip(ys, ready):
        if r["seconds"] is None:
            a.text(lo * 1.15, y + 0.08, "0 s: no per-image step (generic rules)", va="center", fontsize=6.8,
                   color=INK2, style="italic")
            a.text(lo * 1.15, y - 0.3, "0 packages analysed", va="center", fontsize=6, color=INK2)
            continue
        a.barh(y, r["seconds"] - lo, height=0.45, left=lo, color=S1, edgecolor=SURFACE, linewidth=1)
        a.text(r["seconds"] * 1.12, y + 0.04, _fmt_exact(r["seconds"]), va="center", fontsize=6.8, color=INK)
        a.text(lo * 1.15, y - 0.36, r["note"], va="center", fontsize=6, color=INK2)
    a.set_xscale("log")
    a.set_xlim(lo, hi)
    ticks = [t for t in (1, 10, 60, 600, 3600, 36000) if lo <= t <= hi]
    a.set_xticks(ticks)
    a.set_xticklabels([{1: "1 s", 10: "10 s", 60: "1 min", 600: "10 min", 3600: "1 h", 36000: "10 h"}[t] for t in ticks],
                      fontsize=6.5)
    a.set_xlabel("seconds, log scale", fontsize=6.5)
    a.minorticks_off()
    a.set_ylim(-0.8, len(ready) - 0.4)
    a.set_yticks(ys)
    a.set_yticklabels([_tick(r["system"], KIND.get(r["system"], "measured")) for r in ready], fontsize=7)
    a.tick_params(axis="y", length=0)
    _grid(a, "x")
    a.set_title("Time until a new image is protected (measured)", loc="left", fontsize=8, color=INK, pad=6)
    _footer(fig, ["C1. Every time was measured on our VM. PROVBIND compiles its specification",
                  "from signed build evidence once per image digest; PROVBIND + ML-B adds the",
                  "benign recording ML-B learns from. * Confine-E and DeSFAM-E are estimated",
                  "systems: their times are their preparation steps as we ran them, each timed."])
    return _save(plt, fig, path, dpi)


def fig1b_c1(d, path, dpi):
    """Figure 1b (optional): each system's preparation split into its timed components, one small panel
    per system on its own scale. Needs results/PREP.json; without it, PROVBIND's compile steps only."""
    plt = _plt()
    prep = d.get("prep") or {}
    comps = c1_components(prep)
    if not comps:                                       # no PREP.json: PROVBIND's steps from the envelopes
        st = _pre(d, "c1_steps", c1_steps)
        if st["steps"]:
            comps = [("PROVBIND", st["total_s"], [(k, v / 1000) for k, v in st["steps"]])]
    if not comps:
        fig, ax = plt.subplots(figsize=(3.6, 1.2))
        _empty(ax, "Not measured: no PREP.json and no envelope in this run folder.")
        return _save(plt, fig, path, dpi)
    heights = [max(2, len(c[2])) + 1.2 for c in comps] + ([1.4] if prep.get("Falco") else [])
    fig = plt.figure(figsize=(3.8, 0.21 * sum(heights) + 0.2))
    gs = fig.add_gridspec(len(heights), 1, height_ratios=heights, hspace=1.1)
    for i, (name, total, parts) in enumerate(comps):
        ax = fig.add_subplot(gs[i, 0])
        names = [k for k, _ in parts][::-1]
        secs = [v for _, v in parts][::-1]
        top = max(secs) if secs else 1
        ax.barh(range(len(secs)), secs, height=0.6, color=S1, edgecolor=SURFACE, linewidth=1)
        for j, v in enumerate(secs):
            ax.text(v + top * 0.02, j, _fmt_exact(v), va="center", fontsize=5.8, color=INK)
        ax.set_yticks(range(len(secs)))
        ax.set_yticklabels(names, fontsize=6)
        ax.tick_params(axis="y", length=0)
        ax.tick_params(axis="x", labelsize=5.5)
        ax.set_xlim(0, top * 1.45)
        _grid(ax, "x")
        ax.set_title(f"{_tick(name, KIND.get(name, 'measured'))}: {_fmt_exact(total)}", loc="left", fontsize=7,
                     color=INK, pad=3)
    f = prep.get("Falco")
    if f:
        ax = fig.add_subplot(gs[len(comps), 0])
        ax.set_axis_off()
        ax.text(0, 0.5, "Falco: no per-image component (generic rules)."
                + (f"\nIts DaemonSet is ready {_fmt_exact(f['restart_ready_s'])} after a restart "
                   + ("(measured once)." if f.get("restarts") == 1 else f"(median of {f.get('restarts')} restarts).")
                   if f.get("restart_ready_s") is not None else ""),
                transform=ax.transAxes, fontsize=6.3, color=INK2, va="center")
    _footer(fig, ["Preparation time per component, measured on our VM. Each panel has its own scale.",
                  "* Estimated systems: their preparation steps as we ran them, each timed."])
    return _save(plt, fig, path, dpi)


def fig1_c1(d, path, dpi):
    if d.get("prep"):
        return fig1_c1_measured(d, path, dpi)
    plt = _plt()
    from matplotlib.patches import Patch
    ready = c1_readiness(d)
    measured_all = all(r["how"] in ("measured", "none") for r in ready)
    fig, (a, b) = plt.subplots(1, 2, figsize=(7.16, 3.0 if measured_all else 2.5),
                               gridspec_kw={"width_ratios": [1.5, 1] if measured_all else [1.1, 1]})
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
        label = ("≥ " if r["how"] == "by design" else "") + (f"{r['seconds']:.1f} s" if r["seconds"] < 60
                                                           else f"{r['seconds']:.0f} s = {_fmt_s(r['seconds'])}")
        a.text(r["seconds"] * 1.12, y, label, va="center", fontsize=7, color=INK)
        if measured_all and r.get("note"):                                    # the exact count behind the bar
            a.text(lo * 1.15, y - 0.36, r["note"], va="center", fontsize=5.6, color=INK2)
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
    if measured_all:
        _panel(a, "a", "Time until a new image is protected (measured)")
    else:
        _panel(a, "a", "Time until a new image is protected")
        a.legend(handles=[Patch(facecolor=S1, edgecolor=SURFACE, label="measured in this run"),
                          Patch(facecolor=S1, edgecolor=SURFACE, hatch="///", label="by design (minimum the method needs)")],
                 loc="upper center", bbox_to_anchor=(0.5, -0.17), ncol=2, fontsize=6.5)

    st = _pre(d, "c1_steps", c1_steps)
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
                  ("Falco uses hand-written generic rules. * Confine-E and DeSFAM-E: estimated systems; their bars are their "
                   "preparation as run on our VM (start-up or profiling recording + analysis or training), timed."
                   if measured_all else
                   "Falco uses hand-written generic rules. * Confine-E and DeSFAM-E: estimated systems; their bars are the "
                   "observation their published design needs before it can protect a new image.")])
    return _save(plt, fig, path, dpi)


def fig2_c2(d, path, dpi):
    plt = _plt()
    from matplotlib.patches import Patch
    fig, (a, b) = plt.subplots(1, 2, figsize=(7.16, 2.5), gridspec_kw={"width_ratios": [2.2, 1]})
    data = _pre(d, "c2_metrics", lambda d: c2_metrics(d["rows"]))
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

    lat = _pre(d, "c2_latency", c2_latency)
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
                    f"{pub.get('recall')}, false-positive rate {pub.get('fpr', pub.get('false_positive_rate'))}.")
    _footer(fig, foot)
    return _save(plt, fig, path, dpi)


def fig3_c3(d, path, dpi):
    """Figure 3: what each system's alerts name. Measured columns give "named / alerts"; the estimated
    systems are not run live, so their columns say what their design records (yes / no), in grey."""
    plt = _plt()
    att = _pre(d, "c3_attribution", c3_attribution)
    fields, systems = att["fields"], att["systems"]
    cmap = _cmap(BLUE_RAMP, "blue")
    groups = (("Where", ("Container / pod", "Process")), ("Why", ("Rule / clause / technique",)),
              ("Supply-chain origin", ORIGIN_FIELDS))
    fig, ax = plt.subplots(figsize=(5.2, 3.1))
    xs = {s: j + (0.35 if j >= 2 else 0) for j, s in enumerate(systems)}       # a gap before estimated systems
    for i, f in enumerate(fields):
        y = i
        for s in systems:
            x = xs[s]
            if att["how"][s] == "measured" and att["counts"].get(s):
                k, n = att["counts"][s][i]
                frac = k / n if n else 0
                ax.add_patch(plt.Rectangle((x + 0.04, y + 0.06), 0.92, 0.88, color=cmap(0.06 + 0.86 * frac), lw=0))
                txt = f"{k} / {n}\n{frac * 100:.0f}%" if n else "no alert\nof this kind"
                ax.text(x + 0.5, y + 0.5, txt, ha="center", va="center", fontsize=6.3, linespacing=1.15,
                        color=SURFACE if frac > 0.55 else INK)
            else:
                ax.add_patch(plt.Rectangle((x + 0.04, y + 0.06), 0.92, 0.88, color="#efeeea", lw=0))
                if s == "Confine-E":
                    txt = "no alert"
                else:
                    flag = (BY_DESIGN_FIELDS.get(s) or (0,) * len(fields))[i]
                    txt = "yes" if flag else "no"
                ax.text(x + 0.5, y + 0.5, txt, ha="center", va="center", fontsize=6.3, color=INK2, style="italic")
    ax.set_xlim(0, xs[systems[-1]] + 1)
    ax.set_ylim(len(fields), 0)
    head = {"PROVBIND": f"PROVBIND\n{att['n'].get('PROVBIND') or 0} alerts", "Falco": f"Falco\n{att['n'].get('Falco') or 0} alerts",
            "Confine-E": "Confine-E*\nby design", "DeSFAM-E": "DeSFAM-E*\nby design"}
    ax.set_xticks([xs[s] + 0.5 for s in systems])
    ax.set_xticklabels([head.get(s, s) for s in systems], fontsize=6.8)
    ax.xaxis.tick_top()
    ax.set_yticks([i + 0.5 for i in range(len(fields))])
    ax.set_yticklabels(fields, fontsize=6.8)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    row = 0
    for g, members in groups:                                                   # group labels and rules
        if row:
            ax.axhline(row, color=INK2, linewidth=0.7, xmax=0.97)
        ax.text(-1.9, row + len(members) / 2, g, rotation=90, ha="center", va="center", fontsize=6.3,
                color=INK2, style="italic", clip_on=False)
        row += len(members)
    _footer(fig, ["C3. What each system's alerts in attack runs name. PROVBIND and Falco: measured from their alert files,",
                  f"shown as named / alerts. Supply-chain origin rows count only PROVBIND alerts about a file that is in the image",
                  f"({att['n_image']} of {att['n'].get('PROVBIND') or 0}); a dropped file, a connection or a behaviour window has no package or layer to name.",
                  "* Confine-E and DeSFAM-E are estimated, not run live: grey cells say what their design records. Confine-E",
                  "raises no alert at all (seccomp blocks the call silently)."])
    return _save(plt, fig, path, dpi)


def fig4_c4(d, path, dpi):
    plt = _plt()
    import numpy as np
    fig, (a, b) = plt.subplots(1, 2, figsize=(7.16, 2.4), gridspec_kw={"width_ratios": [1.6, 1]})
    systems, rows = _pre(d, "c4_matrix", lambda d: c4_matrix(d["rows"]))
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

    lat = _pre(d, "c4_trust_latency", lambda d: c4_trust_latency(d["alerts"]))
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


NICE = {"ak-1": "Advisory exists before deploy", "ak-2": "Unsigned image", "ak-3": "Signing key revoked before deploy",
        "au-2": "Undeclared program added at build", "trust-1": "Advisory published while running",
        "trust-2": "Signing key revoked while running", "rk-2": "Kernel-CVE call pattern (replay only)",
        "rk-3": "Library injection", "attack-1": "New program dropped and run", "attack-2": "Burst of new files",
        "ru-3": "Connection to an unlisted address", "ru-4": "Declared program replaced",
        "ru-5": "Credential file read", "benign-1": "Interactive shell", "benign-traffic": "Normal web requests",
        "ph4-14": "New temporary file", "benign-3": "DNS lookups", "benign-4": "Writes to a mounted volume",
        "ab-1": "Clean signed image deployed"}
ADMISSION = {"ak-1", "ak-2", "ak-3", "au-2", "ab-1"}
STAGES = {"Confine-E": "runtime", "DeSFAM-E": "runtime", "Sig-only": "admission"}   # stages a system covers


def scenario_outcome(scenario, truth, system, flagged, runs):
    """(kind, text) for one cell of figure 5: right / wrong / partial, or n/a when the system has no check
    at that stage (scored as missed or as no alarm in the tables)."""
    stage = "admission" if scenario in ADMISSION else "runtime"
    if STAGES.get(system, stage) != stage:
        return "na", "n/a"
    right = flagged if truth == "malicious" else runs - flagged
    if truth == "malicious":
        text = "caught" if flagged == runs else ("missed" if flagged == 0 else f"{flagged}/{runs} caught")
    else:
        text = "no alarm" if flagged == 0 else ("false alarm" if flagged == runs else f"{flagged}/{runs} false alarm")
    kind = "right" if right == runs else ("wrong" if right == 0 else "partial")
    return kind, text


def fig5_scenarios(d, path, dpi):
    """Figure 5: every scenario x system, coloured by whether the outcome was RIGHT (attack caught, benign
    activity left alone) or WRONG (attack missed, false alarm); grey where a system has no check at that
    stage. One rule for every row, a symbol beside every word, and a total per system at the bottom."""
    plt = _plt()
    names, rows = _pre(d, "heatmap", lambda d: heatmap(d["tables"]))
    if not rows:
        raise ValueError("no scenario rows in COMPARISON.json")
    fill = {"right": "#256abf", "wrong": "#eb6834", "partial": "#f6b090", "na": "#efeeea"}
    ink = {"right": SURFACE, "wrong": INK, "partial": INK, "na": INK2}
    mark = {"right": "\u2713 ", "wrong": "\u2717 ", "partial": "~ ", "na": ""}
    totals = {n: [0, 0] for n in names}
    fig, ax = plt.subplots(figsize=(6.2, 0.24 * (len(rows) + 1) + 0.7))
    for i, r in enumerate(rows):
        for j, m in enumerate(names):
            flagged = int(round(r["fraction"][j] * r["runs"]))
            kind, text = scenario_outcome(r["scenario"], r["truth"], m, flagged, r["runs"])
            right = flagged if r["truth"] == "malicious" else r["runs"] - flagged
            totals[m][0] += right                      # as the tables score it: n/a = missed, or no alarm
            totals[m][1] += r["runs"]
            ax.add_patch(plt.Rectangle((j + 0.03, i + 0.07), 0.94, 0.86, color=fill[kind], lw=0))
            ax.text(j + 0.5, i + 0.5, mark[kind] + text, ha="center", va="center", fontsize=5.9, color=ink[kind])
    y = len(rows) + 0.25
    for j, m in enumerate(names):
        k, n = totals[m]
        ax.text(j + 0.5, y + 0.5, f"{k} / {n} right", ha="center", va="center", fontsize=6.3, color=INK,
                fontweight="bold")
    ax.axhline(len(rows) + 0.12, color=INK2, linewidth=0.8)
    ax.set_xlim(0, len(names))
    ax.set_ylim(len(rows) + 1.3, 0)
    ax.set_xticks([j + 0.5 for j in range(len(names))])
    ax.set_xticklabels([_tick(n, KIND.get(n, "measured")) for n in names], fontsize=6.8)
    ax.xaxis.tick_top()
    labels = [f"{NICE.get(r['scenario'], r['scenario'])}" + (f" ({SCENARIOS[r['scenario']][0]})"
              if SCENARIOS.get(r["scenario"], ("",))[0] else "") for r in rows]
    ax.set_yticks([i + 0.5 for i in range(len(rows))] + [y + 0.5])
    ax.set_yticklabels(labels + ["Runs judged right"], fontsize=6.3)
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    spans = {}
    for i, r in enumerate(rows):
        spans.setdefault(r["cell"], [i, i])[1] = i
    for cell, (s0, e) in spans.items():
        if s0:
            ax.axhline(s0, color=INK2, linewidth=0.8)
        ax.text(len(names) + 0.1, (s0 + e + 1) / 2, cell, va="center", ha="left", fontsize=6.0, color=INK2,
                style="italic", clip_on=False)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=fill["right"], label="\u2713 right: attack caught, or normal activity left alone"),
                       Patch(color=fill["wrong"], label="\u2717 wrong: attack missed, or false alarm"),
                       Patch(color=fill["na"], label="n/a: the system has no check at this stage (scored as missed, or as no alarm)")],
              loc="upper left", bbox_to_anchor=(-0.02, 1.13), ncol=3, fontsize=5.6, frameon=False,
              handlelength=1.2, columnspacing=1.0)
    _footer(fig, ["Each cell is 5 runs. Falco's admission 'catches' come from rules that fire on every pod start: it also alarms on the clean",
                  "deploy (A-B1). The bottom row counts every run as the comparison tables do (true positives + true negatives).",
                  "* Confine-E, DeSFAM-E: estimated systems (runtime only).  \u2020 Sig-only: a signature check at admission only."])
    return _save(plt, fig, path, dpi)


# --- runtime cost (supervisor's questions 3 and 4), from eval/overhead.py's OVERHEAD.json ---------------

APP_METRICS = (("mix", "p50_ms", "Request mix: median latency"), ("mix", "p95_ms", "Request mix: p95 latency"),
               ("mix", "rps", "Request mix: throughput loss"),
               ("cache", "p50_ms", "File-writing requests: median latency"),
               ("cache", "p95_ms", "File-writing requests: p95 latency"),
               ("cache", "rps", "File-writing requests: throughput loss"))
MICRO_METRICS = (("micro", "file_op_us", "Loop of file writes"), ("micro", "spawn_ms", "Loop of process starts"))


def _overhead_doc(path):
    p = Path(path)
    for f in (p, p / "OVERHEAD.json", p / "results" / "OVERHEAD.json"):
        if f.is_file():
            return json.loads(f.read_text(encoding="utf-8"))
    raise FileNotFoundError(f"no OVERHEAD.json in {path} (eval/overhead.py writes <run>/results/OVERHEAD.json)")


def _overhead_pct(doc, kind, field, config):
    e = next((e for e in doc.get("table") or [] if e.get("kind") == kind and e.get("field") == field), None)
    return None if e is None else (e.get("overhead_pct") or {}).get(config)


def overhead_data(final, history=()):
    """Figures 6 and 7: the final overhead run's change against no monitoring per metric and configuration,
    and PROVBIND's change in each run of `history`, (label, path) pairs in the order to draw them."""
    doc = _overhead_doc(final)
    configs = [c for c in doc.get("configs") or [] if c != "none"]
    app = {e["metric"] for e in doc.get("table") or [] if e.get("kind") in ("mix", "cache")}
    over_t = [v for k, v in (doc.get("provbind_over_tetragon") or {}).items() if k in app and v is not None]
    return {"threshold_pct": doc.get("threshold_pct", 20.0), "repetitions": doc.get("repetitions") or {},
            "final": [{"kind": k, "field": f, "label": lab,
                       "overhead_pct": {c: _overhead_pct(doc, k, f, c) for c in configs}}
                      for k, f, lab in APP_METRICS + MICRO_METRICS],
            "provbind_over_tetragon_max_pct": max(over_t) if over_t else None,
            "cpu": {c: {k: v for k, v in (m or {}).items() if k != "top"} for c, m in (doc.get("cpu") or {}).items()},
            "history": [{"run": label, "overhead_pct": {f"{k}/{f}": _overhead_pct(_overhead_doc(path), k, f, "provbind")
                                                        for k, f, _ in APP_METRICS + MICRO_METRICS}}
                        for label, path in history]}


def _limit_line(ax, th, vertical=True):
    style = dict(color=INK, linewidth=0.9, linestyle=(0, (4, 3)), zorder=2)
    (ax.axvline if vertical else ax.axhline)(th, **style)


def fig6_runtime_cost(d, path, dpi):
    """Figure 6: runtime cost of PROVBIND and Falco against no monitoring, per application metric, with the
    20% limit (supervisor's question 4) and the worst cases in the footer."""
    plt = _plt()
    from matplotlib.lines import Line2D
    from matplotlib.patches import Patch
    ov = _pre(d, "overhead", lambda d: d.get("overhead"))
    if not ov:
        fig, ax = plt.subplots(figsize=(5.2, 1.2))
        _empty(ax, "Not measured: give --overhead <overhead run>, or draw from a data file that has one.")
        return _save(plt, fig, path, dpi)
    th = ov.get("threshold_pct") or 20.0
    rows = [m for m in ov["final"] if m["kind"] in ("mix", "cache")]
    series = (("provbind", "PROVBIND", S1), ("falco", "Falco (default rules)", S2))
    vals = [v for m in rows for c, _, _ in series for v in [m["overhead_pct"].get(c)] if v is not None]
    top = max([th] + vals)
    fig, ax = plt.subplots(figsize=(5.2, 3.0))
    h = 0.36
    ys = list(range(len(rows)))[::-1]
    for y, m in zip(ys, rows):
        for off, (c, _, col) in zip((h / 2, -h / 2), series):
            v = m["overhead_pct"].get(c)
            if v is None:
                ax.text(top * 0.01, y + off, "not measured", va="center", fontsize=6, color=MUTED)
                continue
            ax.barh(y + off, max(v, 0), height=h, color=col, edgecolor=SURFACE, linewidth=1, zorder=3)
            ax.text(max(v, 0) + top * 0.015, y + off, f"{v:+.1f}%", va="center", fontsize=6.3, color=INK)
    _limit_line(ax, th)
    ax.set_yticks(ys)
    ax.set_yticklabels([m["label"] for m in rows], fontsize=6.8)
    ax.tick_params(axis="y", length=0)
    ax.set_xlim(0, top * 1.22)
    ax.set_xlabel("change against no monitoring (%); for throughput, the loss", fontsize=6.5)
    _grid(ax, "x")
    ax.set_title("Runtime cost against no monitoring", loc="left", fontsize=8, color=INK, pad=18)
    ax.legend(handles=[Patch(color=S1, label="PROVBIND"), Patch(color=S2, label="Falco (default rules)"),
                       Line2D([0], [0], color=INK, linewidth=0.9, linestyle=(0, (4, 3)), label=f"{th:.0f}% limit")],
              loc="lower left", bbox_to_anchor=(-0.01, 1.0), ncol=3, fontsize=6.5, frameon=False,
              handlelength=1.6, columnspacing=1.4, borderaxespad=0.2)
    micro = {m["field"]: m["overhead_pct"] for m in ov["final"] if m["kind"] == "micro"}
    fmt = lambda v: "n/a" if v is None else f"{v:+.1f}%"
    reps = sorted(set((ov.get("repetitions") or {}).values()))
    foot = [f"Medians of {'/'.join(str(r) for r in reps) or '?'} repetitions in shuffled order, the same app with no monitor as the "
            "baseline. A value at or below 0 is within the noise.",
            "Worst cases, not drawn: a tight loop of file writes, PROVBIND "
            f"{fmt(micro.get('file_op_us', {}).get('provbind'))} and Falco {fmt(micro.get('file_op_us', {}).get('falco'))}; "
            f"of process starts, PROVBIND {fmt(micro.get('spawn_ms', {}).get('provbind'))} and Falco "
            f"{fmt(micro.get('spawn_ms', {}).get('falco'))}."]
    if ov.get("provbind_over_tetragon_max_pct") is not None:
        foot.append("PROVBIND over its sensor alone (Tetragon with the same policies): at most "
                    f"{ov['provbind_over_tetragon_max_pct']:+.1f}% on these metrics.")
    _footer(fig, foot)
    return _save(plt, fig, path, dpi)


def fig7_cost_history(d, path, dpi):
    """Figure 7: how PROVBIND's runtime cost came down over the overhead runs given with --history, on the
    two metrics that moved most, with the 20% limit."""
    import textwrap
    plt = _plt()
    ov = _pre(d, "overhead", lambda d: d.get("overhead"))
    hist = (ov or {}).get("history") or []
    if not hist:
        fig, ax = plt.subplots(figsize=(5.2, 1.2))
        _empty(ax, "Not measured: give the overhead runs with --history LABEL=<run> ..., in order.")
        return _save(plt, fig, path, dpi)
    th = ov.get("threshold_pct") or 20.0
    panels = (("cache/p95_ms", "File-writing requests, p95 latency"), ("mix/p95_ms", "Request mix, p95 latency"))
    fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.5))
    for ax, (key, title), letter in zip(axes, panels, "ab"):
        vals = [h["overhead_pct"].get(key) for h in hist]
        top = max([th] + [v for v in vals if v is not None])
        for x, v in enumerate(vals):
            if v is None:
                ax.text(x, top * 0.02, "not measured", ha="center", va="bottom", fontsize=6, color=MUTED, rotation=90)
                continue
            ax.bar(x, max(v, 0), 0.55, color=S1, edgecolor=SURFACE, linewidth=1, zorder=3)
            ax.text(x, max(v, 0) + top * 0.02, f"{v:+.1f}%", ha="center", va="bottom", fontsize=6.8, color=INK,
                    zorder=4, bbox=dict(boxstyle="square,pad=0.15", facecolor=SURFACE, edgecolor="none"))
        _limit_line(ax, th, vertical=False)
        # the limit's label gets a column of its own, right of the last bar, so no value label can cover it
        ax.text(len(vals) - 0.62, th, f"{th:.0f}% limit", ha="left", va="center", fontsize=6.3, color=INK, zorder=4,
                bbox=dict(boxstyle="square,pad=0.15", facecolor=SURFACE, edgecolor="none"))
        ax.set_xticks(range(len(hist)))
        ax.set_xticklabels([textwrap.fill(h["run"], 15) for h in hist], fontsize=6.5)
        ax.tick_params(axis="x", length=0)
        ax.set_xlim(-0.6, len(hist) + 0.25)
        ax.set_ylim(0, top * 1.2)
        ax.set_ylabel("PROVBIND, change against\nno monitoring (%)", fontsize=6.5)
        _grid(ax, "y")
        _panel(ax, letter, title)
    fig.tight_layout(w_pad=2.5)
    _footer(fig, ["Each bar is one overhead run (median of the repetitions, against the same app with no monitor), in the order "
                  "the sensor policies were optimised.",
                  "The cost is roughly the number of sensor events per request times the cost of moving each event to PROVBIND: "
                  "each step drops, in the kernel, events that carry nothing new."])
    return _save(plt, fig, path, dpi)


FIGURES = (("fig1_c1_specification.png", fig1_c1), ("fig1b_c1_components.png", fig1b_c1),
           ("fig2_c2_verification.png", fig2_c2),
           ("fig3_c3_attribution.png", fig3_c3), ("fig4_c4_trust.png", fig4_c4),
           ("fig5_scenarios.png", fig5_scenarios),
           ("fig6_runtime_cost.png", fig6_runtime_cost), ("fig7_cost_history.png", fig7_cost_history))

DATA_SCHEMA = "provbind.figures/v1"


def figure_data(d):
    """Every figure's numbers from a run folder (and its overhead runs), JSON-ready: what --export writes
    and --data draws from. Aggregates only: no alert, trace or pod detail leaves the run folder."""
    systems, c4rows = c4_matrix(d["rows"])
    names, hrows = heatmap(d["tables"])
    return {"schema": DATA_SCHEMA, "run": Path(d["run"]).name if d.get("run") else None,
            "prep": d.get("prep") or {},
            "desfam": {"published_reference": (d.get("desfam") or {}).get("published_reference")},
            "systems_table": (d.get("tables") or {}).get("systems"),
            "c1_steps": c1_steps(d), "c2_metrics": c2_metrics(d["rows"]), "c2_latency": c2_latency(d),
            "c3_attribution": c3_attribution(d), "c4_matrix": [list(systems), c4rows],
            "c4_trust_latency": c4_trust_latency(d["alerts"]), "heatmap": [names, hrows],
            "overhead": d.get("overhead")}


def load_data(path):
    """The figure inputs from a data file written by --export (a figures.json, or a folder that holds one)."""
    p = Path(path)
    f = p / "figures.json" if p.is_dir() else p
    data = json.loads(f.read_text(encoding="utf-8"))
    if data.get("schema") != DATA_SCHEMA:
        raise ValueError(f"{f} is not a figure data file ({DATA_SCHEMA})")
    return {"precomputed": data, "prep": data.get("prep") or {}, "desfam": data.get("desfam") or {},
            "rows": [], "tables": {}, "alerts": [], "falco": [], "gt": [], "envelopes": [], "profile_s": 0,
            "results": {}, "overhead": data.get("overhead"), "run": None}


def _history(items):
    out = []
    for it in items:
        label, sep, path = it.partition("=")
        out.append((label, path) if sep else (Path(it).name, it))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.baselines.plot_contributions", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"))
    ap.add_argument("--data", help="draw from a data file written by --export (figures.json, or its folder); "
                                   "no run folder needed")
    ap.add_argument("--export", metavar="FILE", help="write every figure's numbers to FILE instead of drawing")
    ap.add_argument("--overhead", metavar="RUN", help="the final overhead run (its results/OVERHEAD.json): figure 6")
    ap.add_argument("--history", nargs="*", default=[], metavar="LABEL=RUN",
                    help="overhead runs in order, for figure 7 (the final one last)")
    ap.add_argument("--out", help="output directory (default <run>/results/figures; with --data, ./figures)")
    ap.add_argument("--dpi", type=int, default=300)
    args = ap.parse_args(argv)
    if args.data:
        try:
            d = load_data(args.data)
        except (OSError, ValueError) as e:
            print(f"plot_contributions: cannot read the figure data: {e} (Role 1 makes figures.json on the VM "
                  "with --export: docs/FIGURES-HOWTO.md, section 4)", file=sys.stderr)
            return 1
    else:
        d = load_run(args.run)
        if not d["rows"]:
            print(f"plot_contributions: no rows in {args.run}/results/COMPARISON.json "
                  "(run eval.baselines.aggregate --write first)", file=sys.stderr)
            return 1
        if args.overhead:
            d["overhead"] = overhead_data(args.overhead, _history(args.history))
        if args.export:
            target = Path(args.export)
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_name(target.name + ".tmp")          # whole-file output: temp, then rename
            tmp.write_text(json.dumps(figure_data(d), indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
            os.replace(tmp, target)
            print(target)
            return 0
    try:
        import matplotlib  # noqa: F401
    except ImportError:
        print("plot_contributions: matplotlib is not installed (pip install -r requirements.txt)", file=sys.stderr)
        return 3
    out = Path(args.out or ("figures" if args.data else Path(args.run) / "results" / "figures"))
    out.mkdir(parents=True, exist_ok=True)
    for name, fn in FIGURES:
        print(fn(d, out / name, args.dpi))
    return 0


if __name__ == "__main__":
    sys.exit(main())
