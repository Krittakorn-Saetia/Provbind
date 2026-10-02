"""Figures for Role 1's results: the comparison run, the 30 September scored runs and ML-A.

    python -m eval.plots --comparison run/results/COMPARISON.json --desfam run/results/desfam.json \\
        --out docs/figures
    python -m eval.plots --comparison docs/figures/data/comparison-2026-10-01.json --out docs/figures

`--comparison` takes the aggregator's COMPARISON.json (or a summary with the same `tables`); DeSFAM-E's
per-trace fractions come from `--desfam` (desfam.json) or from the summary's `desfam` key. The 30
September numbers (Test 1, Test 2, ML-A) are fixed below, from docs/ROLE1-RESULTS-2026-09-30.md.
Writes PNG (200 dpi) and SVG for each figure; logs go to stderr. Needs matplotlib.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

SYSTEMS = ["PROVBIND", "Falco", "Confine-E", "DeSFAM-E", "Sig-only"]
# Categorical slots 1-5 of the reference palette, validated (light surface); each system keeps its colour
# in every figure. Three slots sit below 3:1 on the surface, so every bar carries a direct value label.
COLOR = {"PROVBIND": "#2a78d6", "Falco": "#eb6834", "Confine-E": "#1baf7a", "DeSFAM-E": "#eda100",
         "Sig-only": "#e87ba4"}
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3de"
SEQ = ["#cde2fb", "#86b6ef", "#2a78d6", "#184f95"]          # sequential blue, light -> dark

KNOWN = {"ak-1", "ak-2", "ak-3", "trust-1", "trust-2", "rk-2", "rk-3"}
UNKNOWN = {"au-2", "attack-1", "attack-2", "ru-3", "ru-4", "ru-5"}
GROUPS = [("Admission", ["ab-1", "ak-1", "ak-2", "ak-3", "au-2"]),
          ("Runtime, known", ["trust-1", "trust-2", "rk-2", "rk-3"]),
          ("Runtime, unknown", ["attack-1", "attack-2", "ru-3", "ru-4", "ru-5"]),
          ("Runtime, benign", ["benign-1", "benign-traffic", "ph4-14", "benign-3", "benign-4"])]

# docs/ROLE1-RESULTS-2026-09-30.md, Sections 1 and 7; Comparison from the run's own tables.
HISTORY = {"Test 1\n30 Sep, 20 runs": {"PROVBIND": (0.91, 0.20), "Falco": (0.50, 0.50)},
           "Test 2 (ML-A)\n30 Sep, 60 runs": {"PROVBIND": (1.00, 0.00), "Falco": (0.40, 0.33)},
           "Comparison\n1 Oct, 90 runs": {"PROVBIND": (0.86, 0.00), "Falco": (0.53, 0.33)}}
MLA = [("ML-A (LightGBM)", 0.516, 0.090), ("Pod's full default set", 0.178, None),
       ("Curated allowlist + port rule", 0.0, None), ("Empty set (Test 1's envelope)", 0.0, None)]


def _plt():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "font.family": "DejaVu Sans", "font.size": 10, "text.color": INK, "axes.labelcolor": INK2,
        "axes.edgecolor": GRID, "xtick.color": INK2, "ytick.color": INK, "axes.titlesize": 11,
        "axes.titleweight": "bold", "axes.titlelocation": "left", "hatch.color": SURFACE, "hatch.linewidth": 1.2,
        "axes.spines.top": False, "axes.spines.right": False, "axes.spines.left": False,
    })
    return plt


def _save(fig, out, name):
    for ext in ("png", "svg"):
        fig.savefig(os.path.join(out, f"{name}.{ext}"), dpi=200, bbox_inches="tight")
    print(f"plots: wrote {out}/{name}.png and .svg", file=sys.stderr)


def _hbars(ax, labels, values, colors, hatches, fmt, xmax=1.0, notes=None):
    y = list(range(len(labels)))[::-1]
    for yi, v, c, h in zip(y, values, colors, hatches):
        ax.barh(yi, v or 0, height=0.62, color=c, hatch=h, edgecolor=SURFACE, linewidth=0)
        ax.text((v or 0) + xmax * 0.02, yi, fmt(v), va="center", ha="left", color=INK, fontsize=9)
    ax.set_yticks(y, labels)
    ax.set_xlim(0, xmax * 1.22)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(axis="y", length=0)
    if notes:
        for yi, label in zip(y, labels):
            if label in notes:
                ax.text(xmax * 1.21, yi - 0.38, notes[label], ha="right", va="center", fontsize=7.5, color=INK2)


def _recall(per, systems, members):
    out = {}
    for n in systems:
        runs = sum(s["runs"] for s in per if s["scenario"] in members)
        hit = sum(s[n] for s in per if s["scenario"] in members)
        out[n] = (hit / runs if runs else None, hit, runs)
    return out


def fig_metrics(plt, tables, out):
    per, sysm = tables["per_scenario"], tables["systems"]
    names = [n for n in SYSTEMS if n in sysm]
    known, unknown = _recall(per, names, KNOWN), _recall(per, names, UNKNOWN)
    hatch = ["//" if sysm[n]["kind"] == "estimated" else "" for n in names]
    colors = [COLOR[n] for n in names]
    fig, axes = plt.subplots(1, 4, figsize=(13.5, 3.4), sharey=True)
    panels = [("F1\n(higher is better)", [sysm[n]["f1"] for n in names], lambda v: "n/a" if v is None else f"{v:.2f}"),
              ("False-positive rate\n(lower is better)", [sysm[n]["fpr"] for n in names], lambda v: f"{v:.2f}"),
              (f"Recall, known threats\n({next(iter(known.values()))[2]} malicious runs)", [known[n][0] for n in names],
               lambda v: f"{v:.2f}"),
              (f"Recall, unknown threats\n({next(iter(unknown.values()))[2]} malicious runs)", [unknown[n][0] for n in names],
               lambda v: f"{v:.2f}")]
    for ax, (title, vals, fmt) in zip(axes, panels):
        _hbars(ax, names, vals, colors, hatch, fmt)
        ax.set_title(title, fontsize=10)
    fig.suptitle(f"Comparison run: five systems, {tables['runs']} scored runs", x=0.01, ha="left",
                 fontsize=13, fontweight="bold", y=1.12)
    fig.text(0.01, -0.08, "Hatched: estimated from published designs applied to our system-call traces, not measured. "
             f"DeSFAM-E's unknown-threat recall comes with a false-positive rate of {sysm['DeSFAM-E']['fpr']:.2f}: "
             "it flags most benign runs too." if "DeSFAM-E" in sysm else "",
             fontsize=8.5, color=INK2)
    _save(fig, out, "comparison-metrics")
    plt.close(fig)


def fig_scenarios(plt, tables, out):
    from matplotlib.colors import LinearSegmentedColormap
    per = {s["scenario"]: s for s in tables["per_scenario"]}
    names = [n for n in SYSTEMS if n in tables["systems"]]
    rows, seps, glabels = [], [], []
    for g, members in GROUPS:
        present = [m for m in members if m in per]
        if not present:
            continue
        glabels.append((g, len(rows), len(rows) + len(present) - 1))
        rows += present
        seps.append(len(rows))
    extra = [s for s in per if s not in rows]
    rows += extra
    cmap = LinearSegmentedColormap.from_list("seq", SEQ)
    fig, ax = plt.subplots(figsize=(8.2, 0.36 * len(rows) + 1.6))
    for i, sc in enumerate(rows):
        s = per[sc]
        for j, n in enumerate(names):
            flagged = s[n]
            correct = flagged if s["label"] == "malicious" else s["runs"] - flagged
            share = correct / s["runs"] if s["runs"] else 0
            ax.add_patch(plt.Rectangle((j + 0.04, i + 0.06), 0.92, 0.88, color=cmap(share), linewidth=0))
            ax.text(j + 0.5, i + 0.5, f"{flagged}/{s['runs']}", ha="center", va="center", fontsize=8.5,
                    color="#ffffff" if share > 0.55 else INK)
    ax.set_xlim(0, len(names))
    ax.set_ylim(len(rows), 0)
    ax.set_xticks([j + 0.5 for j in range(len(names))], names)
    ax.xaxis.tick_top()
    ax.set_yticks([i + 0.5 for i in range(len(rows))],
                  [f"{r}  ({'mal.' if per[r]['label'] == 'malicious' else 'benign'})" for r in rows])
    ax.tick_params(length=0)
    for sp in ax.spines.values():
        sp.set_visible(False)
    for sline in seps[:-1]:
        ax.axhline(sline, color=INK2, linewidth=0.8)
    for g, a, b in glabels:
        ax.text(len(names) + 0.12, (a + b + 1) / 2, g, va="center", ha="left", fontsize=8.5, color=INK2,
                rotation=90)
    ax.set_title("Per scenario: runs flagged (number) and share judged correctly (colour)", pad=26, fontsize=11)
    sm = plt.cm.ScalarMappable(cmap=cmap)
    cb = fig.colorbar(sm, ax=ax, orientation="horizontal", fraction=0.035, pad=0.02, aspect=40)
    cb.set_label("share of runs judged correctly (malicious flagged, benign not flagged)", fontsize=8.5, color=INK2)
    cb.outline.set_visible(False)
    _save(fig, out, "comparison-per-scenario")
    plt.close(fig)


def fig_desfam(plt, desfam, labels, out):
    res = desfam.get("results", {})
    thr = desfam.get("trace_threshold")
    if thr is None:
        m = re.search(r"fraction threshold ([0-9.]+)", desfam.get("detector", ""))
        thr = float(m.group(1)) if m else None
    by = {}
    for name, r in res.items():
        sc = name[:-4].rsplit("-", 1)[0] if name.endswith(".txt") else name.rsplit("-", 1)[0]
        if r.get("phase2_fraction") is not None:
            by.setdefault(sc, []).append(r["phase2_fraction"])
    order = [m for _, ms in GROUPS for m in ms if m in by] + sorted(s for s in by if s not in sum((ms for _, ms in GROUPS), []))
    fig, ax = plt.subplots(figsize=(8.2, 0.34 * len(order) + 1.4))
    seen = set()
    for i, sc in enumerate(order):
        mal = labels.get(sc) == "malicious"
        key = "malicious" if mal else "benign"
        for k, v in enumerate(by[sc]):
            ax.scatter(v, i + (k - 2) * 0.09, s=60, marker="^" if mal else "o", alpha=0.9,
                       color="#eb6834" if mal else "#1baf7a", edgecolors=SURFACE, linewidths=0.8, zorder=3,
                       label=None if key in seen else ("malicious run" if mal else "benign run"))
            seen.add(key)
    if thr is not None:
        ax.axvline(thr, color=INK, linewidth=1, linestyle=(0, (4, 3)), zorder=2)
        ax.text(thr, -0.9, f" trace threshold {thr:.4f}", fontsize=8, color=INK, va="bottom")
    ax.set_yticks(range(len(order)), order)
    ax.set_ylim(len(order) - 0.5, -1.2)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(axis="y", length=0)
    ax.set_xlabel("share of a trace's 15-call windows scored anomalous")
    ax.set_title("DeSFAM-E: benign runs look more anomalous than attacks", pad=10)
    ax.legend(frameon=False, loc="upper right", fontsize=9)
    _save(fig, out, "desfam-anomaly-fractions")
    plt.close(fig)


def fig_history(plt, tables, out, label=None):
    hist = dict(HISTORY)
    if tables:
        s = tables["systems"]
        hist[label or f"This run\n{tables['runs']} runs"] = {n: (s[n]["f1"], s[n]["fpr"]) for n in ("PROVBIND", "Falco")}
    tests = list(hist)
    fig, axes = plt.subplots(1, 2, figsize=(4.4 + 2.0 * len(tests), 3.6))
    for ax, idx, title in ((axes[0], 0, "F1 (higher is better)"), (axes[1], 1, "False-positive rate (lower is better)")):
        w = 0.36
        for k, n in enumerate(("PROVBIND", "Falco")):
            xs = [i + (k - 0.5) * (w + 0.03) for i in range(len(tests))]
            vals = [hist[t][n][idx] for t in tests]
            ax.bar(xs, vals, width=w, color=COLOR[n], label=n, linewidth=0)
            for x, v in zip(xs, vals):
                ax.text(x, v + 0.02, f"{v:.2f}", ha="center", va="bottom", fontsize=8.5, color=INK)
        ax.set_xticks(range(len(tests)), tests, fontsize=8.5)
        ax.set_ylim(0, 1.12)
        ax.yaxis.grid(True, color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        ax.spines["bottom"].set_color(INK2)
        ax.tick_params(axis="x", length=0)
        ax.set_title(title, fontsize=10)
    fig.legend(*axes[0].get_legend_handles_labels(), frameon=False, loc="upper right", ncols=2, fontsize=9,
               bbox_to_anchor=(0.99, 1.06))
    fig.suptitle("PROVBIND vs Falco across all scored runs", x=0.01, ha="left", fontsize=13, fontweight="bold",
                 y=1.04)
    _save(fig, out, "scored-runs-history")
    plt.close(fig)


def fig_mla(plt, out):
    fig, ax = plt.subplots(figsize=(7.2, 2.4))
    labels = [m[0] for m in MLA]
    vals = [m[1] for m in MLA]
    y = list(range(len(MLA)))[::-1]
    for yi, (lab, v, sd) in zip(y, MLA):
        ax.barh(yi, v, height=0.6, color=COLOR["PROVBIND"], linewidth=0)
        if sd:
            ax.errorbar(v, yi, xerr=sd, color=INK, capsize=3, linewidth=1)
        ax.text(v + (sd or 0) + 0.015, yi, f"{v:.3f}" + (f" ± {sd:.3f}" if sd else ""), va="center", fontsize=8.5)
    ax.set_yticks(y, labels)
    ax.set_xlim(0, 0.8)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(axis="y", length=0)
    ax.set_xlabel("micro-F1, 5 folds × 3 repeats, split by image (22 images)")
    ax.set_title("ML-A capability prediction against simple baselines")
    _save(fig, out, "mla-capabilities")
    plt.close(fig)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.plots", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--comparison", help="COMPARISON.json, or a summary with its `tables`")
    ap.add_argument("--desfam", help="desfam.json (per-trace anomalous-window fractions)")
    ap.add_argument("--out", default="docs/figures")
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    plt = _plt()
    tables, desfam, label = None, None, None
    if args.comparison:
        doc = json.load(open(args.comparison, encoding="utf-8"))
        tables = doc["tables"]
        desfam = doc.get("desfam")
        label = doc.get("label")
    if args.desfam:
        desfam = json.load(open(args.desfam, encoding="utf-8"))
    if tables:
        fig_metrics(plt, tables, args.out)
        fig_scenarios(plt, tables, args.out)
        if desfam:
            labels = {s["scenario"]: s["label"] for s in tables["per_scenario"]}
            fig_desfam(plt, desfam, labels, args.out)
    fig_history(plt, tables, args.out, label)
    fig_mla(plt, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
