"""Plot the final numbers from the CSV files in this folder: a short, plain example with pandas and
matplotlib, for anyone who wants to draw their own charts. The paper figures themselves come from
eval/baselines/plot_contributions.py (see docs/FIGURES-HOWTO.md).

    pip install -r requirements.txt
    python docs/figures/data/final-2026-10-09/plot_example.py --out my-figures

Writes four PNG files: detection.png, runtime_cost.png, cost_history.png and preparation.png.
"""
import argparse
import textwrap
from pathlib import Path

import matplotlib

matplotlib.use("Agg")                       # draw straight to files; no window needed
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

HERE = Path(__file__).resolve().parent      # the CSV files sit next to this script
BLUE, ORANGE = "#2a78d6", "#eb6834"         # the two colours the paper figures use
LIMIT = 20.0                                # the supervisor's limit on runtime cost, in percent
MARK = {"measured": "", "estimated": "*", "derived": "†"}   # * estimated, dagger derived


def detection(out):
    """Attacks caught (recall) and false alarms (false-positive rate), per system."""
    df = pd.read_csv(HERE / "detection_by_system.csv")
    names = [s + MARK[k] for s, k in zip(df["system"], df["kind"])]
    x = range(len(df))
    fig, ax = plt.subplots(figsize=(6.5, 3))
    for shift, column, label, colour in ((-0.2, "recall", "attacks caught (recall)", BLUE),
                                         (0.2, "FPR", "false alarms (false-positive rate)", ORANGE)):
        bars = ax.bar([i + shift for i in x], df[column] * 100, 0.4, label=label, color=colour)
        ax.bar_label(bars, fmt="%.0f%%", fontsize=7)
    ax.set_xticks(list(x), names)
    ax.set_ylabel("% of runs")
    ax.set_ylim(0, 110)
    ax.legend(fontsize=8, loc="upper right")
    ax.set_title("Detection, final run (65 attack runs, 30 benign runs)", loc="left", fontsize=10)
    fig.text(0.01, -0.04, "* estimated from the published design   † derived from the admission records",
             fontsize=7)
    return save(fig, out / "detection.png")


def runtime_cost(out):
    """PROVBIND and Falco against no monitoring on the application workloads, with the 20% limit."""
    df = pd.read_csv(HERE / "overhead_opt5.csv")
    app = df[df["unit"].isin(["ms", "req/s"]) & ~df["metric"].str.contains("worst case")]
    metrics = list(dict.fromkeys(app["metric"]))[::-1]          # keep the file's order, top to bottom
    fig, ax = plt.subplots(figsize=(6.5, 3.2))
    for shift, config, label, colour in ((0.2, "provbind", "PROVBIND", BLUE), (-0.2, "falco", "Falco", ORANGE)):
        pct = [app[(app["metric"] == m) & (app["configuration"] == config)]["overhead_pct"].iloc[0] for m in metrics]
        bars = ax.barh([i + shift for i in range(len(metrics))], [max(v, 0) for v in pct], 0.4,
                       label=label, color=colour)
        ax.bar_label(bars, labels=[f"{v:+.1f}%" for v in pct], padding=3, fontsize=7)
    ax.axvline(LIMIT, color="black", linestyle="--", linewidth=1, label=f"{LIMIT:.0f}% limit")
    ax.set_yticks(range(len(metrics)), metrics, fontsize=8)
    ax.set_xlim(0, LIMIT * 1.2)
    ax.set_xlabel("change against no monitoring (%); for throughput, the loss")
    ax.legend(fontsize=8, loc="lower right")
    ax.set_title("Runtime cost, final policies (median of 3 repetitions)", loc="left", fontsize=10)
    return save(fig, out / "runtime_cost.png")


def cost_history(out):
    """How PROVBIND's cost came down over the three valid overhead runs (p95 latency)."""
    df = pd.read_csv(HERE / "overhead_history.csv")
    prov = df[df["configuration"] == "provbind"]
    runs = list(dict.fromkeys(prov["policy_set"]))              # original, filters and rate limits, final
    fig, ax = plt.subplots(figsize=(6.5, 3))
    for shift, metric, label, colour in ((-0.2, "request latency p95, /cache", "file-writing requests", BLUE),
                                         (0.2, "request latency p95, mix", "request mix", ORANGE)):
        pct = [prov[(prov["policy_set"] == r) & (prov["metric"] == metric)]["overhead_pct"].iloc[0] for r in runs]
        bars = ax.bar([i + shift for i in range(len(runs))], [max(v, 0) for v in pct], 0.4, label=label, color=colour)
        ax.bar_label(bars, labels=[f"{v:+.1f}%" for v in pct], padding=3, fontsize=7,
                     bbox=dict(facecolor="white", edgecolor="none", pad=0.5))     # keeps the limit line off the text
    ax.axhline(LIMIT, color="black", linestyle="--", linewidth=1, label=f"{LIMIT:.0f}% limit", zorder=0)
    ax.set_xticks(range(len(runs)), [textwrap.fill(r, 22) for r in runs], fontsize=8)
    ax.set_ylabel("PROVBIND, p95 latency\nchange against no monitoring (%)", fontsize=8)
    ax.margins(y=0.12)                                          # room above the tallest bar for its label
    ax.legend(fontsize=8)
    ax.set_title("PROVBIND's runtime cost over the optimisation", loc="left", fontsize=10)
    return save(fig, out / "cost_history.png")


def preparation(out):
    """Time until each system can protect a new image (log scale: from seconds to hours)."""
    df = pd.read_csv(HERE / "preparation_summary.csv")
    fig, ax = plt.subplots(figsize=(6.5, 2.6))
    y = range(len(df))[::-1]
    ax.barh(list(y), df["total_seconds"].where(df["total_seconds"] > 0), 0.6, color=BLUE)
    for yi, s in zip(y, df["total_seconds"]):
        text = "0 s: no per-image step" if s == 0 else f"{s:.2f} s" if s < 60 else (
            f"{s / 60:.1f} min" if s < 3600 else f"{s / 3600:.1f} h")
        ax.text(max(s, 1) * 1.15, yi, text, va="center", fontsize=7)
    ax.set_xscale("log")
    ax.set_xlim(1, 3e5)
    ax.set_yticks(list(y), df["system"], fontsize=8)
    ax.set_xlabel("seconds (log scale)")
    ax.set_title("Preparation time per new image", loc="left", fontsize=10)
    return save(fig, out / "preparation.png")


def save(fig, path):
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="my-figures", help="folder for the PNG files (default: my-figures)")
    out = Path(ap.parse_args().out)
    out.mkdir(parents=True, exist_ok=True)
    for draw in (detection, runtime_cost, cost_history, preparation):
        print(draw(out))
