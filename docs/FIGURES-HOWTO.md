# How to make the graphs

For whoever draws the figures. Everything needed is in the repository: no VM, no results bundle. There are
two ways:

- **A. The paper figures**: one command draws the eight figures as designed after the supervisor's
  feedback (5 October 2026).
- **B. Your own charts**: the final numbers are CSV files, with a short example script to start from.

Both use the final results of 9 October 2026, in `docs/figures/data/final-2026-10-09/`.

## 1. Set up (once)

From a clone of the team repository, on `main`:

```bash
git checkout main && git pull
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install matplotlib pandas      # all the plotting needs; pip install -r requirements.txt also works
```

Run every command below from the repository's top folder (the one with `README.md`).

## 2. A. The paper figures

```bash
python -m eval.baselines.plot_contributions --data docs/figures/data/final-2026-10-09 --out figures --dpi 300
```

It prints the path of each file it writes into `figures/`. All are PNG at 300 dpi, sized for an IEEE
page (7.16 in across two columns, 3.5 in for one).

| File | Shows | Supervisor's question |
|---|---|---|
| `fig1_c1_specification.png` | time until each system can protect a new image, measured, with the package and file counts behind each bar | Q1: exact times, not estimates; how many packages |
| `fig1b_c1_components.png` | each system's preparation split into its timed components | Q1 (optional figure) |
| `fig2_c2_verification.png` | (a) attacks caught and false alarms per system; (b) PROVBIND's check time per event | Q3: the accuracy side |
| `fig3_c3_attribution.png` | what each system's alerts name (container, process, rule, package, layer, dependency path), as "named / alerts" in every cell | Q1: easier to read |
| `fig4_c4_trust.png` | admission and trust scenarios: runs caught per system; trust-loop reaction time | - |
| `fig5_scenarios.png` | every scenario × system: right (blue), wrong (orange), no check at that stage (grey), with the runs judged right per system at the bottom | Q1: one rule for every cell |
| `fig6_runtime_cost.png` | PROVBIND and Falco against no monitoring on each application metric, with the 20% limit | Q3 and Q4 |
| `fig7_cost_history.png` | PROVBIND's p95 overhead in each overhead run, in the order the sensor policies were optimised | Q4: the optimisation |

Systems marked `*` (Confine-E, DeSFAM-E) are estimated from their published designs on our recorded
traces; `†` (Sig-only) is derived from the admission records. PROVBIND and Falco are measured.

### Check before sending

- Figure 1's title says "(measured)".
- Figure 5's bottom row reads PROVBIND 80 / 95 right, Falco 45, Confine-E 25, DeSFAM-E 41, Sig-only 35.
- Figure 6: PROVBIND's longest bar is +9.9% (file-writing requests, median latency), left of the 20% line.
- Figure 7: (a) +377.5%, +205.2%, +8.0%; (b) +86.0%, +23.6%, -0.1%.

## 3. B. Your own charts from the CSV files

The CSV files and what each holds are listed in `docs/figures/data/final-2026-10-09/README.md`. To start
from a working example:

```bash
python docs/figures/data/final-2026-10-09/plot_example.py --out my-figures
```

It writes four charts: `detection.png` (attacks caught and false alarms per system), `runtime_cost.png`
(PROVBIND and Falco with the 20% limit), `cost_history.png` (how PROVBIND's cost came down) and
`preparation.png` (time per new image, log scale). Each is one short function in the script. The pattern
is always the same: read a CSV, pick rows, draw, save. For example, the runtime cost:

```python
import matplotlib.pyplot as plt
import pandas as pd

df = pd.read_csv("docs/figures/data/final-2026-10-09/overhead_opt5.csv")
app = df[df["unit"].isin(["ms", "req/s"]) & ~df["metric"].str.contains("worst case")]
prov = app[app["configuration"] == "provbind"]

fig, ax = plt.subplots(figsize=(6.5, 3))
ax.barh(prov["metric"], prov["overhead_pct"].clip(lower=0), color="#2a78d6", label="PROVBIND")
ax.axvline(20, color="black", linestyle="--", label="20% limit")
ax.set_xlabel("change against no monitoring (%)")
ax.legend()
fig.savefig("runtime_cost.png", dpi=200, bbox_inches="tight")
```

The CSV files also open in Excel or Google Sheets.

Reading the numbers:

- **Overhead** is the change against the same app with no monitoring, in percent. For latency, positive
  means slower; for throughput it is the loss. A value at or below 0 is within the measurement noise.
- **Detection**: 65 attack runs and 30 benign runs (19 scenarios × 5 runs). Recall is attacks caught;
  the false-positive rate is benign runs with an alarm.
- **Preparation**: the time from a new image to the system being ready to protect it. Falco has no
  per-image step (0 s); PROVBIND + ML-B includes 7 hours of recorded benign traffic.

## 4. Where the figure data comes from

You don't need this to plot. `figures.json` is made once on the demo VM, where the test runs are, by
Role 1, with `plot_contributions.py --export` (the command is in the script's help text). It holds
aggregates only (counts, rates, medians, timings): no alert, trace, pod detail or key leaves the VM.
After a new test run it is exported again.

## 5. If something fails

| Message | Fix |
|---|---|
| `No module named 'matplotlib'` (or `pandas`) | `pip install matplotlib pandas` in the active environment |
| `No module named 'eval'` | run from the repository's top folder |
| `cannot read the figure data: ... figures.json` | the figure data is not in the repository yet: `git pull` later, or ask Role 1; the CSV charts (section 3) work meanwhile |
| anything else | send the last 20 lines of the output to Role 1 |
