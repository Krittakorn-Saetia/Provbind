# How to draw the paper figures (for whoever plots them)

The figures come from one Python script, `eval/baselines/plot_contributions.py`, run on one run folder.
This note gives the exact steps, so the figures come out as the supervisor asked (5 October 2026).

## 1. Get the code

Use the branch `claude/zen-hypatia-pyrg25` (or `main` once PR #26 is merged). If you edited
`plot_contributions.py` locally, set those edits aside first, or the new version will not apply:

```bash
git stash            # only if you have local edits; `git stash drop` later if you don't need them
git fetch origin && git checkout claude/zen-hypatia-pyrg25 && git pull
python3.11 -m venv .venv && source .venv/bin/activate      # or your existing venv
pip install -r requirements.txt                            # includes matplotlib
```

## 2. Get the data

1. **The final comparison run (9 October, optimised policies):** unpack the results bundle
   (`provbind-results-final.tgz` from the team share). It holds a `run-final/` folder with `results/`
   (including `PREP.json`, the measured preparation times figure 1 needs), `ground_truth.csv`,
   `alerts.jsonl`, `falco.jsonl`, `envelopes/` and `traces/baseline/`. On the VM it is made with:
   ```
   tar czf provbind-results-final.tgz run-final/results run-final/ground_truth.csv run-final/alerts.jsonl \
     run-final/falco.jsonl run-final/envelopes run-final/traces/baseline
   ```
2. If `run-final/results/PREP.json` is missing, run `scripts/prep-run.sh` on the VM first (Role 1).
   Without it, figure 1 falls back to the old drawing with "by design" estimates.
3. The 2 October redo (`run/`, original policies) still draws the same way, with `--run run`.

## 3. Draw

```bash
python -m eval.baselines.plot_contributions --run run-final --out figures --dpi 300
```

It prints the paths it wrote. All are PNG, 300 dpi, sized for an IEEE page.

## 4. What each file shows

| File | Shows | What the supervisor asked for |
|---|---|---|
| `fig1_c1_specification.png` | time until a new image is protected, per system | the **exact** measured time (no estimates), and **how many packages** (plus files, repetitions or requests) behind each bar |
| `fig1b_c1_components.png` | each system's preparation split into components, one panel per system | optional; the breakdown exists for **every** system, not only PROVBIND |
| `fig2_c2_verification.png` | detection rate and false-positive rate | (unchanged) |
| `fig3_c3_attribution.png` | what each system's alerts name | "named / alerts" in every measured cell; package, layer and dependency path counted only over alerts about a file in the image; estimated systems in grey with yes/no from their design |
| `fig4_c4_trust.png` | admission and trust scenarios | (unchanged) |
| `fig5_scenarios.png` | every scenario x system | one rule for all rows: blue = right (caught / no alarm), orange = wrong (missed / false alarm), grey = no check at that stage; a word and a mark in every cell; runs judged right per system at the bottom |

## 5. Check before sending

- Figure 1 says "(measured)" in its title. If it shows hatched bars with "≥", `PREP.json` was not found.
- Figure 5's bottom row should match the comparison table (final run: PROVBIND 80/95, Falco 45,
  Confine-E 25, DeSFAM-E 41, Sig-only 35; the 2 October redo: 80, 45, 25, 40, 35).
- Figure 3's footer names how many PROVBIND alerts are about a file in the image.

## 6. If something fails

- `ModuleNotFoundError: matplotlib`: run `pip install -r requirements.txt` in the active venv.
- `no scenario rows in COMPARISON.json`: `--run` must point at the folder that contains `results/`.
- Any other error: send the last 20 lines of the output to Role 1.
