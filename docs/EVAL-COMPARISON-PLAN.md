# Four-system comparison: methodology and run checklist

For the paper's evaluation (EV-01 detection per scenario, EV-02 false positives on the benign
catalogue). It consolidates what is spread across the Sprint Handoff §5, Test Plan §12, and the
tool docstrings, and writes down the two estimated baselines' method for the first time. It
adds no numbers: every result cell is filled from a VM run.

> **Status (30 Sep).** The PROVBIND-vs-Falco half runs today (`eval/compare.py`, on `main`). The
> two estimated baselines and the four-system aggregator are on the unpushed local branch
> `local/comparison-baselines` and are not yet on `main`. No VM run has produced the real tables.
> Owners below.

## The systems

| System | What it is | Source |
|---|---|---|
| **PROVBIND** | The headline: admission trust + runtime `D_exec`/`D_write`/`D_load`/`D_net`/`D_cap` + ML-B | this repo |
| **PROVBIND w/o D_cap** | Ablation: the same alerts minus `D_cap`, for envelopes without ML-A capabilities. Never the headline | `eval/compare.py` |
| **Falco** | Runtime rules engine, the deployed baseline. Runtime behaviour only; no supply-chain trust | `eval/capture_falco.sh` → `falco.jsonl` |
| **Confine-E** *(estimated)* | Allow-list from the image binaries' imported libc calls; a run is "blocked" if its trace uses a call outside the list | `eval/baselines/` (unpushed) |
| **DeSFAM-E** *(estimated)* | Confine's allow-list plus an Isolation Forest over 15-call windows | `eval/baselines/` (unpushed) |

**Estimated** means a re-implementation of the published method from its paper, not the authors'
system. Both estimators are labelled "estimated" in every table, and the paper must say so: they
approximate the comparison, they do not reproduce it.

### Baseline method, and what is left out (for the paper's honesty)

- **Confine-E.** Confine builds a per-container seccomp allow-list by static analysis of the
  image's binaries. The estimate approximates that with the libc functions each closure binary
  imports (from its ELF dynamic symbols), mapped to syscalls through a curated, documented
  `libc → syscall` table. *Omitted:* Confine's full glibc call-graph analysis; the map is an
  approximation and is documented as one. Confine has no admission check, no attribution and no
  trust model — that is its design, not a gap in the estimate.
- **DeSFAM-E.** DeSFAM adds an anomaly detector on top of the allow-list. The estimate uses an
  Isolation Forest over sliding 15-call windows and reports DeSFAM's published operating point
  (≈90 % detection, ≈1.6 % false positive) alongside the estimate, never in place of it.
  *Omitted:* the VAE half of the published model; the estimate says so.

## Metrics (`eval/compare.py`)

Per system, from the confusion counts TP/FP/FN/TN: **precision**, **recall**, **F1**,
**false-positive rate** (FP / (FP + TN)), **accuracy**. A cell is `—` where the denominator is 0.
Reported over two scopes:

- **all** — every detection scenario.
- **runtime** — the `trust-*` scenarios removed, so Falco (which has no trust check) is compared
  like for like.

A run counts as **detected** when PROVBIND raised an alert above Low (trust alerts are High) or
Falco fired any rule. Scenarios that check something other than detection (e.g. `tamper-1` checks
the log) are marked "not counted". Fewer than the Test Plan §12.2 minimum of runs per scenario is
flagged, not hidden.

## Data flow and the file contract

Everything is in the run folder (`$PROVBIND_RUN`, Sprint Handoff §3.2):

| File | Written by | Read by |
|---|---|---|
| `ground_truth.csv` (`scenario,label,namespace,pod_prefix,start,end,expected`) | Role 1, `eval/ground_truth.py`, one row per run | both tools |
| `alerts.jsonl` (one PROVBIND alert per line) | Role 4 | both tools |
| `falco.jsonl` (Falco JSON, one event per line) | Role 1, `eval/capture_falco.sh` | both tools |
| `traces/<scenario>-<k>.txt` (bpftrace, tab-separated) | Role 1, on the VM | the estimators |
| `results/confine_e.json`, `results/desfam_e.json` | the estimators | the aggregator |

- **Trace naming is a contract:** `<scenario>-<k>.txt` is the k-th run of that scenario, and it
  must line up with that scenario's k-th `ground_truth.csv` row. The estimators score a trace; the
  aggregator joins it back to the truth row by (scenario, k).
- **`eval/compare.py`** produces `results/SCORING.md` / `.json` for the two PROVBIND variants and
  Falco. **`eval/baselines/aggregate.py`** (unpushed) produces `results/COMPARISON.md` / `.json`
  for all four systems, adding the **detection stage** (admission / runtime / trust) and each
  system's **attribution level**.

## Scenario matrix

The scenario → expected-detection map is `testbed/behaviours.md` (Role 1). It already lists the
Tier-1 scenarios (`attack-1`, `attack-2`, `trust-*`, the benign catalogue) as ready, and the
Tier-2 ones (`attack-5` library injection, `attack-7` exfiltration, `attack-8` install-time) as
not yet implemented. This doc does not duplicate it; the aggregator's per-scenario rows are keyed
to those names. The credential-read row is a documented PROVBIND gap (it hooks exec/write/
exec-mmap/capability/connect, not reads), and the paper states it plainly.

## VM run checklist (Role 1)

1. Start the cluster and the demo app; capture the startup trace and the benign baseline trace.
2. For each scenario, three or more runs (Test Plan §12.2, dataset D4). Around each run:
   - `python -m eval.ground_truth --scenario <name> --label <benign|malicious> --start now … --end now …`;
   - record `traces/<scenario>-<k>.txt` with the trace recorder;
   - keep PROVBIND's `alerts.jsonl` and Falco's `falco.jsonl` running.
3. Export the closure's ELF binaries once per image, for the estimators.
4. Run, in order: the two estimators → `eval/compare.py --write` → `eval/baselines/aggregate.py --write`.
5. The tables land in `results/` (`SCORING.md`, `COMPARISON.md`). Fill the shells below from them.

## Result tables (fill from the VM run — no numbers until then)

**Detection and false positives (runtime scope), per system:**

| System | TP | FP | FN | TN | Precision | Recall | F1 | FPR | Accuracy |
|---|---|---|---|---|---|---|---|---|---|
| PROVBIND | | | | | | | | | |
| PROVBIND w/o D_cap | | | | | | | | | |
| Falco | | | | | | | | | |
| Confine-E *(estimated)* | | | | | | | | | |
| DeSFAM-E *(estimated)* | | | | | | | | | |

**Per system, qualitative:**

| System | Detection stage(s) | Attribution | Supply-chain trust |
|---|---|---|---|
| PROVBIND | admission + runtime + trust | file → package → layer | yes |
| Falco | runtime | none | no |
| Confine-E *(estimated)* | runtime | none | no |
| DeSFAM-E *(estimated)* | runtime | none | no |

## Ownership and what is blocking

- **Mine (Role 2), done here:** this methodology write-up.
- **On the unpushed `local/comparison-baselines` branch (Korn):** the two estimators, the trace
  reader, the aggregator, their tests, and the VM helper scripts. Push it to reach `main`; I did
  not re-implement it here, to avoid colliding with that work.
- **Korn + Role 1:** the Tier-2 scenario re-creations (`attack-5/7/8`, the endpoints in
  `testbed/`) and the orchestration that runs them on the VM.
- **Blocked on the VM run:** every result table above, and the final paper prose.
