# Final numbers (9 October 2026), for plotting

The final configuration's results as plain CSV, so anyone can plot them without the VM. All come from one
configuration: the optimised Tetragon policies (`node/tetragon/opt/`) with ML-B retrained under them. They
are copied from the run outputs on the demo VM; the per-scenario rows add up to the system totals.

| File | What it holds | Source on the VM | Paper figure |
|---|---|---|---|
| `detection_by_scenario.csv` | runs flagged per scenario and system (out of 5), with truth and the known/unknown label | `run-final/results/COMPARISON.md` | figure 5 (scenario × system), figure 4 (trust/admission rows) |
| `detection_by_system.csv` | TP, FP, FN, TN, precision, recall, F1, false-positive rate, attribution level, known/unknown recall | `run-final/results/COMPARISON.md` | figure 2 (detection and false alarms) |
| `overhead_opt5.csv` | runtime cost: median, min and max of 3 repetitions per metric and configuration, and the overhead against no monitoring; CPU and memory | `run-overhead-opt5/results/OVERHEAD.md` | a runtime-cost figure (questions 3 and 4) |
| `overhead_history.csv` | overhead against no monitoring in the three valid runs: original policies (`orig4`), filters and rate limits (`opt4`), final (`opt5`) | `run-overhead-{orig4,opt4,opt5}/results/OVERHEAD.md` | "how the cost came down" |
| `preparation_components.csv` | preparation per new image, split into components | `run-final/results/PREP.md` | figure 1b (components) |
| `preparation_summary.csv` | preparation per new image, total and counts | `run-final/results/PREP.md` | figure 1 (time per system) |

Reading the numbers:

- **Overhead** is the change against no monitoring, in percent. For latency, positive means slower; for
  throughput it is the loss (positive means fewer requests per second). A negative value is within the
  measurement noise (PROVBIND on the request mix).
- **Request mix:** 60% `GET /`, 25% `/healthz`, 15% `/cache`, 4 concurrent clients, 120 s. **/cache:** every
  request writes a file, 60 s. **Worst case:** a tight loop of 20,000 file writes, and of 500 process starts.
- The 20% limit is the supervisor's: every application metric of PROVBIND is within it (worst +9.9%). Only
  the process-start loop is over (+118.6%).
- **Known/unknown:** known attacks have an advisory, signature or revoked key that could describe them
  (7 scenarios, 35 runs); unknown ones have nothing (6 scenarios, 30 runs).
- DeSFAM-E and Confine-E are estimated from their published designs on recorded traces; Sig-only is derived
  from the admission records.

To draw the paper figures exactly as designed, use `eval/baselines/plot_contributions.py` on the full run
folder (`docs/FIGURES-HOWTO.md`): it also reads the alerts, envelopes and traces, which are not in this
folder. These CSV files hold the same numbers for any other tool.
