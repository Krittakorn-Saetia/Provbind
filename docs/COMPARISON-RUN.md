# Comparison run: PROVBIND vs Falco, Confine and DeSFAM

**Branch:** `local/comparison-baselines` (Role 2, Korn) · **Date:** 1 October 2026 · **Status:** code and
unit tests done; **no VM run yet, so no numbers.** Every result comes from Role 1's run on the demo VM.

This note says why the comparison exists, what this branch adds, how to run it, and what its limits are.

---

## 1. Why we did this

Our advisor asked us to compare PROVBIND with related work. The agreed design (Korn, 30 September):

- **Four systems plus one baseline.** PROVBIND and **Falco** are *measured* on the demo VM. **Confine**
  [14] and **DeSFAM** [24] have no usable public code for our setting, so each is represented by an
  **estimated function**: its published decision rules, applied to system-call traces we record from our
  own scenarios. They are always labelled *estimated*. **Sig-only** ("check the signature at admission
  and nothing else") is the draft's own fifth baseline; it is *derived* from PROVBIND's binding records.
- **The test grid.** Known and unknown (zero-day) threats, at admission and inside the container, plus
  benign activity that must not alert.
- **Where the threats come from.** Behaviours reported in the Datadog malicious-packages dataset,
  **re-created harmlessly** by our own test code. No sample is downloaded, opened or run anywhere
  (`testbed/behaviours.md`, Test Plan §12.4).
- **Honest framing.** Confine and DeSFAM guard the *kernel boundary* (privilege escalation, escape), not
  the supply chain. The grid includes one kernel-CVE-shaped scenario (R-K2) so the comparison is not
  only on our home ground, and the paper should call them **complementary**.

What it shows for the four contributions:

| Contribution | Evidence from this run |
|---|---|
| C1 specification compilation | a design property: shown in the feature table, not a detection number |
| C2 runtime verification | detection rate and false-positive rate per system (`COMPARISON.md`) |
| C3 attribution | attribution level per system: 3 PROVBIND, 1 Falco and DeSFAM, 0 Confine and Sig-only |
| C4 trust re-evaluation | the admission and trust rows (A-K1, A-K3, R-K1): what Sig-only misses and PROVBIND catches |

---

## 2. What this branch adds

| Path | What it is |
|---|---|
| `eval/baselines/trace.py`, `syscalls.py` | read a recorded trace; read the libc functions an ELF file imports; map them to system calls |
| `eval/baselines/confine_estimate.py` | **Confine-E**: allow list = system calls the image's programs can make (static); a run is *blocked* if its trace uses a call outside it |
| `eval/baselines/desfam_estimate.py` | **DeSFAM-E**: DeSFAM's allow-list formula (Eq. 1) plus an Isolation Forest over 15-call windows, threshold at the 99.5th percentile of benign scores; DeSFAM's published recall/FPR reported beside it |
| `eval/baselines/aggregate.py` | joins everything per ground-truth run and writes the tables: detected or not, the stage (admission / runtime / trust), confusion matrix, precision, recall, F1, FPR, attribution level |
| `eval/baselines/record_trace.sh` | bpftrace recorder: the demo pod's system calls only (filtered by its PID namespace) |
| `eval/baselines/export_binaries.sh` | copies the image's executables and libraries out of the pod, for the estimators |
| `eval/baselines/alert_latency.py` | time-to-alert for PROVBIND and Falco |
| `testbed/demo-app/tier2.py` (+ routes in `app.py`) | the new harmless scenario behaviours, one function per scenario |
| `testbed/demo-app/inj.c`, `gen_payload.sh` | a harmless shared library for R-K3, embedded at image build like `x9.c` |
| `testbed/demo-app/Dockerfile.au2` | the A-U2 image variant |
| `testbed/demo-app/volume-patch.yaml` | mounts an `emptyDir` at `/data` for B5 |
| `testbed/scenarios/*.sh` | one script per new scenario, each writing its ground-truth row; `deploy_lib.sh` and the `deploy-*.sh` admission scripts |
| `scripts/comparison-run.sh`, `make comparison` | the whole run, end to end |
| `tests/eval/test_baselines.py`, `test_aggregate.py` | unit tests (no VM needed) |

Everything our scenarios do happens inside the throwaway demo container.

---

## 3. The scenarios

Each runs `ROUNDS` times (default 5). The ground-truth name is what appears in `ground_truth.csv`, the
trace file names and the tables.

| Grid ID | Cell | Ground-truth name | `make` target | Re-creates (harmless) | PROVBIND expected |
|---|---|---|---|---|---|
| A-K1 | Admission, known | `ak-1` | `ak1` | advisory for our test package exists before deploy | trust alert |
| A-K2 | Admission, known | `ak-2` | `ak2` | unsigned image | binding failure |
| A-K3 | Admission, known | `ak-3` | `ak3` | signing key revoked before deploy | not verified (v_trust) |
| A-U2 | Admission, unknown | `au-2` | `au2-deploy` | a build step adds a program no package declares | weak `outside_closure` only (documented limit) |
| R-K1 | Runtime, known | `trust-1` | `trust` | advisory published while the pod runs | trust alert |
| — | Runtime, known | `trust-2` | `trust2` | signing key revoked while the pod runs | trust alert |
| R-K2 | Runtime, known | `rk-2` | `rk2` | the *shape* of kernel-CVE system calls, no exploit | none (complementary case) |
| R-K3 | Runtime, known | `rk-3` | `rk3` | library injection | `D_load` |
| R-U1 | Runtime, unknown | `attack-1` | `attack` | drop and execute | `D_exec` + `D_write` |
| R-U2 | Runtime, unknown | `attack-2` | `attack2` | in-envelope burst (needs ML-B; `ATTACK2=1`) | `D_beh` |
| R-U3 | Runtime, unknown | `ru-3` | `ru3` | outbound connection to an undeclared address; nothing is sent | `D_net` |
| R-U4 | Runtime, unknown | `ru-4` | `ru4` | a declared binary replaced (restored afterwards) | `D_write` |
| R-U5 | Runtime, unknown | `ru-5` | `ru5` | credential read; only a hash would be sent | none (PROVBIND's documented gap) |
| B1 | Benign | `benign-1` | `benign` | terminal shell | nothing above Low |
| B2 | Benign | `benign-traffic` | `benign-traffic` | normal requests | nothing above Low |
| B3 | Benign | `ph4-14` | `ph4-14` | a new file under `/tmp` | nothing above Low |
| B4 | Benign | `benign-3` | `benign-dns` | DNS lookups | nothing above Low |
| B5 | Benign | `benign-4` | `benign-vol` | writes to a mounted volume | nothing above Low |

---

## 4. How each system is judged

The same ground-truth row decides every system. A row is TP, FP, FN or TN from its label (malicious or
benign) and whether the system flagged that run.

| System | Kind | Read from | "Detected" means |
|---|---|---|---|
| PROVBIND | measured | `alerts.jsonl` | an alert above Low in the row's pod and time window |
| Falco | measured | `falco.jsonl` | any Falco rule in the row's pod and time window |
| Confine-E | estimated | `traces/<scenario>-<k>.txt` → `results/confine.json` | the trace uses a system call outside the static allow list |
| DeSFAM-E | estimated | the same trace → `results/desfam.json` | a 15-call window scores above the benign threshold (or a call outside its allow list) |
| Sig-only | derived | `bindings.json` + `results/admission-bindings.jsonl` | the pod's binding failed for a signature or attestation reason; a revoked key is a miss |

**The trace naming is a contract:** `traces/<scenario>-<k>.txt` is the k-th run of that scenario and must
line up with its k-th ground-truth row. `comparison-run.sh` names them this way.

---

## 5. How to run it (demo VM, Role 1)

### Once, before the run
1. `make up`, then **rebuild the demo image** with `make demo-app` (it now contains `tier2.py` and the R-K3
   library). Keep the printed `ref@digest` as `DEMO_REF`.
2. Install bpftrace: `sudo apt install bpftrace` (the VM owner's decision). Check the recorder on the
   running demo pod for 5 seconds:
   ```bash
   sudo eval/baselines/record_trace.sh --pid "$(pgrep -n -f 'python app.py')" --out /tmp/t.txt --seconds 5
   ```
   `/tmp/t.txt` should have tab-separated lines. If bpftrace rejects the PID-namespace filter on kernel 7.0,
   see the note at the top of `record_trace.sh` (`--pids` fallback).
3. Optional, for DeSFAM-E's template: Docker's default seccomp profile (a public JSON file, approved by
   Korn) saved as `eval/baselines/docker-seccomp.json`. Without it DeSFAM-E uses a built-in fallback.
4. A-U2 builds and **signs** its image variant each round: the key holder exports `COSIGN_PASSWORD`
   in that terminal (typed by hand, never stored), as for `make demo-app`.
5. **Check A-K1 once by hand** (see §8, item 1): `DEMO_REF=... make ak1`, then `make show` must list a trust
   alert for a `demo-app-akadv-…` pod.
6. Start from a fresh run folder (`mv run run-old`).

### The run
Run it as your normal user, with the project's venv active. It asks for the sudo password once (bpftrace
only). Do not run it under `sudo`: sudo resets `PATH` and Python loses the venv's packages.
```bash
DEMO_REF=localhost:5001/demo-app@sha256:<hex> make comparison
```
Options (environment variables): `ROUNDS=5`, `TRACE=0` (no bpftrace: PROVBIND vs Falco only),
`ATTACK2=1` (add R-U2 once ML-B is trained), `ADMISSION=0` (skip the admission scenarios),
`BASELINE_SECONDS=600`, `BASELINE_CYCLES=3`, `STARTUP_SECONDS=30`, `DOCKER_SECCOMP=<path>`.

Rough duration with the defaults: 30 min benign baseline + about 1 h of runtime rounds + about 1 h of
admission rounds (each rebuilds an image). Do not type in the terminal or snapshot the VM while it runs.

What it does, in order: starts the controller, node, alerts, trust loop and Falco capture (as
`make scored`) → deploys the signed demo app with `/data` → start-up trace from the moment the pod is
ready → exports the image's binaries → benign baseline traces → every runtime and benign scenario,
`ROUNDS` times, each with its own trace → the admission scenarios → Confine-E and DeSFAM-E → the tables.

### Only the analysis (any PC, after the run)
```bash
python -m eval.baselines.confine_estimate --binaries run/traces/binaries --trace run/traces/rk-2-1.txt ... --out run/results/confine.json
python -m eval.baselines.desfam_estimate  --binaries run/traces/binaries --benign 'run/traces/baseline/benign-*.txt' \
    --docker-seccomp eval/baselines/docker-seccomp.json --trace ... --out run/results/desfam.json
python -m eval.baselines.aggregate --run run --confine run/results/confine.json --desfam run/results/desfam.json --write
```

---

## 6. What you get (`run/results/`)

| File | Content |
|---|---|
| `COMPARISON.md` | the tables: per-scenario "flagged / runs" for each system; per-system TP/FP/FN/TN, precision, recall, F1, FPR, attribution |
| `COMPARISON.json` | the same data, machine-readable: `rows` (one per run, with the stage per system) and `tables` |
| `SCORING.md` | the existing PROVBIND vs Falco scoring matrix (`make compare`) |
| `confine.json`, `desfam.json` | the estimators' detail per trace (for example which call Confine-E would block) |
| `admission-bindings.jsonl` | the admission pods' bindings, saved before teardown (for Sig-only) |
| `latency.json` | time-to-alert |

The raw inputs stay in `run/` (`ground_truth.csv`, `alerts.jsonl`, `falco.jsonl`, `traces/`), so every
table can be rebuilt. For your own charts, load the JSON:
```python
import json, pandas as pd
doc = json.load(open("run/results/COMPARISON.json"))
runs = pd.DataFrame(doc["rows"])                                         # one row per run
per_scenario = pd.DataFrame(doc["tables"]["per_scenario"])
per_system = pd.DataFrame.from_dict(doc["tables"]["systems"], orient="index")
```

---

## 7. Limits to state in the paper

- **Estimates, not the real systems.** Confine-E's libc→syscall map approximates Confine's glibc
  analysis. DeSFAM-E leaves out the VAE half of DeSFAM's model and simplifies its template; DeSFAM's
  published recall (0.90) and FPR (1.6 %) are reported beside the estimate, never instead of it.
- **No admission check in Confine or DeSFAM.** Admission rows have no traces, so both count as "not
  detected" there. That is their design, not a gap in the estimate.
- **Sig-only is derived** from the reason in PROVBIND's own binding record, not a separate tool.
- **Start-up trace** begins when the pod is ready (a second or two after the container starts), not at
  the very first instruction.
- **Tracing slows the pod.** Time-to-alert and overhead come from a separate untraced run
  (`make scored`), not from this one.
- **Falco's clock drifts on VirtualBox** (Role 1's finding): stop guest time sync and restart Falco first.

---

## 8. Open items

1. **A-K1 may be scored wrongly.** The trust loop alerts once per *image*, and A-K1 deploys the same
   image as the running demo pod, so the short-lived pod may get no alert of its own. Check it once
   by hand before the full run (§5 step 5). If it fails, the fix is a decision for the team: stop the
   main demo pod during the admission phase, or give A-K1 its own signed image.
2. **Names versus the Test Plan.** Test Plan §7 already numbers some of these behaviours (`attack-4`,
   `attack-5`, `attack-7`, `attack-8`, `attack-9`) and reserves `/update4`–`/update9` for them. This branch
   uses the comparison-grid names (`ru-4`, `rk-3`, `ru-3`, `au-2`, `ak-2`) and endpoints `/rk2`…`/au2`.
   Decide whether to rename before the run, then update `testbed/behaviours.md`.
3. **R-U5 has no sink service.** No in-cluster sink is deployed, so its send never connects; the
   credential read itself still happens. Deploy a small sink if the connection should be in the trace.
4. **`docs/EVAL-COMPARISON-PLAN.md`** (branch `cloud/eval-comparison-plan`) calls the estimator outputs
   `confine_e.json` / `desfam_e.json`; this branch writes `confine.json` / `desfam.json`. Align them when
   both are merged.
