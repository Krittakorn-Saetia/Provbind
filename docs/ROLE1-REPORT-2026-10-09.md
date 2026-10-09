# PROVBIND evaluation report: the work since the supervisor's feedback

**SF9-26 PROVBIND prototype · Role 1 (testbed and evaluation) · 5–9 October 2026**

This report covers what we did after the supervisor's feedback of 5 October 2026, and what we found. The
full record of every run, with all the tables, is `docs/ROLE1-SUPERVISOR-QUESTIONS-2026-10-05.md`.

## Summary

On 5 October the supervisor asked four questions about our evaluation. All four are now answered, from one
final configuration of PROVBIND:

- **Q4, is the cost under 20%? Yes, after optimisation.** With its original sensor policies, PROVBIND's
  runtime cost was far over 20%: up to +378% at p95 on requests that write a file. We changed the
  policies so the kernel drops events that carry nothing new. PROVBIND's worst application overhead is now
  +9.9%, against Falco's +8.2%. The one measure still over 20% is a worst-case loop that does nothing but
  start processes (+119%).
- **Q3, is the cost worth the accuracy? Yes, on these tests.** For about Falco's runtime cost, PROVBIND
  caught twice as many attack runs (50 of 65, against 25), with no false alarm in 30 benign runs, where
  Falco raised 10. The optimisation cost no accuracy: the result is identical, scenario by scenario, to
  the run with the original policies.
- **Q2, is our zero-day method a recognised standard? It is adapted from recognised methods.** There is no
  single standard for testing unknown attacks. Our method adapts three recognised ones, used by the
  host-intrusion-detection benchmarks ADFA-LD and LID-DS and by newer work up to 2026. Seven checks show
  that no detector had access to the attacks before the test.
- **Q1, make the graphs easier to read. Done.** Figure 1 now shows each system's measured preparation time
  with exact package counts; figures 3 and 5 show counts and a right or wrong mark in every cell; two new
  figures show the runtime cost. All figures can be drawn from the repository alone.

We also found and corrected an error in our own measurements: the overhead numbers we reported before
7 October were too low, and they are withdrawn (Section 3.3).

## 1. The questions

| # | The supervisor's question (5 October) | Answer | Section |
|---|---|---|---|
| Q1 | Make the graphs make more sense and easier to read | Redesigned; exact measured times and counts | 4.4 |
| Q2 | Is our zero-day method a recognised standard? If not, did we adapt it from one? | Adapted from three recognised methods | 4.3 |
| Q3 | Is the runtime cost worth the accuracy gained by eliminating false positives? | Yes, on these tests | 4.2 |
| Q4 | Is the time PROVBIND spends to avoid mistakes under 20% of other work? If not, optimise | Yes, after optimisation | 4.1 |

## 2. The test setup

- **Testbed.** One demo image (a small Python web app) in a kind Kubernetes cluster on a VirtualBox VM
  (Ubuntu 24.04, kernel 7.0, Tetragon 1.7.1).
- **Systems compared.** PROVBIND and Falco with its default rules, both run live. DeSFAM-E and Confine-E
  are our estimates of two published designs, applied to system-call traces recorded during the same runs.
  "Signature check only" is derived from the admission records.
- **Scenarios.** 19 scenarios, each run 5 times: 95 runs, of which 65 are attack runs and 30 benign runs.
  The attacks re-create, harmlessly, behaviours reported for real malicious packages. 35 attack runs are
  *known* attacks (an advisory, a signature or a revoked key could describe them); 30 are *unknown*
  (nothing describes them).
- **Runtime cost** (new, Section 3.1). The same app under four configurations: no monitoring, Falco,
  Tetragon with PROVBIND's policies only, and the full PROVBIND. Each configuration is run three times, in
  shuffled order. "20%" is read as the change against the same app with no monitoring.

## 3. What we did, 5 to 9 October

| Date | Step | Outcome |
|---|---|---|
| 5 Oct | Built a runtime-cost test and a preparation-time measurement for every system | Cost measured against no monitoring and against Falco |
| 5–6 Oct | First cost runs; a first set of optimised sensor policies; two faults in the test itself fixed | Numbers later withdrawn (7 Oct) |
| 6 Oct | First detection check with the optimised policies | Every attack the app process carries out was missed, which led to the 7 October finding |
| 7 Oct | Found a measurement error: restarting the sensor left the app unmonitored | A probe now guards every run; earlier overhead numbers withdrawn |
| 7–8 Oct | Valid cost runs with the original (`orig4`) and optimised (`opt4`) policies | The cost explained: sensor events per request |
| 8 Oct | A rate limit on file truncation as well (`opt5`) | Within 20% on every application metric (worst +9.9%) |
| 8 Oct | Detection check with these policies | The same attacks caught; 2 false alarms from ML-B, which was trained under the old policies |
| 8–9 Oct | ML-B retrained under the optimised policies (7 h of benign traffic) | No false alarm in a held-out hour |
| 9 Oct | Final comparison (`run-final`): all 19 scenarios, 5 runs each, all systems; leakage checks; preparation times | The results in Section 4 |
| 9 Oct | Merged into the team's main branch; final numbers in the repository; a proposed Results section and citations for the paper | Section 6 |

### 3.1 A test of the runtime cost

The comparison of 2 October measured accuracy only. Nothing measured PROVBIND's cost against Falco or
against an unmonitored app. We wrote `scripts/overhead-run.sh`, which runs the same app, pod and image
under the four configurations above, with three workloads, from a client inside the cluster:

- a **request mix**: 60% `GET /`, 25% `/healthz` and 15% `/cache`, 4 concurrent clients, 120 s;
- **file-writing requests** only (`/cache`, where every request writes a file), 60 s;
- **worst-case loops** inside the container: 20,000 file writes, and 500 process starts.

It measures request latency (median and p95), throughput, time per file write and per process start, and
the CPU and memory of each monitor. For Q1 we also wrote `eval/prep_time.py`, which times each system's
preparation for a new image (Section 4.4).

### 3.2 First runs and first optimisation

The first runs put PROVBIND over 20%. PROVBIND's own check is cheap (1.9 µs per event at the median,
measured by replaying a recording), so we looked at the sensor's policies, which decide how many events
reach PROVBIND. We built an optimised policy set, `node/tetragon/opt/`, in which the kernel drops events
that carry nothing new: writes to pipes and sockets (PROVBIND discarded them anyway), and repeats of the
same event within a minute. It also removes return probes that PROVBIND does not use.

These runs also exposed three faults in the test itself, which we fixed: the graph database (used only
offline) was busy on its own during one configuration and is now paused; the load client resolved the
service name on every request and now resolves it once; and one run started while the previous load
client was still shutting down, so the script now waits for it and lists any failed workload.

### 3.3 A measurement error, found and corrected

On 6 October the first detection check with the optimised policies missed every attack that the app's
own process carries out. That pointed to a problem in the testbed rather than in the policies. The cause:
Tetragon reports only processes it saw start. The test script switched Tetragon off and on between
configurations while the app kept running, so after each restart Tetragon silently stopped reporting the
app. A probe (`scripts/probe-events.sh`) confirmed it: 0 of 20 test writes by the app were reported,
until the app was restarted; then 20 of 20.

What this means:

- **Every overhead number reported before 7 October is withdrawn**, including 44.8%, 32.1% and about 23%.
  In those runs the app's events never reached PROVBIND, so the cost looked lower than it was.
- The 6 October detection check says nothing about the optimised policies and was repeated (Section 3.5).
- **The 2 October accuracy results stand**: that run's recording contains the app's events (3,626 file-write
  events and all 5 test connections).

Every run script now restarts the app after the sensor and stops if the probe does not see the app's
events. All numbers in this report come from runs with that check.

### 3.4 Finding the cost and bringing it under 20%

With valid measurements, the original policies cost far more than the early runs had shown (`orig4`: +86%
at p95 on the request mix, +378% at p95 on file-writing requests). The numbers explained where it came
from: **the cost is the number of sensor events per request, times the cost of moving each event from the
kernel to PROVBIND.** With the original policies, moving the events used about 1.2 CPU cores, against
0.36 core for the sensor itself.

The optimised policies (`opt4`) removed most of these events, but one per file-writing request was left.
The app rewrites its cache files with `open(path, "w")`, and opening an existing file that way passes the
kernel's truncation hook, which had no rate limit. The request mix suffered too, although only 15% of its
requests write a file, because the demo server handles one request at a time: the others wait behind a
slow one. On 8 October we rate-limited the truncation hook the same way and removed its return probe
(`opt5`). With that, PROVBIND is within 20% on every application metric (Section 4.1).

### 3.5 Keeping the accuracy

A rate limit removes repeated events, so the detection had to be checked again with the new policies. On
8 October the runtime scenarios caught exactly the same attacks as on 2 October, but ML-B, PROVBIND's
behaviour model, raised 2 false alarms in 25 benign runs. It had been trained on traffic recorded under
the original policies, so we retrained it on 7 hours of benign traffic recorded under the optimised ones
(232 windows). In a held-out hour it raised no false alarm in 55 windows.

On 9 October the final comparison (`run-final`) ran all 19 scenarios five times with every system. Its
result is in Section 4.2. The seven leakage checks (Section 4.3) pass on this run, and the preparation
time of every system was measured on the same configuration (Section 4.4).

### 3.6 The zero-day method and the figures

In parallel we answered Q2 from the literature (Section 4.3) and redesigned the figures for Q1
(Section 4.4). Everything was merged into the team's main branch on 9 October, with the final numbers as
CSV files and a proposed Results section and citations for the paper (Section 6).

## 4. Results

All numbers come from one configuration: the optimised sensor policies with ML-B retrained under them.
Accuracy is from the final comparison (`run-final`, 9 October), runtime cost from the overhead run `opt5`
(8 October).

### 4.1 Q4: runtime cost

Change against the same app with no monitoring, median of 3 repetitions:

| Metric | Falco (default rules) | Tetragon with PROVBIND's policies | **PROVBIND** |
|---|---|---|---|
| Request mix: median / p95 latency | +3.2% / +4.7% | +0.4% / +0.3% | **−0.5% / −0.1%** |
| Request mix: throughput loss | 3.4% | 0.3% | **none** |
| File-writing requests: median / p95 latency | +8.2% / +7.7% | +9.7% / +7.7% | **+9.9% / +8.0%** |
| File-writing requests: throughput loss | 7.1% | 7.1% | **7.5%** |
| Worst case, tight loop: file write / process start | +5.1% / +15.8% | +1.7% / +127.2% | +5.2% / +118.6% |
| Monitor CPU (% of one core) / memory | 8.2% / 119 MB | 0.2% / 155 MB | 0.2% / 409 MB |

- **Every application metric is within 20%** (worst +9.9%, the median latency of file-writing requests),
  on par with Falco (+8.2%). A value at or below zero is within the measurement noise.
- In absolute terms, a file-writing request went from 0.87 to 0.95 ms (median) and from 1.08 to 1.17 ms
  (p95). The request mix is unchanged (p95 1.29 ms).
- **PROVBIND adds at most 0.4% over its sensor alone** (Tetragon with the same policies), which is the
  baseline the paper's evaluation plan names.
- **The one figure over 20% is a worst case:** a loop that only starts processes (0.41 to 0.91 ms per
  process). Every new process still produces its start and exit events, which no rate limit removes.
  Workloads that start many short-lived processes pay this.

How the cost came down, PROVBIND against no monitoring:

| PROVBIND | Request mix p95 | File-writing median | File-writing p95 | File-writing throughput loss |
|---|---|---|---|---|
| Original policies (`orig4`, 7 Oct) | +86.0% | +151.8% | +377.5% | 66.1% |
| In-kernel filters and rate limits (`opt4`, 8 Oct) | +23.6% | +71.5% | +205.2% | 49.1% |
| **Plus a rate limit on file truncation (`opt5`, 8 Oct)** | **−0.1%** | **+9.9%** | **+8.0%** | **7.5%** |

Figure 6 draws the first table, with the 20% limit; figure 7 draws the second.

### 4.2 Q3: the trade-off

Final comparison, 95 runs: 65 attack runs and 30 benign runs.

| System | Attack runs caught | False alarms | Precision | Recall | F1 | False-alarm rate | Known caught | Unknown caught |
|---|---|---|---|---|---|---|---|---|
| **PROVBIND** | **50 of 65** | **0 of 30** | 1.00 | 0.77 | **0.87** | **0.00** | 30 of 35 | 20 of 30 |
| Falco (default rules) | 25 of 65 | 10 of 30 | 0.71 | 0.38 | 0.50 | 0.33 | 15 of 35 | 10 of 30 |
| DeSFAM-E (estimated) | 34 of 65 | 23 of 30 | 0.60 | 0.52 | 0.56 | 0.77 | 10 of 35 | 24 of 30 |
| Confine-E (estimated) | 0 of 65 | 5 of 30 | — | 0.00 | — | 0.17 | 0 of 35 | 0 of 30 |
| Signature check only | 5 of 65 | 0 of 30 | 1.00 | 0.08 | 0.14 | 0.00 | 5 of 35 | 0 of 30 |

- **The answer to Q3 is yes, on these tests.** For about Falco's cost on application requests (+9.9%
  against +8.2%), PROVBIND caught twice as many attack runs and raised no false alarm, where Falco raised
  10 in 30 benign runs. The price is memory (409 MB against 119 MB) and slower process starts.
- **The optimisation cost no accuracy.** PROVBIND's result is identical, scenario by scenario, to the run
  of 2 October with the original policies: the same ten scenarios caught, the same three missed. The three
  it misses are outside what PROVBIND checks, as documented: a kernel-exploit call pattern (rk-2), a read
  of the service-account token (ru-5), and a program added during the build (au-2).
- Falco, Confine-E and the signature check match 2 October exactly. DeSFAM-E differs slightly (34 caught
  and 23 false alarms, against 35 and 25), because its traces are recorded anew in each run.

### 4.3 Q2: the zero-day method

**There is no single standard for testing unknown ("zero-day") attacks, but there are recognised methods,
and ours adapts three of them:**

| Method | What it means | Where it is used | Ours |
|---|---|---|---|
| A. Normal-only training | The detector is built from benign behaviour only, so every attack is unseen by construction | ADFA-LD [1]; LID-DS [2] | PROVBIND's envelope is compiled from signed build metadata before any attack exists; ML-B is trained on benign traffic only |
| B. Leave-one-attack-out | A detector trained on attacks is tested on a family held out of training | ML intrusion-detection papers | Not applicable: PROVBIND is never trained on attacks |
| C. Adversary emulation | Documented attacker techniques re-created as small, harmless tests in a controlled testbed | Atomic Red Team, MITRE CALDERA [9, 10] | One harmless test per behaviour reported for real malicious packages |
| D. Container testbed with kernel-level recording | The victim runs in a container, reset between runs, with system calls recorded | LID-DS [2, 4] | The demo app in a Kubernetes pod, redeployed per run; Tetragon and bpftrace record; 5 repetitions |

The papers whose method we follow:

1. **ADFA-LD** (Creech and Hu, IEEE WCNC 2013) [1]: built to evaluate host intrusion detection "capable of
   reliably detecting zero-day attacks"; the detector is trained only on normal traces. The same group
   applied it to zero-day and stealth attacks on Windows (Haider et al., Future Internet 2016) [3].
2. **LID-DS** (Grimmer et al., 2019) [2]: each scenario is a victim container, a normal-traffic generator
   and an exploit container, recorded in timed windows, many times.
3. **LID-DS 2021** (Grimmer et al., CRITIS 2022) [4]: attacker, victim and user each in a container; 15
   scenarios re-create real vulnerabilities.

Newer work uses the same approach: Syairozi and Arizal (RITECH 2025) test Falco, Tetragon and Tracee live
in a Kubernetes cluster against emulated attacks, measuring detection rate, false-positive rate and CPU
and memory [5], the closest setup to ours; Kozachok et al. (2026) test a detector trained on normal
behaviour against vulnerabilities it never saw [6]. DeSFAM, one of our baselines, evaluates its detector
the same way [8].

What we adapted, and why:

| Element | LID-DS and ADFA-LD | Ours |
|---|---|---|
| Attacks | exploits of real server vulnerabilities | harmless re-creations of real malicious-package behaviours [7, 11], because PROVBIND targets software supply chains and real samples must never be run |
| Evaluation | offline, on a recorded dataset | live: PROVBIND and Falco run during the attacks; the estimated baselines use the recorded traces |
| Known and unknown | all attacks unseen | split into known and unknown, because supply-chain defences mostly work on known indicators |
| Leakage | by construction | checked explicitly on every run (below) |

**The checks that the attacks were unseen** (`eval/zero_day_check.py`, all seven pass on `run-final`):
PROVBIND's specification was compiled before the first scenario (Z1); no attack artefact appears in it
(Z2); ML-B's training windows all end before the first scenario and none overlaps an attack (Z3); the
ML-B model (Z4) and DeSFAM-E's benign baseline (Z5) were written before the first scenario; no advisory
exists for the unknown attacks (Z6); and Falco ran its default rules, with nothing written for our
scenarios (Z7).

**The weakness a reviewer will raise:** we wrote the attack scenarios ourselves, so they could fit what
PROVBIND checks. The checks above show the detectors never saw the attacks; they do not remove that bias.
We propose to map every scenario to MITRE ATT&CK and to add a few third-party Atomic Red Team tests for the
same techniques (Section 7).

### 4.4 Q1: the graphs

The supervisor asked, for figure 1, for the exact measured time of each system instead of estimates, and
for how many packages each time is based on. Before, Confine-E and DeSFAM-E were drawn as hatched "by
design" minimums. Now every system's preparation for a new image is measured on our VM:

| System | Time until a new image is protected | Made of | Counts |
|---|---|---|---|
| **PROVBIND** | **4.38 s** | compiling the envelope from signed build metadata (median of 5 cold compiles, 4.19–4.67 s) | 109 packages, 5,695 files |
| PROVBIND with ML-B | 7 h | 7 h of benign traffic, then 0.82 s of training | 4,544 requests, 232 windows |
| Falco | 0 s | no per-image step: generic rules | (a restart takes 25.7 s until ready) |
| Confine-E | 32.8 s | a 30 s start-up window, then 2.8 s of export and analysis | 31 executable files from 8 packages, plus 21 outside any package |
| DeSFAM-E | 30.5 min | profiling, then 1.2 s for the allow lists and training | 329 requests in 3 runs, 2,302 windows |

The figures that changed:

| Figure | What changed |
|---|---|
| 1, preparation time | every bar measured, labelled with its exact time and the package and file counts behind it |
| 1b, components (new) | each system's preparation split into its timed components, one panel per system |
| 3, attribution | "named / alerts" counts in every cell, not shares only |
| 5, scenarios × systems | one rule for every cell: right (attack caught or no false alarm), wrong, or no check at that stage, with a word and a mark in each cell and the runs judged right per system |
| 6, runtime cost (new) | PROVBIND and Falco against no monitoring on each application metric, with the 20% limit |
| 7, cost history (new) | PROVBIND's cost in each valid overhead run, in the order the policies were optimised |

All eight figures are drawn by one script from a data file in the repository, so anyone can draw them
without the VM (`docs/FIGURES-HOWTO.md`).

## 5. Limits

- One small demo app on one VM. Its requests take about 1 ms, so a small absolute cost shows as a large
  percentage.
- Five runs per scenario. No false alarm in 30 benign runs still allows a true rate up to about 10% at 95%
  confidence.
- The attacks are harmless re-creations of reported behaviours, not real malware, and we wrote them
  (Section 4.3).
- DeSFAM-E and Confine-E are our re-implementations of published designs, applied to recorded traces.
  Falco ran its default rules.
- The optimised policies report a repeated event once a minute. Tetragon treats two file events as the
  same when their paths have the same length and the same first 32 characters, so two such paths within a
  minute are reported once. Every attack in our set was still caught.
- Starting a new process stays costly (+119% in a tight loop), and PROVBIND uses 409 MB of memory against
  Falco's 119 MB.
- A sensor restarted while the workload runs stops reporting the workload's existing processes. Our
  testbed restarts the app after the sensor and checks that its events arrive before every measurement.

## 6. What is in the repository

Everything is on the team's main branch (Krittakorn-Saetia/Provbind):

| Where | What |
|---|---|
| `docs/ROLE1-SUPERVISOR-QUESTIONS-2026-10-05.md` | the full record: method, every run and its numbers, the correction, the references |
| `docs/PROVBIND-Capability-Test-Plan.md`, Section 10 | a proposed Results section with these numbers, and the citations to add to the paper |
| `docs/figures/data/final-2026-10-09/` | the final numbers as CSV files, and the data file the figures are drawn from |
| `docs/FIGURES-HOWTO.md` | how to draw the figures: one command, plus example code for your own charts |
| `node/tetragon/opt/` | the optimised sensor policies |
| `scripts/overhead-run.sh`, `scripts/comparison-run.sh`, `scripts/record-d2.sh`, `scripts/prep-run.sh`, `scripts/probe-events.sh` | the tests: runtime cost, comparison, ML-B training data, preparation times, the sensor probe |
| `eval/zero_day_check.py` | the leakage checks Z1–Z7 |

## 7. Next steps and open decisions

| Step | Status |
|---|---|
| Draw the final figures from the final run's data | in progress |
| Paper: add a Results section and the missing citations, including the reference behind the "[?]" in Section IV (SynthChain [12]) | proposed in the test plan, Section 10 |
| The evaluation plan promises a kernel ring-buffer drop rate under burst load, which we have not measured | to decide: measure it during attack-2's burst, or drop it from the plan |
| Map the scenarios to MITRE ATT&CK and add a few Atomic Red Team tests, to answer the designer-bias point | proposed |
| Read the full texts of [2], [5] and [6] before citing them; their summaries here come from abstracts and project pages | to do |

## References

1. G. Creech and J. Hu, "Generation of a new IDS test dataset: Time to retire the KDD collection," IEEE
   WCNC 2013, pp. 4487–4492. ADFA-LD: https://research.unsw.edu.au/projects/adfa-ids-datasets
2. M. Grimmer, M. M. Röhling, D. Kreußel, S. Ganz, "A Modern and Sophisticated Host Based Intrusion
   Detection Data Set," BSI IT-Sicherheitskongress, 2019.
   https://dbs.uni-leipzig.de/files/research/publications/2019-5/pdf/BSI-LID-DS.pdf
3. W. Haider, G. Creech, Y. Xie, J. Hu, "Windows Based Data Sets for Evaluation of Robustness of Host
   Based Intrusion Detection Systems (IDS) to Zero-Day and Stealth Attacks," Future Internet 8(3):29,
   2016. https://doi.org/10.3390/fi8030029
4. M. Grimmer, T. Kaelble, F. Nirsberger, E. Schulze, T. Rucks, J. Hoffmann, E. Rahm, "Dataset Report:
   LID-DS 2021," CRITIS 2022, LNCS 13723, Springer, 2023.
   https://link.springer.com/chapter/10.1007/978-3-031-35190-7_6
5. A. A. Syairozi and Arizal, "Comparative Analysis of eBPF-Based Runtime Security Monitoring Tools in
   Monitoring and Threat Detection on Kubernetes," RITECH 2025, SciTePress, pp. 136–141.
   https://www.scitepress.org/Papers/2025/142727/142727.pdf
6. A. V. Kozachok, S. G. Vyugov, S. G. Magomedov, "From CVE to CWE: Syscall-Based HIDS Generalisation,"
   arXiv:2606.22581, 2026. https://arxiv.org/abs/2606.22581
7. M. Ohm, H. Plate, A. Sykosch, M. Meier, "Backstabber's Knife Collection: A Review of Open Source
   Software Supply Chain Attacks," DIMVA 2020. https://arxiv.org/abs/2005.09535
8. DeSFAM, IEEE Access, 2025, doi:10.1109/ACCESS.2025.3592192.
   https://ieeexplore.ieee.org/document/11095719/
9. Red Canary, Atomic Red Team. https://github.com/redcanaryco/atomic-red-team
10. MITRE, CALDERA. https://github.com/mitre/caldera
11. Datadog, malicious-software-packages-dataset. https://github.com/DataDog/malicious-software-packages-dataset
12. Tan et al., "SynthChain: A synthetic benchmark and forensic analysis of advanced and stealthy software
    supply chain attacks," arXiv:2603.16694, 2026. https://arxiv.org/abs/2603.16694
