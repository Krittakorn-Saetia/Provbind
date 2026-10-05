# Supervisor's four questions (5 October 2026): Role 1's answers and the follow-up test

**From:** Role 1 · **For:** the supervisor, Korn and the team · **Status:** question 2 answered below;
questions 3 and 4 need the overhead test (`scripts/overhead-run.sh`, Section 3), whose numbers go into
Section 4 when it has run; question 1 (the graphs) is being reworked with the figures he saw.

| # | Question | Where |
|---|---|---|
| 1 | Make the graphs make more sense and easier to read | Section 5 |
| 2 | Is our zero-day method a recognised standard; if not, did we adapt from one? | Section 2 |
| 3 | Is the runtime cost worth the accuracy gained by eliminating false positives? | Sections 3 and 4 |
| 4 | Is the time PROVBIND spends to avoid mistakes under 20% of other work; if not, optimise | Sections 3 and 4 |

---

## 1. Short answers

- **Q2.** There is no single standard for "zero-day" evaluation, but there are three recognised methods, and
  ours combines two of them; one more step (Section 2.4) makes it fully traceable to a public standard.
- **Q3 and Q4.** We had measured accuracy, not runtime cost, so these could not be answered from the
  existing runs. The overhead test measures PROVBIND's cost against no monitoring and against Falco, on
  the same VM, pod and image, and reports it against the 20% limit.

## 2. Question 2: how "unknown" (zero-day) attacks are evaluated, and where our method stands

### 2.1 The recognised methods

| Method | What it means | Where it is used |
|---|---|---|
| **A. Normal-only training (anomaly detection)** | The detector is built from benign behaviour only; every attack is unseen by construction | ADFA-LD, designed for HIDS that detect zero-day attacks, uses no attack traces in training [1]; LID-DS [2] |
| **B. Leave-one-attack-out (LOAO)** | An ML detector trained on attacks is tested on an attack family held out of training | standard in ML intrusion-detection papers [3, 4] |
| **C. Adversary emulation of techniques** | Attacks are re-created as small, harmless tests of documented techniques (MITRE ATT&CK) and run in a controlled testbed | Atomic Red Team (1,225 tests for 261 ATT&CK techniques), MITRE CALDERA [5, 6] |
| **D. Container testbed with kernel-level recording** | The victim runs in a container, reset between runs; each scenario re-creates a real vulnerability; system calls are recorded | LID-DS, 15 CVE/CWE-based scenarios [2, 7] |

For software supply chains in particular, attack behaviour is usually categorised from real malicious
packages: Backstabber's Knife Collection (174 packages, two attack trees for how code is injected and
when it runs) [8]; we used the Datadog malicious-packages dataset the same way.

### 2.2 What we did, method by method

| Part of our design | Matches |
|---|---|
| PROVBIND's envelope is compiled from signed build metadata before any attack exists; ML-B is trained on benign traffic only (D2). Every runtime attack is unseen by the detector | **A** |
| 19 scenarios re-create behaviours reported for real malicious packages (Datadog dataset), harmlessly, one test per behaviour | **C** (with our own tests in place of Atomic Red Team's) |
| The demo app runs in a container, redeployed per run; Tetragon/bpftrace record kernel events; 5 repetitions | **D** |
| "Unknown" = a behaviour no signature, advisory or allow list available to any compared system describes | the usual definition of a novel attack |
| LOAO | **not applicable**: PROVBIND is not trained on attacks, so there is no attack family to hold out |

**So: we adapted recognised methods (A, C, D) rather than invented one.** What is ours: the scenarios
themselves.

### 2.3 Weaknesses a reviewer will raise
1. **We wrote the attacks ourselves** (designer bias): our tests could fit what PROVBIND checks.
2. **They are not mapped to a public taxonomy**, so a reader cannot check coverage.
3. **Few unknown types** (6 runtime/admission behaviours).

### 2.4 How to close them (proposed)
1. **Map every scenario to MITRE ATT&CK** (below; to be confirmed against attack.mitre.org).
2. **Add a third-party set**: a handful of Atomic Red Team Linux tests for the same techniques, run inside
   the demo container. These tests are harmless by design and written by someone else, which answers the
   designer-bias point. It can join the re-test (Section 3) without rebuilding the image.

| Scenario | Behaviour | ATT&CK technique (to confirm) |
|---|---|---|
| attack-1 | drop a binary in /tmp and run it; write /etc/passwd | T1105 Ingress Tool Transfer; T1136.001 Create Account: Local |
| attack-2 | burst of file writes inside the envelope | T1486-like (impact by mass file writes) |
| rk-2 | system-call shape of a kernel CVE (no exploit) | T1068 Exploitation for Privilege Escalation |
| rk-3 | LD_PRELOAD of an injected library | T1574.006 Dynamic Linker Hijacking |
| ru-3 | outbound connection to an undeclared address | T1041 Exfiltration Over C2 Channel |
| ru-4 | replace a declared binary | T1554 Compromise Host Software Binary |
| ru-5 | read the service-account token | T1552.001 Unsecured Credentials: Credentials In Files |
| au-2 | build step adds an undeclared program | T1195.002 Compromise Software Supply Chain |
| ak-1, trust-1 | known-malicious dependency (advisory) | T1195.001 / T1195.002 Supply Chain Compromise |
| ak-2 | unsigned image | T1525 Implant Internal Image |
| ak-3, trust-2 | signing key revoked (stolen-key case) | T1553.002 Subvert Trust Controls: Code Signing |

## 3. Questions 3 and 4: the overhead test

**What was missing.** The comparison measured accuracy only. Korn's figure script has panels for
PROVBIND's own cost (OH-01 per-event latency, OH-04 compile time), but the redo ran before those steps
were merged, so they were never produced, and nothing measured cost *against* Falco or no monitoring.

**The test** (`scripts/overhead-run.sh`, about 1.5 h, unattended): the same VM, demo image and pod, four
configurations in shuffled order, three repetitions:

| Configuration | What runs |
|---|---|
| `none` | no runtime monitor (Tetragon and Falco stopped) |
| `falco` | Falco with its default rules |
| `tetragon` | Tetragon with PROVBIND's five policies only (the sensor's share of PROVBIND's cost) |
| `provbind` | all of PROVBIND: Tetragon + policies, controller, node with ML-B and the egress list, alerts, trust loop |

Workloads in each: the load generator's request mix and a file-writing-only mix, both from a client
inside the cluster (no port-forward in the path), and a worst-case micro-benchmark (20,000 file writes
and 500 process starts in the container, every one a hooked event; the same style as Falco's own driver
benchmark [9]). Measured: request latency p50/p95, throughput, time per file write and per process start,
CPU and memory of every monitor. Before that, PROVBIND's internal costs come from the comparison run's
own files: OH-01 (per-event verification latency), OH-04 and OH-05 (compile time, index memory).

**How the 20% is judged (both readings, so the supervisor can pick):**
- **(a) against no monitoring**: PROVBIND's added latency or lost throughput is at most 20% of the
  unmonitored baseline;
- **(b) against other work**: PROVBIND's overhead minus Falco's overhead, and PROVBIND's monitor CPU as a
  ratio of Falco's.
If PROVBIND exceeds 20% on either, Section 4 says where the time goes (sensor vs PROVBIND's own
userspace, from the `tetragon` configuration) and what to optimise.

**For reference, published figures:** Tetragon's process-execution tracking adds 1.68% in a worst-case
kernel build benchmark (2.46% when also writing every event to disk) [10]; DeSFAM reports under 1%
overhead and sub-millisecond enforcement [11]; Falco publishes per-system-call latency with and
without its drivers [9]. Our test measures Falco directly; Confine-E and DeSFAM-E are estimates and are not
run live, so their cost is taken from their papers.

**Q3, the trade-off, is then read from one table:** each system's TP, FP, F1 and false-positive rate (from
the comparison run) beside its measured overhead. Falco raised 10 false positives in 30 benign runs; PROVBIND
0. The question is whether PROVBIND's extra cost, if any, buys those 10.

**Also part of "time spent to avoid mistakes"** (one-off setup, not runtime): compiling an envelope per
image (OH-04), and ML-B's training data, which took 9 h of benign load per image on our VM (Section 10 of
the comparison write-up). The latter is the obvious candidate for optimisation, and Section 4 will state it.

## 4. Results

*To be filled in from `run-overhead/results/OVERHEAD.md` after the run.*

## 5. Question 1: the graphs

*Being reworked once we have the figures the supervisor saw and his comments.*

## References

1. UNSW, ADFA IDS Datasets. https://research.unsw.edu.au/projects/adfa-ids-datasets
2. LID-DS, Leipzig Intrusion Detection Data Set. https://github.com/LID-DS/LID-DS
3. "Evaluating ML-based Intrusion Detection Systems: The Illusion of Model Efficacy," arXiv 2609.02469. https://arxiv.org/html/2609.02469v1
4. "From Zero-Shot Machine Learning to Zero-Day Attack Detection," arXiv 2109.14868. https://arxiv.org/abs/2109.14868
5. Red Canary, Atomic Red Team (via Datto, "Using Atomic Red Team for adversary attack emulation"). https://www.datto.com/blog/atomic-red-team-part-2-using-atomic-red-team-for-adversary-attack-emulation/
6. Picus Security, "A data-driven comparison of open source adversary emulation tools." https://www.picussecurity.com/resource/blog/data-driven-comparison-between-open-source-adversary-emulation-tools
7. M. Grimmer et al., "A Modern and Sophisticated Host Based Intrusion Detection Data Set" (LID-DS). https://dbs.uni-leipzig.de/files/research/publications/2019-5/pdf/BSI-LID-DS.pdf
8. M. Ohm, H. Plate, A. Sykosch, M. Meier, "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks," DIMVA 2020. https://arxiv.org/abs/2005.09535
9. Falco, "Falco eBPF & Kernel Module Performance." https://github.com/falcosecurity/libs/files/8334709/Falco.eBPF.Kernel.Module.Performance.pdf
10. InfoQ, "eBPF Kubernetes Security Tool Tetragon Improves Performance and Stability," 2023. https://www.infoq.com/news/2023/11/kubernetes-ebpf-tetragon/
11. DeSFAM, IEEE Access 2025, doi:10.1109/ACCESS.2025.3592192. https://ieeexplore.ieee.org/document/11095719/
