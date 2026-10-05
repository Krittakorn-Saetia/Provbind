# Supervisor's four questions (5 October 2026): Role 1's answers and the follow-up test

**From:** Role 1 · **For:** the supervisor, Korn and the team · **Status:** question 2 answered below.
Questions 1, 3 and 4 need one more run on the VM, `scripts/overhead-run.sh` (about 1.6 h). It is a new
measurement, not a repeat of the comparison, whose accuracy results stand. It measures runtime overhead
(Sections 3–4) and each system's preparation time with exact counts (Section 5, figure 1).

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

### 2.2b The papers whose method we follow, and what we changed

Our zero-day testing follows the method of two established host-intrusion-detection benchmarks:

1. **LID-DS** (M. Grimmer, M. M. Röhling, D. Kreußel, S. Ganz, "A Modern and Sophisticated Host Based
   Intrusion Detection Data Set," BSI IT-Sicherheitskongress 2019; the method paper is M. M. Röhling
   et al., "Standardized container virtualization approach for collecting host intrusion detection
   data," FedCSIS 2019, ACSIS vol. 18). Each scenario is a **victim container**, a **normal-behaviour
   generator**, and an **exploit container** that re-creates a known vulnerability, recorded with
   sysdig in timed windows (warm-up, then recording), with and without the exploit, many times [2, 7, 19].
2. **ADFA-LD** (G. Creech and J. Hu, "Generation of a new IDS test dataset: Time to retire the KDD
   collection," IEEE WCNC 2013). Built to evaluate host IDS "capable of reliably detecting zero-day
   attacks": the detector is trained **only on normal traces**, so every attack in the test set is
   unseen [1, 20]. The same authors' group extended this to Windows for "zero-day and stealth attacks"
   (Haider, Creech, Xie and Hu, Future Internet 2016) [21].

**Newer work (2022–2026) that uses the same method:**

3. **LID-DS 2021** (M. Grimmer, T. Kaelble, F. Nirsberger, E. Schulze, T. Rucks, J. Hoffmann, E. Rahm,
   "Dataset Report: LID-DS 2021," CRITIS 2022, Springer LNCS, 2023). The updated framework: every scenario
   has three roles, **Attacker, Victim and User, each a Docker container**; the user's benign timings are
   sampled from real web-server logs; 15 scenarios re-create real CVEs/CWEs [22].
4. **Syairozi and Arizal, "Comparative Analysis of eBPF-Based Runtime Security Monitoring Tools in
   Monitoring and Threat Detection on Kubernetes,"** RITECH 2025, pp. 136–141. Falco, Tetragon and Tracee
   run **live in a Kubernetes cluster** while emulated attacks (container escape, DoS, cryptomining, from
   the OWASP Kubernetes Top 10) are carried out; measured: detection rate, false-positive rate, mean time
   to detect, CPU and memory [23]. **This is the closest to ours**: the same live, Kubernetes, emulated-
   attack evaluation of runtime monitors, including Falco, with the same metrics (and the same cost
   measures as our overhead test).
5. **Kozachok, Vyugov and Magomedov, "From CVE to CWE: Syscall-Based HIDS Generalisation,"** arXiv
   2606.22581, 2026. A one-class detector **trained on normal behaviour only** is tested on **CVEs it never
   saw** (held-out LID-DS-2021 scenarios grouped by weakness class): the zero-day-by-construction
   protocol, applied in 2026 [24].
6. **DeSFAM** (IEEE Access 2025), one of our baselines, evaluates its detector the same way: attacks
   (privilege escalation, container escape) carried out against containers, the detector trained on
   benign behaviour [11].

| Element | LID-DS / ADFA-LD | Ours | Adapted? |
|---|---|---|---|
| Victim | the vulnerable app in a Docker container | the demo app in a Kubernetes pod (kind) | same idea, on Kubernetes |
| Normal behaviour | a normal-behaviour generator | `make loadgen` and 6 benign scenarios | same |
| Attacks | exploit container re-creating real CVEs | harmless re-creations of real malicious-package behaviours (Section 2.5b) | **adapted**: supply-chain behaviours instead of CVE exploits, and harmless by rule (Test Plan §12.4) |
| Zero-day by construction | detector trained on normal traces only | PROVBIND's envelope from signed build data, ML-B trained on benign D2 only; leakage checked (Z1–Z7) | same principle, plus an explicit leakage check |
| Recording | sysdig, timed windows | Tetragon (PROVBIND), Falco, bpftrace (for the estimated baselines), ground-truth windows | same, with live detectors |
| Repetitions | many recordings per scenario | 5 rounds per scenario | same |
| Evaluation | offline, on the recorded dataset | **live**, the detectors run during the attacks; estimated baselines on the recorded traces | **adapted**: live measurement for PROVBIND and Falco |
| Known vs unknown | — (all attacks unseen) | **added**: "known" = an advisory, signature or revoked key exists; "unknown" = nothing describes it | **added**, because supply-chain defences mostly work on known indicators |

So: **yes, others use this method, and we adapted it**: same structure (container victim, normal
generator, re-created attacks, timed recording, repetitions, normal-only detectors), applied to
supply-chain behaviours instead of CVE exploits, kept harmless, run live, and split into known and
unknown.

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

### 2.5 Is our zero-day set valid? The checks

Two things make a self-made "unknown" attack set valid: **the detectors never saw the attacks before the
test** (no leakage), and **each attack stands for something real**.

**(a) No leakage: checked on the run data** by `eval/zero_day_check.py`, which the overhead run executes
first (step 0c) and writes to `results/ZERODAY.md`:

| Check | What it proves |
|---|---|
| Z1 | PROVBIND's specification of the demo image was compiled before the first scenario ran |
| Z2 | no unknown attack's artefact is in the specification: `/tmp/.x9`, `/tmp/.cache`, `/tmp/.inj.so` in no image file; 203.0.113.9 outside the egress list; `helperd` (A-U2) owned by no package |
| Z3 | ML-B's training and validation windows all ended before the first scenario, and none overlaps an attack |
| Z4 | the ML-B model was written before the first scenario |
| Z5 | DeSFAM-E's benign baseline was recorded before the first scenario |
| Z6 | no advisory names anything but the known-trust test package (the unknown attacks have no advisory) |
| Z7 | Falco runs its default rules, with no custom rule written for our scenarios |

**(b) Each scenario stands for a real, publicly reported behaviour** (public incident write-ups only; no
sample was downloaded or run, Test Plan §12.4):

| Scenario | Real behaviour it stands for | Public report |
|---|---|---|
| attack-1 drop and run | compromised litellm 1.82.7/1.82.8 downloads `/tmp/pglog` and executes it; ua-parser-js 0.7.29 downloads and runs an executable from its preinstall script | [12], [13] |
| au-2 build-time program | ua-parser-js's preinstall script runs at install time (install-time execution, the second most common behaviour in the Datadog analysis) | [13] |
| ru-5 credential read | litellm reads `/var/run/secrets/kubernetes.io/serviceaccount/token`; mrmustard 0.7.4 collects SSH keys, AWS credentials and Kubernetes configuration | [14], [15] |
| ru-3 outbound connection | the same packages send what they collect to an attacker's server | [14], [15] |
| rk-3 library injection | termncolor/colorinal drop a shared object (`terminate.so`) and load it; LD_PRELOAD user-space rootkits such as HiddenWasp | [16], [17] |
| ru-4 binary replaced | ATT&CK T1554 Compromise Host Software Binary (a technique-level source: we found no package incident that replaces a system binary inside a container) | ATT&CK |
| attack-2 file burst | not from a sample: the test plan's in-envelope adversary (only ML-B can see it), T1486-like | — |
| ak-3, trust-2 revoked key | stolen code-signing keys: GitHub's certificates (2022, invalidated), Nvidia's (used to sign malware) | [18] |
| ak-1, trust-1 advisory | malicious-package advisories (OSV `MAL-` entries) for a dependency | [8] |
| rk-2 kernel-CVE shape | the call pattern of kernel CVEs such as Dirty Pipe (splice), as DeSFAM's paper uses | [11] |

**(c) What remains a limit.** The scenarios were written by us, not by an independent red team, and one
image is tested. The checks above show the detectors had no access to the attacks; they do not remove
designer bias. That is stated in the write-up, with the third-party test set (2.4) as the way to close it.

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
image, and ML-B's training data (7 h of benign load for our image, plus 1 h held out for checking;
Section 10 of the comparison write-up). Both are measured per system in Section 5, against Confine-E's
and DeSFAM-E's own preparation. ML-B's 7 h is far longer than DeSFAM-E's 30 min of profiling, so it is the
obvious candidate for optimisation (more requests per hour, or fewer windows); Section 4 will state it
with the numbers.

## 4. Results (overhead run, 5 October 2026, demo VM)

**Zero-day validity (Z1–Z7): all pass.** Specification compiled 2026-10-01 14:50Z, first scenario
2026-10-02 00:24Z; no attack artefact declared; 220 ML-B windows, none after the first scenario or
overlapping an attack; model and DeSFAM baseline written first; no advisory; Falco on default rules.

**Preparation time per new image (measured):** PROVBIND 5.34 s (median of 5 cold compiles; 109 packages,
5,695 files); PROVBIND + ML-B 7 h (4,532 requests, 220 windows; training 0.8 s); Falco 0 s (no per-image
step); Confine-E 30 s start-up window + 2.2 s (export 1.9 s, analysis 0.24 s; 27 ELF files from 8 packages,
+17 outside packages); DeSFAM-E 30.4 min (profiling; training 0.8 s; 320 requests, 2,297 windows).
Note: the redo run's start-up trace came out empty, so Confine-E's start-up step is counted as its 30 s
recording window, not the trace's span.

**Runtime overhead, against no monitoring (medians of 3 repetitions):**

| Metric | Falco | Tetragon only | PROVBIND |
|---|---|---|---|
| request latency p95, request mix | +13.1% | +8.1% | **+34.4%** |
| request latency p95, file-writing requests | +9.5% | +15.6% | **+44.8%** |
| throughput, request mix / file-writing | −11.8% / −10.3% | −5.8% / −13.8% | **−20.5% / −29.1%** |
| worst case: file write / process start | +1.4% / +9.4% | +43.5% / +159.5% | **+84.8% / +133.5%** |
| monitor CPU (% of one core) / memory | 12.7% / 98 MB | 15.8% / 204 MB | 14.4% / 428 MB |

In absolute terms the request mix's p95 went from 2.68 ms to 3.60 ms (+0.92 ms; Falco +0.35 ms).

**Q4, against 20%: PROVBIND is over.** Its worst application overhead is 44.8% (worst case 133.5%).
Falco stays under 20% on the application (13.7%). Against the paper's own baseline, the existing runtime
collection (Tetragon with the same policies), PROVBIND's userspace adds 17–25% to latency and 16–18% to
throughput: also just over.

**Where the time goes (from these numbers):**
- **The sensor's policies** carry much of it: Tetragon with PROVBIND's five policies alone already adds
  16% on file-writing requests, 44% per file write and 160% per process start. Process starts are
  expensive because the capability hook (`cap.yaml`) and the library-load hook (`load.yaml`) fire many
  times for every new process; every file write hits `write.yaml`.
- **PROVBIND's own userspace** adds the rest (17–25% over Tetragon alone). Its verification is cheap
  (OH-01: 1.9 µs per event at p50, 6.7 µs at p99), so the cost is the pipeline around it: Tetragon's JSON
  through `kubectl logs` into a Python process, ML-B's windows, the alert engine, on a VM whose CPU was
  already 69% busy with no monitor at all (82% with PROVBIND).

**Caveats.**
- The VM was close to saturation (69% busy before any monitor), so every monitor's CPU competes with the
  app directly; overheads on a node with idle cores would be lower. This must be stated.
- The test app's requests are tiny (1.7 ms), so a fixed per-event cost is a large percentage; for a real
  service with longer requests the same absolute cost (+0.9 ms) is a smaller share.
- Three repetitions; the report now also gives the min–max spread.

**Q3, the trade-off.** For 0 false positives instead of Falco's 10 (of 30 benign runs), and 50 detections
instead of 25 (of 65 attacks), PROVBIND costs about +0.6 ms more per request than Falco at p95 (+21
percentage points) and 4x Falco's memory. Whether that is worth it depends on the supervisor's 20% rule,
which PROVBIND does not yet meet, so the answer is: **the accuracy gain is large, but the cost has to come
down before the trade-off can be claimed.**

**Optimised variant (built 5 October, to be measured):** `node/tetragon/opt/` (rate-limited write, cap and
load hooks; no return probe on write and load), `EVENT_SOURCE=file` (read Tetragon's export file in the
kind node instead of `kubectl logs`), orjson in the node, and ML-B optional (`NODE_MLB=0`). Measured with
`POLICY_SET=opt EVENT_SOURCE=file scripts/overhead-run.sh`; detection re-checked with the same settings in
`scripts/comparison-run.sh` before any claim.

**Next: find and cut the cost** (`scripts/overhead-ablation.sh`, about 1.5 h): each policy alone against no
monitoring, and PROVBIND without ML-B. Then optimise what it points at. The likely candidates:
1. **Narrow the hooks in the kernel:** filter `write.yaml` to the paths that matter, and `cap.yaml` to the
   capabilities the envelope tracks, instead of sending every event to userspace (Tetragon `matchArgs`).
2. **A cheaper event path:** read Tetragon's gRPC or export file directly instead of `kubectl logs`, and
   parse with a faster JSON library, or batch.
3. **ML-B only when needed:** it only adds D_beh (attack-2); measure its share and offer it as an option.

## 5. Question 1: the graphs

The supervisor's comment on figure 1 (`fig1_c1_specification`, "time until a new image is protected"):
**he wants the exact measured time for each system, not estimates, and exactly how many operations each
time is based on.** Before, Confine-E and DeSFAM-E were drawn as hatched "by design" minimums (30 s, 30 min).

What changed:
- `eval/prep_time.py` measures each system's preparation on our VM, and `scripts/overhead-run.sh` runs it
  (step 0b):

  | System | Measured as | Count shown |
  |---|---|---|
  | PROVBIND | `compiler.compile` on the image, cold, 5 times | compiles, files per image |
  | PROVBIND + ML-B | D2 benign load (from the record-d2 log) + model training, timed | requests, windows |
  | Falco | no per-image step; DaemonSet ready time after each restart | restarts |
  | Confine-E | start-up trace span + exporting the binaries + static analysis, timed | ELF files |
  | DeSFAM-E | baseline profiling span + allow list + Isolation Forest training, timed | requests, windows |

- Figure 1 (`eval/baselines/plot_contributions.py`) reads `results/PREP.json` when it exists:
  - (a) every bar is measured, labelled with its exact time (e.g. "1,812 s (30.2 min)"), with the exact
    number of packages and files analysed (PROVBIND: packages in the SBOM; Confine-E and DeSFAM-E: the
    packages owning the ELF files they analysed, found with `dpkg -S` in the container) and the
    repetitions or requests behind it;
  - (b) a component breakdown for **every** system, not only PROVBIND, one small panel each on its own
    scale: PROVBIND's compile steps, PROVBIND + ML-B (benign load, training), Confine-E (start-up
    recording, binary export, reading ELF imports, mapping to system calls), DeSFAM-E (profiling, static
    and dynamic allow list, Eq. 1, Isolation Forest training), and Falco (no per-image component; its
    DaemonSet restart time).
  Without the file the figure falls back to the old drawing.

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
12. Datadog Security Labs, "LiteLLM and Telnyx compromised on PyPI: tracing the TeamPCP supply chain campaign." https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/
13. Rapid7, "NPM library (ua-parser-js) hijacked: what you need to know," 2021. https://www.rapid7.com/blog/post/2021/10/25/npm-library-ua-parser-js-hijacked-what-you-need-to-know/
14. SafeDep, "Malicious litellm 1.82.8: credential theft and persistent backdoor." https://safedep.io/malicious-litellm-1-82-8-analysis/
15. StepSecurity, "Compromised PyPI package: mrmustard 0.7.4 steals SSH, cloud, and Kubernetes credentials." https://www.stepsecurity.io/blog/compromised-pypi-mrmustard-0-7-4-credential-stealer
16. The Hacker News, "Malicious PyPI and npm packages discovered exploiting dependencies in supply chain attacks," 2025. https://thehackernews.com/2025/08/malicious-pypi-and-npm-packages.html
17. Sandfly Security, "Detecting and de-cloaking HiddenWasp Linux stealth malware." https://sandflysecurity.com/blog/detecting-and-de-cloaking-hiddenwasp-linux-stealth-malware
19. LID-DS, Recording Framework documentation (victim container, normal-behaviour generator, exploit container, sysdig, warm-up and recording windows). https://github.com/LID-DS/LID-DS/wiki/LID-DS-Recording-Framework:-Documentation-and-Installation
20. G. Creech and J. Hu, "Generation of a new IDS test dataset: Time to retire the KDD collection," IEEE WCNC 2013, pp. 4487–4492. https://dblp.org/rec/conf/wcnc/CreechH13.html
21. W. Haider, G. Creech, Y. Xie, J. Hu, "Windows Based Data Sets for Evaluation of Robustness of Host Based Intrusion Detection Systems (IDS) to Zero-Day and Stealth Attacks," Future Internet 8(3):29, 2016. https://doi.org/10.3390/fi8030029
22. M. Grimmer, T. Kaelble, F. Nirsberger, E. Schulze, T. Rucks, J. Hoffmann, E. Rahm, "Dataset Report: LID-DS 2021," CRITIS 2022, LNCS vol. 13723, Springer, 2023. https://link.springer.com/chapter/10.1007/978-3-031-35190-7_6
23. A. A. Syairozi, Arizal, "Comparative Analysis of eBPF-Based Runtime Security Monitoring Tools in Monitoring and Threat Detection on Kubernetes," RITECH 2025, SciTePress, pp. 136–141. https://www.scitepress.org/Papers/2025/142727/142727.pdf
24. A. V. Kozachok, S. G. Vyugov, S. G. Magomedov, "From CVE to CWE: Syscall-Based HIDS Generalisation," arXiv:2606.22581, 2026. https://arxiv.org/abs/2606.22581
18. DigiCert, "What went wrong with GitHub stolen code signing keys." https://www.digicert.com/blog/github-stolen-code-signing-keys-and-how-to-prevent-it
