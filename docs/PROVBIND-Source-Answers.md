# PROVBIND: Answers from the Project Documents

Prepared 27 September 2026, for use by Claude Code. Every answer comes from a document listed at the end. "Not specified" means no document says it.

## How to read the sources

| Key | Document | What kind of source it is |
|---|---|---|
| **AJ** | Aj Ohm's draft (the advisor's rewrite of the paper) | **The paper.** Newest version; wins over DS2 and DS1 where they differ |
| **DS2** | Our revised DS2 paper draft, `main_DS2_revised.tex` | Older paper draft, superseded by AJ |
| **DS1** | DS1 Project Concept, `SF9-26-ProjectConcept.docx` | Earliest paper draft |
| **SH** | PROVBIND Sprint Handoff v1.0 | **Plan** for the 4-day prototype, written by Claude; not approved by Aj Ohm |
| **EX** | *PROVBIND: Project Explanation and Review of Aj Ohm's Draft* | **Review and proposals** written by Claude; not approved by Aj Ohm |
| R2 | Role 2 Handoff v0.1 and its kit | **Plan**, written by Claude. Not in your list; used only where marked |
| MH | `handoff-provbind-2026-09-26.md` | Internal project notes. Not in your list; used only where marked |

Equation, algorithm and step numbers refer to AJ unless another key is given. AJ sections are: I Introduction · II Related Work (A–C) · III Our Proposed PROVBIND System (A System Model, B Threat Model, C System Process: Phases 1–6) · IV Evaluation Plan.

---

## A. The paper

### 1. Target conference, deadline, page limit, format

- **Conference:** not specified.
- **Deadline:** not specified in the listed documents.
  - *MH §1 (not in your list):* the paper is course Deliverable Set 2 (DS2), "submitted before the onsite presentation", and the presentation window is **28 September – 2 October 2026**. DS1's deadline was 31 August.
- **Page limit:** not specified.
- **Format:** IEEE two-column conference format.
  - DS2 file header: "IEEE two-column conference format", and line 12: `\documentclass[conference]{IEEEtran}`.
  - AJ is a 12-page PDF, US Letter, in IEEE style (Index Terms, IEEE reference style). It does not name a venue.
  - *MH §1 (not in your list):* the format example was "an IEEE two-column conference paper, the SMARTX XSS paper".

### 2. Contributions and research questions

**Contributions, AJ §I (end of the Introduction), verbatim:**

> • **Provenance-to-runtime specification compilation.** PROVBIND carries verified supply-chain evidence beyond Kubernetes admission and compiles image, provenance, and SBOM information into an indexed runtime specification, while explicitly separating declaration-derived properties from inferred expectations.
>
> • **Continuous provenance-bound runtime verification.** An eBPF-assisted pipeline binds kernel-level runtime events to the admitted image and verifies them against its compiled specification, transforming a class of runtime detections from statistical anomaly identification into consistency verification against authenticated supply-chain evidence.
>
> • **Dependency-aware deviation attribution.** Detected deviations are associated with the corresponding component, dependency depth, image layer, and violated specification clause, supporting provenance-aware interpretation and root-cause analysis.
>
> • **Continuous post-admission trust re-evaluation.** An independent mechanism reassesses running workloads when the trust state of signing keys, builders, or declared components changes, extending supply-chain trust beyond the admission instant.

DS2 §I has an older three-item list (C1–C3), which AJ replaces.

**Research questions:** not specified. No document states research questions. The nearest things written down are:

- **Four challenges, AJ §I:**
  > First, provenance and runtime events have different semantics [...]. Second, signed declarations are behaviorally incomplete [...]. Third, verification must remain efficient at runtime [...]. Finally, artifact trust changes over time [...].
- **The central claim, AJ §IV** (also in DS1 "Evaluation" and DS2 §IV):
  > verification against a signed specification should eliminate the class of false alarms arising when a learned baseline encounters legitimate but infrequent behaviour.

### 3. Threat model

Source: AJ §III-B, "Threat Model". DS2 and DS1 have no threat-model section.

**Who the attacker is**, verbatim:

> PROVBIND considers software supply-chain adversaries that compromise software before or during container construction, as well as attacks that become observable only after deployment. An adversary may compromise a direct or transitive dependency, base-image component, source artifact, or other software incorporated into an otherwise legitimate container. Consequently, a malicious artifact may be correctly built, signed, represented in the SBOM and provenance, and successfully pass Kubernetes admission without violating the cryptographic validity of its supply-chain evidence.

**What the attacker does after deployment:**

> the adversary may attempt to execute undeclared or modified code, load unexpected executable content, modify image-declared files, exercise unexpected privileges or capabilities, or establish network communication inconsistent with the admitted runtime envelope. The adversary may also attempt to conceal malicious activity within apparently legitimate runtime behavior.

**Trust changes after admission:**

> An image that was legitimately admitted may subsequently become untrusted because, for example, its signing key or builder is revoked or a declared component is later identified as compromised.

**What the attacker controls:**

| Area | Answer | Source |
|---|---|---|
| Package registry | Not named in the threat model. AJ §I says an adversary may compromise "a dependency, build process, repository, or container image"; the kind of repository is not stated. | AJ §I, §III-B |
| Build | Yes, in the sense of compromising software "before or during container construction", which then gets legitimately signed. The signing and transparency mechanisms themselves are trusted (below). | AJ §III-B |
| Runtime | The attacker's code runs inside the workload. The node's monitoring stack is trusted, so the attacker does not control it. | AJ §III-B |

**Trusted components**, verbatim:

> The Kubernetes control plane, PROVBIND verification components, eBPF monitoring infrastructure, key-management service, and cryptographic primitives are assumed trusted. The underlying signing and transparency mechanisms are assumed to correctly authenticate and preserve their records.

**Out of scope**, verbatim:

> Denial-of-service attacks, compromise of these trusted components, and attacks that produce neither an observable runtime deviation nor a change in available supply-chain trust information are outside the scope of this work.

AJ also says: "PROVBIND does not assume that a valid signature, provenance attestation, or SBOM implies that the corresponding software is benign."

### 4. What the evaluation must show, and the metrics

**AJ §IV (Evaluation Plan):**

- **Detection:** "Detection quality is assessed against ground-truth labels with a supply chain violation as the positive class, reporting precision, recall, F1, false positive rate, and accuracy." The false-positive rate is reported next to the F-measure, not folded into it.
- **Cost:** "per-event verification latency, node-level CPU and memory overhead, kernel ring buffer drop rate under burst load, and compilation and indexing time per image."
- **Overhead baseline:** "Overhead is reported relative to existing runtime collection rather than to an unmonitored host."

**DS1 "Evaluation" adds:**

- metric formulas: Precision = TP/(TP+FP); Recall = TP/(TP+FN); F1 = 2PR/(P+R); FPR = FP/(FP+TN); Accuracy = (TP+TN)/(TP+TN+FP+FN);
- **stage coverage** per attack scenario;
- resident memory of the index structures;
- compile and index cost against the number of distinct image digests;
- cache hit rate at realistic replica counts;
- **ablations** of each envelope layer, of severity scoring and of residual screening;
- an **adversarial attack** that stays within the declared envelope, with the resulting miss reported.

**Capability inference (ML-A):** AJ §IV does not specify an evaluation of it, and no document gives metrics for it. EX §12 (proposal) adds an ablation of "ML-A against the curated allowlist".

**EX §12 (proposal, not the paper)** also adds:

- ablations of the origin term s_π, of strict versus split closure classes, and of the behavioural path;
- the benign-workload list in question 9;
- binding failures, trust-alert latency and duplicate suppression;
- cold-start window length.

### 5. Systems we compare against

- **AJ §IV:** "a rule-based runtime monitor, an independently trained learned-anomaly detector, and admission-time signature verification alone". None of them is named.
- **DS1 "Evaluation":** the same three, with the anomaly detector "trained on benign traces" and "instantiated separately from the residual screening component so that the system is not compared against one of its own parts".
- **EX §12 (proposal)** names them:
  1. **Falco** with its default rules;
  2. **ML-C**, an Isolation Forest trained on all events;
  3. admission-time signature verification alone.
- **SH §1.1 (plan):** in the demo, Falco watches the same actions.
- **Tetragon policies as a baseline:** not specified. Tetragon is PROVBIND's own event collector (DS2 Table I; SH §7), not a comparison system.
- Systems in AJ §II (Confine, Optimus, NodLink, ORTHRUS and others) are related work, not experimental baselines.

---

## B. Detection (Roles 3 and 4)

### 6. How the verifier decides that an event contradicts the envelope

**The paper (AJ Phase 4, Steps 1–3):**

- **Eq. (51), binding:** v_bind(e_t) = BindCheck(c, d_I). "An unknown or inconsistent binding is immediately reported as a binding failure and is never evaluated against another artifact's envelope."
- **Eq. (53), envelope check:** v_env(e_t) = Verify_τt(e_t, ℰ_I, 𝒥_τt) ∈ {0, 1}, where 0 means a direct contradiction.
- **Eq. (54), deviation classes:** 𝒟^det = {D_exec, D_load, D_write, D_cap, D_net, D_hash}. These are "undeclared execution, unexpected executable-code loading, protected-file modification, capability excess, network-egress inconsistency, and modified or relocated code, respectively."
- **Eq. (55), exec:** V_exec(f) = 1[f ∈ 𝒬_I] ∧ 1[H(f) = h_I(f)]. An exec is consistent only if the file is in the entrypoint closure *and* its hash matches.
- **Eq. (56), capability:** V_cap(c_p) = 1[c_p ∈ 𝒞_I].
- **Writes** have no equation. The rule is the text after Eq. (56): "Runtime-created mutable objects are not classified as contradictions solely because they are absent from ℱ_I, provided that they do not modify a protected image-declared object or violate another envelope clause."
- **Order when an event fits two classes:** not specified in AJ.

**Older draft, DS2 Algorithm 4 ("Binding Verification (per event)"):**

- **Exec, path declared (in I_path):**
  - hash differs → **ModifiedBinary**;
  - path not in Q → **UnexpectedProcess**;
  - otherwise → Conforming.
- **Exec, path not declared:**
  - hash is in I_hash → **RelocatedBinary**;
  - otherwise → **UndeclaredExec**.
- **Library load** with path not in Q → **UndeclaredLibrary**.
- **Write** to a path in I_path → **ImmutableWrite**; creating a new path is conforming.
- **Capability** not in K.caps → **CapabilityExcess**.
- **Connect** to a destination not in K.egress → **UndeclaredEgress**.
- Anything else → Conforming, passed on to residual screening.

**Demo plan, SH §7 (code) and §4.4 (class table):** exec and write only.

- **Binding:** no binding → `binding / unknown_container`; no envelope yet → buffer the event.
- **Exec:** a file in no layer → `D_hash / relocated` if its hash is declared, else `D_exec / undeclared`. A declared file with a different hash → `D_hash / modified`. A declared file not in the closure → `D_exec / outside_closure`.
- **Write:** to a declared file that is not under a mount → `D_write / declared_file`. New files are conforming.

**EX §7, Step 3 (proposal):** the same decision order, extended with the load, capability and network classes.

⚠ **The drafts conflict.** Under AJ Eq. (55), executing a declared file outside the closure is a full contradiction. DS2 (UnexpectedProcess, τ = 0.25), SH (`outside_closure`, capped at Low) and EX (§14, C2) treat it as weak evidence.

### 7. How an alert is scored, and the alert threshold

**The paper (AJ Phase 5, Step 2):**

- **Eq. (65):** S_det(D) = w_τ s_τ(τ_D) + w_π s_π(π(x_D)) + w_c s_c(𝒞_D).
- **Eq. (66):** s_π(AUTHENTICATED) > s_π(INFERRED).
- **Eq. (67):** S_beh(D) = w_A s̄_A(q, W) + w_c s_c(𝒞_D).
- **Eq. (68):** Ŝ(D) ∈ [0, 1], "used only for alert prioritization; it does not alter the detection decision made in Phase 4."
- AJ gives **no values** for the weights, s_τ, s_π or s_c, and has **no ρ function**. Dependency position enters only through s_c.

**Older draft (DS2 §III-D):**

- **Eq. (1):** S = w_t τ(t) + w_p ρ(δ) + w_c κ, with w_t + w_p + w_c = 1.
- **Eq. (2):** ρ(δ) = 1 if δ = ⊥ (no declared component), and δ/(1+δ) if δ ∈ ℕ. δ = 0 is the application itself.
- **Table II, τ:**

| Deviation | τ |
|---|---|
| Undeclared execution | 1.00 |
| Modified binary | 1.00 |
| Undeclared library load | 0.85 |
| Immutable write | 0.80 |
| Relocated binary | 0.70 |
| Capability excess | 0.60 |
| Undeclared egress | 0.55 |
| Unexpected process | 0.25 |

- **Table III:**
  - κ: privileged 1.00, network 0.70, filesystem 0.50, none 0.20;
  - buckets on 100·S: Critical ≥ 80, High 60–79, Medium 35–59, Low < 35.
- **Weights:** initially 0.4 / 0.4 / 0.2. Worked examples score 100 (Critical) and 61 (High).

**"Unowned files at 0.5": the demo rules, SH §8 (plan):**

- S = 0.4·s_type + 0.2·s_origin + 0.4·(0.5·rho + 0.5·kappa), and score = round(100·S).
- **rho:** 1.0 if the file is in no layer; **0.5 if the file is declared but owned by no package, or its depth is unknown**; depth/(1+depth) otherwise.
- **kappa:** privileged pod 1.0, root 0.5, non-root 0.2.
- **Caps and fixed scores:** `outside_closure` is capped at 34; binding failures score a fixed 60.
- **Expected scores:** 90 (exec of `/tmp/.x9`), 72 (write to `/etc/passwd`), 34 (exec of `/usr/bin/ls`).

**EX §8 (proposal):**

- **Weights and terms:** w_τ 0.4, w_π 0.2, w_c 0.4, with s_c = ½ρ + ½κ.
- **ρ:** 1 for ⊥, 0.5 for unresolved depth, δ/(1+δ) otherwise.
- **Origin:** s_π = 1.0 for AUTHENTICATED, 0.5 for INFERRED.
- **Behavioural score:** S_beh uses w_A 0.6 and w_c 0.4, capped at 59.
- **Worked examples:** 100 and 57.

EX gives 0.5 only to unresolved depth; SH extends it to declared files with no owner. *R2 §13 (not in your list)* lists as open whether files such as `/app/app.py` should be depth 0 instead.

**Threshold for raising an alert:** not specified as a number in any document.

- DS2 §III-D says an outside-closure exec is "deliberately placed below the threshold at which an alert would be raised on its own", but gives no value.
- AJ Eq. (68) uses the score only for prioritisation.
- In SH (§3.1, §8), every detection becomes an alert with a bucket.

### 8. Attack scenarios the paper must show

| Scenario | What it does | Install time or run time | Source |
|---|---|---|---|
| Reconstructed corpus scenarios | Attack semantics taken from a published corpus and rebuilt in an attested container testbed | Not specified | AJ §IV; DS1 "Evaluation"; DS2 §IV |
| In-envelope adversarial attack | An attack that "deliberately remains within the declared envelope"; the resulting miss is reported | Not specified | DS1 "Evaluation" (ref. [18], Goyal et al.); EX §12 |
| **Demo `attack-1`** | The app's `/update` endpoint calls `requestz_helper.check_update()`. It decodes a base64 payload stored in the package, writes it to `/tmp/.x9`, sets mode 755 and starts it in the background. The payload (static C binary `x9.c`) appends `provbind-test:x:0:0::/:/bin/false` to `/etc/passwd`, then sleeps 600 s. Expected: D_exec undeclared (90) plus D_write (72), in one chain. | **Run time.** The package is installed during the image build from a local wheel, but its payload runs only when `/update` is called after deployment. `attack.sh` waits for `envelope_ready`, then calls `/update`. Not at import. | SH §1.1, §5 |
| Relocated binary (stretch goal) | Copies `/usr/bin/ls` to `/tmp/.l` and runs it; needs runtime hashing | Run time | SH §11 |
| Phase 6 preview (stretch goal) | A local advisory file marks `requestz-helper` as malicious; a script withdraws trust and prints a trust alert. This is a trust change, not a runtime attack. | Not applicable | SH §11 |

- **Install-time attacks (during `docker build`):** no document defines one.
  - EX §4 states the limit: "A compromise made before or during the build is declared honestly in the SBOM and passes every check here. PROVBIND sees it only if it behaves differently at runtime."
  - AJ §III-B covers build-time compromise only through its later runtime effects.

### 9. Benign workloads for false positives

- **SH §5 (plan), `benign-1`:** three `curl` calls to `/`, then `kubectl exec -it -n demo deploy/demo-app -- sh -c 'ls /; cat /etc/hostname'`. SH §1.1 expects two Low observations for `sh` and `ls`.
- **EX §12 (proposal), full list:**
  - `pip install` at runtime;
  - `kubectl exec` sessions;
  - cron jobs;
  - JIT compilers writing to `/tmp`;
  - log rotation;
  - injected sidecars;
  - DNS lookups, which load glibc NSS modules;
  - writes to mounted volumes.
- **DS1 and DS2:** DS1 mentions an anomaly detector "trained on benign traces", and DS2 weights "fixed by ablation on benign workloads". Neither lists the workloads.
- **Number of images or packages:** not specified. The demo uses one image, `demo-app` (SH §1, §5).

### 10. Planned dataset of attacks

- **Name:** SynthChain. The citation prints as "[?]" in AJ §IV. DS2 §IV cites `synthchain2026`, and DS1 cites it as ref. [17].
- **Source:** "University of Glasgow, 'SynthChain: A synthetic benchmark and forensic analysis of advanced and stealthy software supply chain attacks,' arXiv preprint arXiv:2603.16694, 2026" (DS2 bibliography; the same in DS1 ref. [17]).
- **How it is used:**
  - The corpus "ship[s] without the signed provenance and SBOM documents this framework requires; the majority of their scenarios are additionally not containerised".
  - So the attack semantics are "extracted and re-instantiated within an attested container testbed" (AJ §IV; DS1 "Evaluation"; DS2 §IV).
- **Size:** not specified.
- **Access conditions:** not specified.
- **A dataset of malicious packages:** not specified.
- The dataset for training ML-A is covered in question 14.

---

## C. Linux capabilities and ML-A

### 11. What ML-A is

"ML-A" is the project's internal name, used in EX §10 (and in MH and R2). AJ calls it "a pre-trained LightGBM classifier [21]".

**Where it is defined:** AJ Phase 3, Step 3 ("Supplementary Runtime and Behavioral Context"), Eqs. (32)–(34), and Algorithm 1 ("Evidence-Aware Capability Inference").

**Inputs:**

- **Eq. (32):** z_I = Ω_I(𝒞^cfg_I, 𝒫*_I, 𝒬_I, C_I), where "Ω_I(·) extracts artifact and workload features from the container configuration, reachable packages, executable closure, and deployment context."
- **Algorithm 1 inputs:** verified state 𝒱_I, package closure 𝒫*_I, execution closure 𝒬_I, declared capabilities 𝒞^decl_I, the effective Kubernetes capability set 𝒞^K8s_I, the model LGBM_cap and a threshold θ_C.
  - Line 1 uses different arguments from Eq. (32): z_I ← Ω_I(𝒱_I, 𝒫*_I, 𝒬_I).

**Outputs:**

- **Eq. (33):** Ĉ_I = LGBM_cap(z_I), "candidate runtime capabilities".
- **Eq. (34):** 𝒞_I = Ĉ_I ∩ 𝒞^K8s_I; the prediction "cannot grant capabilities beyond those permitted by the effective Kubernetes security configuration."
- **Algorithm 1:** keeps predictions with p_I(c) ≥ θ_C, caps them at 𝒞^K8s, returns 𝒞_I = 𝒞^decl ∪ Ĉ^inf, and labels each capability AUTHENTICATED (declared) or INFERRED (predicted).

**Egress:** AJ's abstract says "a gradient-boosted model supplies capability and egress expectations", but Step 3 covers capabilities only. The egress set N̂_I appears in Eq. (35) and is never defined (EX §14, M8).

**Older drafts:**

- DS2 §III-B, item 4: "A LightGBM multi-label classifier [...] trained on statically extracted package features and observed capability usage, predicts the capability set each declared component requires. The result is intersected with the pod security context". That is per component, where AJ is per image.
- DS1 "Procedure": "The capability layer is supplied by a learned model, since no current attestation format expresses permission or egress requirements."

### 12. Who owns ML-A, and whether code or a model exists

- **Owner:**
  - EX §13 (proposal) puts ML-A in work stream 2, "Evidence and compiler: Phases 1–3, including ML-A", and says roles are "still unassigned".
  - SH §2 gives the envelope compiler to Role 2, but **SH §1.3 puts ML-A (LightGBM) out of scope** for the 4-day sprint.
  - *R2 header (not in your list):* "Owner: Korn" for Role 2.
- **Code or trained model:** none, according to every document.
  - EX §2: "No experiment has run yet."
  - SH §1.3: ML-A is out of scope.
  - *R2 T10 and the kit's `caps_allowlist.json` (not in your list):* a curated allowlist is used instead, marked "placeholders until ML-A exists", and "the demo never checks capabilities".

### 13. Capability labels and ground truth

- **Label set:** not specified as a complete list.
  - AJ says only "candidate runtime capabilities".
  - EX §6, Step 4 (proposal) gives examples, not a full list: `CAP_NET_BIND_SERVICE`, `CAP_CHOWN`, `CAP_SETUID`, `CAP_NET_RAW` and `CAP_SYS_ADMIN`, plus egress classes such as "outbound TCP 443" and "DNS".
  - DS2 Table III's classes (privileged, network, filesystem, none) are for scoring κ, not labels.
- **Ground truth:**
  - EX §6, Step 4 (proposal): "run a corpus of images in a sandbox cluster under Tetragon and record which capabilities they use and where they connect."
  - EX §10: "Images profiled in a sandbox (capabilities used, destinations contacted)."
  - DS2 §III-B: "observed capability usage".

### 14. Dataset and metrics for ML-A

- **Dataset:** not specified by name or size. The only description is "images profiled in a sandbox" (EX §6, Step 4; EX §10).
  - EX calls building this training set "the largest hidden task in the project".
  - *MH §4 (not in your list):* "a sandbox-profiled package corpus".
- **Baseline:** a curated allowlist, reported as an ablation (EX §6, Step 4; EX §12).
- **Metrics:** not specified in any document.

### 15. Capability origins: AUTHENTICATED, INFERRED, CONFIGURED

**AUTHENTICATED and INFERRED (AJ):**

- **Eq. (36):** π(x) ∈ {AUTHENTICATED, INFERRED}, "preventing model-derived expectations from being treated as authenticated supply-chain claims."
- **Algorithm 1, lines 7–13:** a capability in 𝒞^decl is AUTHENTICATED; one that is only predicted is INFERRED.
- **Phase 3 text:** "Predictions are bounded by the effective Kubernetes capability set and retain an INFERRED provenance label, while declaration-derived capabilities remain AUTHENTICATED."
- **Eq. (66):** s_π(AUTHENTICATED) > s_π(INFERRED).
- Detections carry π(x_D) (Eqs. 60, 76).

**Where "declared capabilities" come from:** not specified. EX §14, M9 flags this gap.

**CONFIGURED:** not in AJ, DS2 or DS1.

- EX §14, M9 (proposal): if declared capabilities come from the pod's securityContext, "that is operator configuration, not signed evidence [...] label pod-spec values CONFIGURED."
- *R2 kit (not in your list):* `contracts/envelope.schema.json` allows `CONFIGURED` as an origin value.
- SH §4.1: for now "every entry is `INFERRED`".

**Which origins the paper must evaluate:** not specified. EX §12 (proposal) suggests an ablation of the origin term s_π.

---

## D. Setup and constraints

### 16. The experiment machine

- **SH §10 (plan):**
  - native **Ubuntu 24.04**, not WSL or a VM;
  - **16 GB RAM minimum, 32 GB comfortable**;
  - **8 cores**, **100 GB free disk**;
  - internet access.
- **EX §11:**
  - Linux **kernel 5.8 or later** for CO-RE eBPF, marked VERIFY;
  - Python 3.11;
  - kind or minikube on a 16 GB laptop for development;
  - **one bare-metal Ubuntu machine** for the overhead numbers.
- **Exact kernel version:** not specified.
- **Tetragon version:** not specified.
- **Falco version:** not specified. SH §10 installs both with Helm without pinned versions and asks for the installed versions to be recorded later (`testbed/VERSIONS.md`, a blank template in the R2 kit).
- AJ gives no machine details.

### 17. Real malware, isolation, and institutional email

- **May we run real malware samples:** not specified.
  - SH §5 (plan) uses only a harmless test payload: "The payload must stay harmless and run only inside the throwaway demo container."
- **Isolation (VM, no network) for malware:** not specified. SH §10's "not WSL or a VM" is about eBPF support on the demo PC, not about malware isolation.
- **Institutional email:** yes. AJ's author block lists SIIT addresses for all four students and the advisor:
  - `6622771283@g.siit.tu.ac.th`
  - `6622770475@g.siit.tu.ac.th`
  - `6622770426@g.siit.tu.ac.th`
  - `6622780664@g.siit.tu.ac.th`
  - `somchart@siit.tu.ac.th` (advisor)
- **Which dataset requires an institutional email:** not specified in any document.

### 18. Results that already exist

**None.** No document reports a measured number, a results table or a results figure.

- AJ §IV and DS2 §IV are titled "Evaluation Plan", and DS1's "Evaluation" describes a plan.
- EX §2: "No experiment has run yet."
- SH plans the first results table for Day 4 of the sprint (§1.1 step 5; §5 Day 4).

Things that look like results but are not:

- AJ Fig. 1 (system model) and Fig. 2 (provenance graph model), and DS2's figures, are architecture diagrams.
- DS2's scores of 100 and 61 are worked examples, not measurements.
- EX §6's "roughly 15,000 files" for `python:3.11-slim` is labelled an approximate figure from the design log, not a measurement.

---

## Where the documents disagree

Resolve these before writing code that depends on them. AJ is the current paper.

| Topic | AJ (the paper) | Older drafts and plans |
|---|---|---|
| Exec outside the closure | Contradiction (Eq. 55) | Weak: DS2 UnexpectedProcess τ = 0.25; SH capped at Low |
| Score formula | Eqs. (65)–(68), no values, no ρ | DS2 ρ(δ) with weights 0.4/0.4/0.2; EX 0.4/0.2/0.4 with s_π; SH demo variant |
| Violation log | Hash chain (Eq. 79) | DS1 Merkle-anchored log; DS2 Merkle with KMS-signed roots and Rekor |
| ML-A granularity | One feature vector per image (Eq. 32) | DS2 per declared component |
| Contributions | Four (§I) | DS2 C1–C3 |
| Admission | The AEM itself admits or rejects (Eqs. 13, 19–20) | DS1: an existing admission controller, with PROVBIND retrieving evidence asynchronously |
| Behavioural path | Per process, with a model per image (Eqs. 57–59, Alg. 2) | DS2 one Isolation Forest on windows of conforming events |

---

## Documents used

| Key | Title | Date |
|---|---|---|
| AJ | *PROVBIND: Continuous Provenance-Bound Runtime Integrity Verification for Detecting Software Supply Chain Attacks in Cloud-Native Containers*, advisor-revised draft by Dr. Somchart Fugkeaw (`PROVBIND_AjOhmdraft.pdf`, 12 pages) | Undated; received 26 Sep 2026 |
| DS2 | *PROVBIND — Deliverable Set 2*, revised paper draft (`main_DS2_revised.tex`, identical to `main.tex`) | Undated in the file; project copy as of 26 Sep 2026 |
| DS1 | *PROVBIND: Continuous Provenance-Bound Runtime Integrity Verification for Detecting Software Supply Chain Attacks in Cloud-Native Containers — Project Concept* (`SF9-26-ProjectConcept.docx`) | August 2026 (title page) |
| SH | *PROVBIND Sprint Handoff: 4-Day Prototype*, version 1.0 | 26 Sep 2026 |
| EX | *PROVBIND: Project Explanation and Review of Aj Ohm's Draft* (Claude Doc, revision 16) | 26 Sep 2026 |
| R2 | *Role 2 Handoff: Evidence and Compiler*, draft v0.1, and its kit (`contracts/envelope.schema.json`, `compiler/caps_allowlist.json`). Not in your list | 26 Sep 2026 |
| MH | `handoff-provbind-2026-09-26.md`, internal project handoff. Not in your list | 26 Sep 2026 |

SH, EX and R2 were written by Claude as plans and proposals. They are not decisions by the team or by Aj Ohm.
