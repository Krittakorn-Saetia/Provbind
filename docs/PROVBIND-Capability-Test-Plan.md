# PROVBIND Capability Test Plan

**Version 1.2 · 9 October 2026 · Reference: Aj Ohm's draft (`PROVBIND_AjOhmdraft.pdf`)**

Aj Ohm gave us his draft and asked us to **understand, check and update** it. This plan is the "check" step: every capability the draft claims gets at least one test, and every result either confirms the draft or produces a specific update to it (Section 10).

"Understand" is covered by *PROVBIND: Project Explanation and Review of Aj Ohm's Draft*. "Update" happens once results exist and we have his `.tex` source.

Equation, algorithm, phase and step numbers refer to Aj Ohm's draft. Fail-point IDs (C1–C5, M1–M17) refer to Section 14 of the explanation doc. Every dataset the tests use, and the rules for handling real malicious samples, are in Section 12.

---

## 0. Three rules

**1. Test the draft as written.** Where the review found a problem, run the draft's version *and* the proposed fix side by side, and let the numbers decide the update. Examples:

- Eq. (55)'s strict exec rule against the split classes;
- the Cuckoo filter on and off;
- a per-image ML-B model against a global one;
- the hash chain with and without signed checkpoints.

**2. Every test leaves evidence.** A test writes `run/results/<ID>.json` in the format of Section 2. `python -m eval.report` turns all results into the table we show Aj Ohm. A test without a result file counts as "not run".

**3. Three priorities.**

| Priority | Meaning | Deadline |
|---|---|---|
| **P0** | A working demonstration of each capability | Before the presentation; freeze at Day 3 noon (Sprint Handoff §9) |
| **P1** | Negative cases, edge cases, A/B comparisons | As time allows, Day 3–4 |
| **P2** | Quantitative evaluation for the paper | After the presentation |

On slides, say which priority each result comes from.

**This plan widens the sprint's scope.** ML-A, ML-B, the Cuckoo filter, all five event hooks and the trust loop are now tested, and Sprint Handoff v1.1 records that change.

---

## 1. Capability inventory

Every capability in the draft, where it is defined, and the tests that check it. Role keys: **R1** Testbed and evaluation · **R2** Evidence and compiler · **R3** Node runtime · **R4** Alerts and integration.

| # | Capability | Draft reference | Tests | Owner |
|---|---|---|---|---|
| 1 | Build, SBOM, provenance, signing, transparency | Phase 1, Eqs. (1)–(6) | PH1-01 to 04 | R2 |
| 2 | Evidence authentication | Phase 2, Eqs. (10)–(13) | PH2-01 to 05 | R4 |
| 3 | Cross-evidence binding | Eqs. (14)–(18) | PH2-06, 07 | R2 |
| 4 | Admission decision, verified state, cold start | Eqs. (19)–(23) | PH2-08 to 10 | R4, R3 |
| 5 | File and layer derivation | Phase 3 Step 1, Eqs. (24)–(26) | PH3-01 to 03 | R2 |
| 6 | Package graph, depth, ownership | Step 2, Eqs. (27)–(30) | PH3-04 to 06 | R2 |
| 7 | Execution closure | Eq. (31) | PH3-07 | R2 |
| 8 | **Capability inference (ML-A)** | Step 3, Eqs. (32)–(34), Algorithm 1 | MLA-01 to 08 | R2 (data: R1, R3) |
| 9 | Envelope, origin labels, indices | Step 4, Eqs. (35)–(37) | PH3-08, 09 | R2 |
| 10 | Provenance graph and store | Step 5, Eqs. (38)–(49) | PH3-10 to 12 | R4, R2 |
| 11 | Event collection and binding | Phase 4 Step 1, Eqs. (50)–(51) | PH4-01 to 03 | R3 |
| 12 | Cache and **Cuckoo filter** | Step 2, Eq. (52) | PH4-04, CF-01 to 06 | R3, R1 |
| 13 | Deterministic verification, six classes | Step 3, Eqs. (53)–(56) | PH4-05 to 18 | R3 |
| 14 | **Behavioural path (ML-B)** | Step 4, Eqs. (57)–(59), Algorithm 2 | MLB-01 to 07 | R3 |
| 15 | Scoring | Phase 5 Step 2, Eqs. (65)–(68) | PH5-01 to 05 | R4 |
| 16 | Attribution | Step 3, Eqs. (69)–(74) | PH5-06 to 08 | R4 |
| 17 | Alert record | Step 4, Eqs. (75)–(78) | PH5-09 | R4 |
| 18 | Hash-chained log, chains | Step 5, Eqs. (79)–(80) | PH5-10 to 13 | R4 |
| 19 | Trust re-evaluation | Phase 6, Eqs. (81)–(96) | PH6-01 to 09 | R4 |
| 20 | Detection against baselines | §IV | E2E-01 to 12, EV-01 to 07 | R1 |
| 21 | Cost | §IV | OH-01 to 06 | R3, R2 |

---

## 2. How tests run and record results

**Layout.**

- `tests/capability/`: pytest files, one per test ID or small group (for example `test_cf_02_fp_rate.py`). Tests that need Docker or the cluster are marked `integration`.
- `tests/capability/registry.json`: every test ID with its owner, priority and draft reference. It is generated from this plan and ships in the test kit.
- `ml/`: ML-A and ML-B data, training and evaluation code.
- `eval/report.py`: builds the results table. It ships in the test kit.

**Result record.** One file per test at `run/results/<ID>.json`, matching `tests/capability/result.schema.json`:

```json
{
  "id": "CF-02",
  "status": "pass",
  "priority": "P1",
  "owner": "R3",
  "draft_ref": "Phase 4, Step 2, Eq. (52)",
  "fail_point": "M15",
  "finished": "2026-09-29T14:03:00Z",
  "metrics": { "fp_rate_16bit": 0.000065, "theory_16bit": 0.000122 },
  "artifacts": ["run/results/CF-02/queries.csv"],
  "notes": "Reference filter, 400,000 non-member queries"
}
```

- `status` is one of `pass`, `fail`, `blocked` or `not_run`.
- A `blocked` result must say why in `notes`.
- A `fail` is a valid, useful result: it becomes an update item in Section 10.

**Commands.**

| Command | Does |
|---|---|
| `pytest -q tests/capability -m "not integration"` | Unit-level capability tests, runnable anywhere |
| `pytest -q tests/capability -m integration` | Tests that need the cluster, Tetragon or the registry |
| `python -m eval.report --run $PROVBIND_RUN` | Writes `run/results/REPORT.md`: one row per registry entry, missing results shown as `not_run` |

---

## 3. Tests by phase

All tables share one format, and `registry.json` is generated from them.

### 3.1 Phase 1: Build and supply-chain evidence

| ID | Checks | How | Pass criterion | Owner | P |
|---|---|---|---|---|---|
| PH1-01 | Image, SBOM and provenance are signed and bound to d_I (Eqs. 1–6) | Run `build-and-attest.sh` on the stand-in and demo images | `cosign verify` and both `verify-attestation` calls pass; every statement subject equals d_I | R2 | P0 |
| PH1-02 | Each evidence object is signed, not only d_I (fail point C1) | Attach an extra SBOM attestation signed with a second key | Verification with our key does not accept it; if no valid SBOM remains, the compiler exits 2 | R2 | P1 |
| PH1-03 | A transparency record τ_I exists (Eqs. 5–6) | Read the Rekor log index from `cosign verify` output | Index present, or `blocked` if offline | R2 | P1 |
| PH1-04 | The SBOM has dependency edges | Count `dependencies` in the SBOM | Count above 0; `unresolved_fraction` recorded | R2 | P0 |

### 3.2 Phase 2: Admission and evidence verification

| ID | Checks | How | Pass criterion | Owner | P |
|---|---|---|---|---|---|
| PH2-01 | A signed image is admitted and bound (Eqs. 10–13, 19) | Deploy the demo image by digest | Its binding shows `verified: true` | R4 | P0 |
| PH2-02 | An unsigned image fails v_sig (Eq. 10) | Deploy an unsigned image in namespace `demo` | Binding failure reported | R4 | P1 |
| PH2-03 | A signature from the wrong key fails v_sig | Sign an image with a second key and deploy it | Binding failure reported | R4 | P1 |
| PH2-04 | A broken transparency record fails v_trans (Eq. 11) | Corrupt a copy of the stored Rekor bundle | Verification fails | R4 | P1 |
| PH2-05 | A revoked key fails v_trust (Eq. 12) | Mark our key revoked in `run/keystatus.json`, a stand-in for KMS key state | Check fails with reason `key` | R4 | P1 |
| PH2-06 | v_M catches a changed manifest (Eq. 15) | Unit test with altered manifest bytes | Mismatch raised | R2 | P1 |
| PH2-07 | v_B and v_P catch evidence bound to another image (Eqs. 17–18) | Unit test with a statement whose subject is not d_I | `EvidenceError`; compiler exits 2 | R2 | P1 |
| PH2-08 | A moved tag cannot redirect evidence (Eq. 7) | Push a new image to the same tag while a pod runs | The running pod keeps its own digest and evidence | R4 | P1 |
| PH2-09 | The verification context Γ_I is stored (Eq. 22) | Inspect the stored context | Key, signatures, Rekor entry and t0 present | R4 | P0 |
| PH2-10 | Cold-start window between admission and envelope (C4) | Time pod admission to `envelope_ready`; count buffered events | Window reported in seconds; zero events lost | R3 | P1 |

### 3.3 Phase 3: Envelope compilation

| ID | Checks | How | Pass criterion | Owner | P |
|---|---|---|---|---|---|
| PH3-01 | Two-pass whiteout union (Eqs. 24–26) | Role 2 kit, T5 unit tests | All pass | R2 | P0 |
| PH3-02 | Real-path keys on merged `/usr` images | Role 2 kit, T6 tests | All pass | R2 | P0 |
| PH3-03 | Layer attribution Λ_I (Eq. 26) | Compare `layer` for 5 known files with a manual layer inspection | All 5 match | R2 | P1 |
| PH3-04 | Dependency depth δ (Eq. 29) | Role 2 kit T8 tests; stand-in image | `requests` depth 1, `urllib3` depth 2 | R2 | P0 |
| PH3-05 | Packages without edges are marked unresolved, never ⊥ (M16) | Report `unresolved_fraction`; inspect null depths | Every package without edges has a null depth | R2 | P1 |
| PH3-06 | Ownership Φ (Eq. 30) | Role 2 kit, T9 tests | All pass | R2 | P0 |
| PH3-07 | Execution closure (Eq. 31) | Role 2 kit, T7 integration test | python, libpython and libc in; `ls` and `dash` out | R2 | P0 |
| PH3-08 | Every expectation carries an origin (Eq. 36) | Scan the envelope | Every capability has `origin`; file, package and closure sections come only from verified evidence (`verification` block all true) | R2 | P0 |
| PH3-09 | Indices agree with the envelope (Eq. 37) | Property test on 500 random files | 100% agreement across J_path, J_hash, J_layer, J_pkg, J_depth | R2 | P0 |
| PH3-10 | Graph schema matches Eqs. (38)–(48) | Load the demo envelope into Neo4j and count | Node and edge counts equal the envelope's | R4 | P1 |
| PH3-11 | Two images sharing packages do not mix SBOMs (M4) | Load stand-in and demo; trace a demo file's dependency path | Path uses only demo SBOM edges; otherwise M4 is confirmed | R4 | P1 |
| PH3-12 | Compile time and envelope size | Time each compiler step on the demo image | Times and size reported | R2 | P1 |

### 3.4 ML-A: capability inference (details in Section 4)

| ID | Checks | How | Pass criterion | Owner | P |
|---|---|---|---|---|---|
| MLA-01 | Algorithm 1 logic: threshold θ_C, cap at 𝒞^K8s, origin labels (Eqs. 33–34) | Unit tests with fixed probabilities, θ_C, 𝒞^K8s and 𝒞^decl | Output set and labels exactly as expected; nothing outside 𝒞^K8s | R2 | P0 |
| MLA-02 | Feature extractor Ω_I is deterministic (Eq. 32) | Extract z_I twice from the same envelope | Identical vectors; every feature named in `ml/features.md` | R2 | P0 |
| MLA-03 | Ground-truth labels from observed capability use | Profile at least 20 images under Tetragon's `cap_capable` policy | `ml/data/labels.jsonl`, one row per image | R1 | P0 |
| MLA-04 | LightGBM trains and predicts | Repeated 5-fold cross-validation, folds by image | Model saved; per-label and micro/macro metrics reported | R2 | P0 |
| MLA-05 | ML-A against simple baselines | Same folds: allowlist, empty set, pod defaults, per-label majority | Comparison table reported | R2 | P1 |
| MLA-06 | Predictions never exceed the pod's allowed set (Eq. 34) | Predict for a pod with capabilities dropped | Zero predictions outside 𝒞^K8s | R2 | P0 |
| MLA-07 | Effect on false positives: D_cap alerts with ML-A vs the allowlist | Run the benign scenarios with each | D_cap count per scenario, per method | R3 | P1 |
| MLA-08 | Egress expectations N̂_I (M8) | Add egress labels to the same model | Metrics reported, or `blocked` with reason | R2 | P2 |

### 3.5 Phase 4: Collection, binding and deterministic verification

| ID | Checks | How | Pass criterion | Owner | P |
|---|---|---|---|---|---|
| PH4-01 | Exec events carry real path, pid, ppid and container (Eq. 50) | Run a command in a demo pod | All fields present and correct | R3 | P0 |
| PH4-02a | Exec, write and capability events arrive (M11) | Trigger each once | One event per trigger; event rate per kind recorded | R3 | P0 |
| PH4-02b | Executable-mmap and connect events arrive (M11) | Trigger each once | One event per trigger; event rate per kind recorded | R3 | P1 |
| PH4-03 | Unknown containers are binding failures (Eq. 51) | Start an unbound container in `demo` | Binding failure; never checked against another envelope | R3 | P1 |
| PH4-04 | One cached envelope per digest (Eq. 52) | Scale the demo to 5 replicas, then to 0 | One envelope in memory; evicted at 0 | R3 | P1 |
| PH4-05 | D_exec for a file in no layer | Scenario attack-1 | `D_exec / undeclared` for `/tmp/.x9` | R3 | P0 |
| PH4-06 | Exec outside the closure: Eq. (55) as written vs split class (C2) | Run benign-1 and the benign catalogue under both rules | Detection count and false-positive rate for each rule | R3 | P0 |
| PH4-07 | D_hash for a relocated binary | Scenario attack-3 | `D_hash / relocated` | R3 | P1 |
| PH4-08 | D_hash for a declared binary modified in place (C3) | Scenario attack-4 | `D_hash / modified` | R3 | P1 |
| PH4-09 | A missing runtime hash is handled (C3) | Disable hashing and replay attack-3 | No crash; path-only result, marked as such | R3 | P1 |
| PH4-10 | D_load for a library in no layer | Scenario attack-5 | `D_load / undeclared` | R3 | P1 |
| PH4-11 | D_load for a declared library outside the closure (dlopen, NSS) | Scenario benign-3 | Weak class, not `undeclared` | R3 | P1 |
| PH4-12 | D_write on a declared file | Scenario attack-1 | `D_write` on `/etc/passwd` | R3 | P0 |
| PH4-13 | Writes under volume mounts (M10) | Scenario benign-4 | Nothing under the mount rule; count recorded under the draft's rule | R3 | P1 |
| PH4-14 | New files are conforming | Write `/tmp/new.txt` in a demo pod | No detection | R3 | P0 |
| PH4-15 | D_cap | Scenario attack-6 | `D_cap` with origin INFERRED | R3 | P1 |
| PH4-16 | D_net | Scenario attack-7 | `D_net` | R3 | P1 |
| PH4-17 | Detection records have every field (Eq. 60) | Schema check on all detections | Class, clause, origin and time present | R3 | P0 |
| PH4-18 | One class per event (M12) | Exec at a new path with declared content | Exactly one detection, `D_hash / relocated` | R3 | P1 |

### 3.6 Cuckoo filter (details in Section 6)

| ID | Checks | How | Pass criterion | Owner | P |
|---|---|---|---|---|---|
| CF-01 | No false negatives | Insert every envelope path, then query each | Zero misses | R3 | P0 |
| CF-02 | False-positive rate matches theory, 2b/2^f | Query 400,000 non-member paths at 8- and 16-bit fingerprints | Measured rate at or below theory | R1 | P1 |
| CF-03 | Memory against a Python `set` and `dict` | Measure bytes for the demo envelope's paths | Ratio reported | R1 | P1 |
| CF-04 | Lookup time for hits and misses against `set` | Microbenchmark, at least 10,000 lookups each | ns per lookup reported | R1 | P1 |
| CF-05 | Effect on the real event path (M15) | Replay a recorded event stream with the filter on and off | Per-event latency and CPU reported; keep-or-drop decision recorded | R3 | P1 |
| CF-06 | Behaviour when the filter is full | Insert beyond capacity with expansion off | Failed insertion detected and handled; no silent loss | R1 | P1 |

### 3.7 ML-B: behavioural path (details in Section 5)

| ID | Checks | How | Pass criterion | Owner | P |
|---|---|---|---|---|---|
| MLB-01 | Only conforming events enter the window (Algorithm 2, lines 2–4) | Feed a mix of conforming and contradicting events | No contradiction reaches a window | R3 | P0 |
| MLB-02 | Windows and features Ψ_I are deterministic (Eq. 57) | Replay the same events twice | Identical feature vectors | R3 | P0 |
| MLB-03 | A per-image model trains as in Eq. (49) | Train on the demo image's benign run | Model, θ_A and g_I stored beside the envelope | R3 | P0 |
| MLB-04 | False-positive rate on held-out benign behaviour | A second benign run, at least an hour later | Window false-positive rate at most 1% | R3 | P0 |
| MLB-05 | An in-envelope attack is flagged | Scenario attack-2 | At least one `D_beh`; no deterministic detection for attack-2 | R3 | P0 |
| MLB-06 | Per-image vs global model (C5) | Train a global model on 3 or more images | False-positive rate and detection compared | R3 | P1 |
| MLB-07 | Behavioural scores never outrank contradictions (M2) | Score the attack-1 and attack-2 detections | Ordering reported; S_beh capped if violated | R4 | P1 |

### 3.8 Phase 5: Scoring, attribution, alerts and the log

| ID | Checks | How | Pass criterion | Owner | P |
|---|---|---|---|---|---|
| PH5-01 | Eq. (65) with the agreed values | Unit tests using the Sprint Handoff §8 examples | Scores 90, 72 and 34 exactly | R4 | P0 |
| PH5-02 | Authenticated outranks inferred (Eq. 66) | Same detection with the origin flipped | Score with AUTHENTICATED above score with INFERRED | R4 | P0 |
| PH5-03 | Scores stay in [0, 1] and never change detections (Eq. 68) | Property test over random inputs | Always in range; detection set unchanged | R4 | P0 |
| PH5-04 | An undeclared file outranks any declared one at equal type and capability | Property test over depths | Holds for every depth | R4 | P1 |
| PH5-05 | Unresolved depth is not scored as ⊥ (M16) | A base-image file with a null depth | rho = 0.5, not 1 | R4 | P1 |
| PH5-06 | Layer path (Eqs. 71–72) | A known file | Correct layer returned | R4 | P0 |
| PH5-07 | Dependency path (Eqs. 69–70) | A `urllib3` file on the stand-in | Path from the root through `requests` to `urllib3` | R4 | P1 |
| PH5-08 | An undeclared file has empty paths | `/tmp/.x9` | Reported as introduced by no layer, with no package | R4 | P0 |
| PH5-09 | Alert record fields (Eqs. 75–78) | Schema check on all alerts | Clause, origin, score, attribution and signing identity present | R4 | P0 |
| PH5-10 | The hash chain appends and verifies (Eq. 79) | Append 100 records, then run `verify_log` | Passes | R4 | P0 |
| PH5-11 | Editing a record is detected | Change one character in record k | `verify_log` reports record k | R4 | P0 |
| PH5-12 | Rewriting the chain from storage (M6) | Rewrite record k and recompute every later hash | Plain chain passes, showing the weakness; with signed checkpoints it fails | R4 | P1 |
| PH5-13 | A multi-stage attack forms one chain (M7) | Scenario attack-1 | Both detections share one `chain_id` | R4 | P1 |

### 3.9 Phase 6: Trust re-evaluation

| ID | Checks | How | Pass criterion | Owner | P |
|---|---|---|---|---|---|
| PH6-01 | An admitted image starts trusted (Eq. 84) | Check the trust state after admission | Trusted = 1 | R4 | P0 |
| PH6-02 | KeyCheck withdraws trust (Eq. 85) | Scenario trust-2 | One trust alert naming `key` | R4 | P0 |
| PH6-03 | BuilderCheck withdraws trust (Eq. 87) | Add the image's `builder_id` to the denylist | One trust alert naming `builder` | R4 | P1 |
| PH6-04 | ComponentCheck withdraws trust (Eq. 88) | Scenario trust-1 | One trust alert naming `comp`, with package path and layer | R4 | P0 |
| PH6-05 | An ordinary CVE does not withdraw trust (policy) | Local advisory with a plain CVE ID | No withdrawal; advisory reported | R4 | P1 |
| PH6-06 | Alert only on the 1 → 0 transition (Eq. 90) | Stay untrusted for 5 cycles | Exactly one alert | R4 | P0 |
| PH6-07 | Runtime and trust states are independent (Eqs. 95–96) | Conforming but untrusted; deviating but trusted | Both combinations reported correctly | R4 | P1 |
| PH6-08 | TransparencyCheck fails on a bad proof (Eq. 86) | Corrupt the stored inclusion proof | Trust withdrawn, naming `trans` | R4 | P1 |
| PH6-09 | Trust-alert latency | Time from a trust change to its alert | At most ΔR plus processing time | R4 | P1 |

### 3.10 End-to-end scenarios (scenario details in Section 7)

| ID | Checks | How | Pass criterion | Owner | P |
|---|---|---|---|---|---|
| E2E-01 | Undeclared exec plus declared write | Scenario attack-1 | D_exec (90) and D_write (72) in one chain; Falco output recorded | R1 | P0 |
| E2E-02 | Benign use | Scenario benign-1 | Nothing above Low; Falco output recorded | R1 | P0 |
| E2E-03 | In-envelope burst | Scenario attack-2 | `D_beh` only; Falco output recorded | R1 | P0 |
| E2E-04 | Relocated binary | Scenario attack-3 | `D_hash / relocated` | R1 | P1 |
| E2E-05 | Binary modified in place | Scenario attack-4 | D_write, then `D_hash / modified` | R1 | P1 |
| E2E-06 | Library injection | Scenario attack-5 | `D_load / undeclared` | R1 | P1 |
| E2E-07 | Capability excess | Scenario attack-6 | `D_cap` | R1 | P1 |
| E2E-08 | Undeclared egress | Scenario attack-7 | `D_net` | R1 | P1 |
| E2E-09 | Install-time payload | Scenario attack-8 | Only a weak outside-closure detection: the documented boundary | R1 | P1 |
| E2E-10 | Unsigned container | Scenario attack-9 | Binding failure | R1 | P1 |
| E2E-11 | Trust withdrawal on a running pod | Scenario trust-1 | One trust alert; runtime state still conforming | R1 | P0 |
| E2E-12 | Log tampering | Scenario tamper-1 | `verify_log` fails at the edited record | R1 | P0 |

### 3.11 Evaluation against baselines

| ID | Checks | How | Pass criterion | Owner | P |
|---|---|---|---|---|---|
| EV-01 | Detection per scenario: PROVBIND against Falco | All E2E scenarios | Table: detected or not, per system | R1 | P0 |
| EV-02 | False positives on the benign catalogue | Scenarios benign-1 to benign-6, each system | Alert count per scenario per system | R1 | P1 |
| EV-03 | Ablations: envelope layers, s_π, strict vs split closure, ML-B on and off, ML-A vs allowlist | Re-run E2E and benign scenarios with one part off | Detection and false-positive deltas | R1 | P1 |
| EV-04 | Reconstructed SynthChain scenarios (draft §IV) | Rebuild the corpus attacks in the attested testbed | Precision, recall, F1, FPR, accuracy | R1 | P2 |
| EV-05 | Low-and-slow mimicry | attack-2 spread over 30 minutes | Detected or missed, reported honestly | R1 | P2 |
| EV-06 | Stage coverage per scenario (DS1) | Multi-stage scenarios | Fraction of stages detected | R1 | P2 |
| EV-07 | ML-C baseline, kept separate from ML-B | Isolation Forest on all benign events, with its own code, data and model file | Baseline column added to EV-01 and EV-02 | R1 | P1 |

### 3.12 Cost

| ID | Checks | How | Pass criterion | Owner | P |
|---|---|---|---|---|---|
| OH-01 | Per-event verification latency | Replay at least 100,000 recorded events | p50 and p99 reported | R3 | P1 |
| OH-02 | Node CPU and memory on top of Tetragon alone | Benign load with and without PROVBIND | Overhead in percent | R3 | P1 |
| OH-03 | Ring-buffer drops under burst | An exec storm of 10,000 short processes | Drop rate reported | R3 | P1 |
| OH-04 | Compile and index time per image | Every test image | Seconds per image | R2 | P1 |
| OH-05 | Index memory per envelope | Every test image | Bytes per 1,000 files | R2 | P1 |
| OH-06 | Cache hit rate at 1, 10 and 50 replicas | Scale test | Hit rate reported | R3 | P2 |

Cost numbers from kind on a laptop are only indicative. Numbers for the paper need the bare-metal machine.

---

## 4. ML-A test design

**What the draft claims.** A pre-trained multi-label LightGBM model predicts the capabilities a workload needs from a feature vector z_I = Ω_I(·) built from configuration, reachable packages, the execution closure and deployment context (Eqs. 32–33). Predictions are capped at the pod's allowed set (Eq. 34) and labelled INFERRED, while declared capabilities are AUTHENTICATED (Algorithm 1).

The draft gives no label set, no training data and no metrics, so this test defines them. Its results go into the paper as measured.

### 4.1 Corpus

`ml/corpus.yaml` lists the images, how to run each, and a workload that exercises it. The test kit has a starter file. This corpus is dataset D1 (Section 12).

- **Size:** at least 20 images, target 40.
- **Variety:**
  - web servers: nginx, httpd, caddy;
  - datastores: redis, postgres, mariadb, mongo, memcached;
  - a message broker: rabbitmq;
  - language apps: Python/Flask, Node/Express, a static Go binary;
  - utilities: busybox, alpine with ping;
  - a curl-based job;
  - our stand-in and demo images.
- **Preparation:** re-tag each image into `localhost:5001` and attest it with our key, so the compiler reads verified evidence, exactly as in production.

### 4.2 Labels: observed capability use

Use Tetragon's documented policy for recording Linux capability usage, which hooks `cap_capable`. Its return value is 0 when the check succeeded and access was granted, and -1 when it was denied.

- **Label for an image:** the set of capabilities with at least one **granted** check from the workload's own processes, during a 120-second run after the workload starts.
- **Denied checks:** record them separately. They are attempts, useful for analysis, but not labels.
- **Runs:** two per image; the label is the union. Report how often the two runs disagree, since that is the label noise.
- **Rare labels:** a label with fewer than 3 positive images is reported as "too rare" and left out of training.

### 4.3 Features Ω_I

Write every feature name into `ml/features.md`; this is also the missing definition of Ω_I in the paper. Keep to about 200 features:

| Group | Features |
|---|---|
| Configuration | runs as root; `User` set; number of exposed ports; any port below 1024; number of environment variables |
| Packages | count per ecosystem; indicator for each of the 100 most frequent package names in the corpus |
| Closure | closure size; interpreter type (python, node, java, shell, static) |
| ELF imports across closure binaries | indicators for `socket`, `bind`, `listen`, `connect`, `setuid`, `setgid`, `setgroups`, `chown`, `fchown`, `chmod`, `mount`, `umount2`, `ptrace`, `capset`, `prctl`, `chroot`, `setns`, `unshare`, `sethostname` |
| Deployment | pod privileged; number of capabilities added and dropped |

### 4.4 Training

`MultiOutputClassifier(LGBMClassifier(n_estimators=200, num_leaves=15, min_child_samples=2, learning_rate=0.05))`.

- **Cross-validation:** 5 folds repeated 3 times, with folds split **by image**.
- **Threshold:** θ_C = 0.5 by default, plus a sweep from 0.2 to 0.8 that shows the trade-off in Section 4.5.

### 4.5 Metrics

- **Standard:** per-label precision, recall and F1; micro- and macro-F1; subset accuracy; Hamming loss.
- **The two that matter for PROVBIND:**
  - **Under-prediction rate** = capabilities used but not predicted, divided by capabilities used. Each one becomes a false D_cap alert at runtime.
  - **Over-prediction rate** = capabilities predicted but not used, divided by capabilities predicted. Each one widens the envelope and can hide an attack.

  Plot both against θ_C.

### 4.6 Baselines (MLA-05)

1. The curated allowlist (`compiler/caps_allowlist.json` plus the port rule).
2. The empty set: under-prediction at its maximum.
3. The pod's full default set: zero under-prediction by construction, over-prediction at its maximum.
4. Per-label majority.

### 4.7 Pass criteria and honesty

- **P0:** the pipeline runs end to end on at least 20 images, the Algorithm 1 unit tests pass, and cross-validated metrics are reported. The draft sets no accuracy target.
- **P1:** the baseline comparison. If ML-A does not beat the allowlist on under-prediction, report that. It is a legitimate result and an update item.
- **Sample size:** 20–40 images make this a feasibility result, not a benchmark. Say so on the slide.

---

## 5. ML-B test design

**What the draft claims.** Only envelope-conforming events from monitored processes 𝒬^beh enter per-process windows W_q. A per-image Isolation Forest IF_I scores the window features Ψ_I, a normaliser g_I and a threshold θ_A decide, and a behavioural detection never claims a contradiction (Eqs. 57–59, 61; Algorithm 2). The model is stored with the envelope (Eq. 49), but the draft never says where its training data comes from (C5).

**The test follows the draft:** one model per image, trained from a sandbox run of that image. The global-model alternative is MLB-06.

| Item | Setting |
|---|---|
| Hook requirement | Widen the write hook to **all paths** in monitored pods, not only protected prefixes, because ML-B needs every file written. Measure the extra event rate (OH-01). |
| Monitored processes | Long-lived processes in the container, alive more than 10 s |
| Window | 30 s or 200 events per process, whichever comes first |
| Features Ψ_I | Per window: count per event kind; new files written; distinct directories written; child processes started; distinct executables run; granted capability checks; with the connect hook on, connections plus distinct destination addresses and ports; each count also as a rate per second |
| Benign data (dataset D2) | The demo image under a load generator for **at least 3 hours**: `curl` at random intervals, health checks, the app's own cache-file writes. That gives about 360 windows per process. Split 70/30 into training and validation. |
| Model | `IsolationForest(n_estimators=100, max_samples=min(256, n), contamination="auto", random_state=0)`; record the number of windows |
| Normaliser g_I | Percentile rank against the validation windows' scores |
| Threshold θ_A | 99th percentile of validation scores, which needs at least 100 validation windows. With fewer, use the 95th percentile and say so. |
| Held-out test (MLB-04) | A second benign run, at least one hour long (about 120 windows), starting at least one hour after the first |
| Attack (MLB-05) | Scenario attack-2: 300 new files written under `/tmp/.cache` in 20 s and read back, with no new executables and no writes to declared files. Expected: no deterministic detection, at least one `D_beh`. |
| Global model (MLB-06) | Windows from the stand-in plus at least 2 corpus images; features as rates and ratios so they carry across images |

**Honest boundary.** attack-2 is a volumetric case, the easy one. A low-and-slow version (EV-05) will probably evade the forest; report the miss, as DS1 planned for the in-envelope adversary.

**Separation from ML-C.** The evaluation baseline ML-C is a different Isolation Forest, with its own code, training data (all events) and model file (EV-07).

---

## 6. Cuckoo filter test design

**What the draft claims.** Phase 4, Step 2: "A Cuckoo filter provides a compact membership test before detailed indexed lookup." Review item M15 doubts it helps: most events touch declared files, so most filter answers are "maybe", and the index must still be consulted. These tests decide.

### 6.1 Implementation

- **Use the reference filter in the test kit** (`node/ref_cuckoo.py`). It implements partial-key cuckoo hashing, where the first bucket comes from the key's hash and the second from XOR with the fingerprint's hash. Its false-positive rate follows the theory: 2b/2^f for bucket size b and fingerprint bits f.
- **Do not use pyprobables with small fingerprints.** In pyprobables 0.7.0, both bucket indices are derived from the fingerprint alone (see `_generate_fingerprint_info`), so the false-positive rate grows with the number of stored items instead of following 2b/2^f. It behaves correctly only with 4-byte fingerprints. CF-02 must report which implementation it used.
- **Build one filter per envelope on the node,** from the keys of `files`, at load time.

### 6.2 Pre-check in Claude's sandbox (synthetic paths, not a project result)

15,000 synthetic paths, Python 3.12. Re-run CF-01 to CF-04 on real envelopes before using any number.

| Measurement | Python `set` | Reference filter, 16-bit | pyprobables 0.7.0 |
|---|---|---|---|
| Lookup, hit | about 30 ns | about 2,500 ns | about 10,000 ns |
| Lookup, miss | about 40 ns | about 3,300 ns | about 5,800 ns |
| Memory | about 0.5 MB of references (the path strings exist anyway) | 64 KB | 1.1–1.8 MB |
| False-positive rate | none | 0.0065% (26 of 400,000; theory at most 0.0122%) | 19.8% at 16 bits; 100% at 8 bits; 0% at 32 bits |
| False negatives | none | 0 | 0 |

**What this predicts.** In CPython a set lookup runs in C, so a Python filter is roughly 80 times slower per lookup. The filter saves memory only if the full index does **not** have to stay resident, but the draft consults the index after every "maybe", and "maybe" is the common case. Expect CF-05 to show the filter adding latency.

### 6.3 Decision rule for the update log

- **Keep the filter** only if CF-05 shows lower per-event latency, or OH-05 shows that index memory limits how many images a node can cache and the filter removes that limit.
- **Otherwise** update the draft to a hash-table index, and report the filter as evaluated and rejected, with the numbers.

---

## 7. Scenario library

"When it runs" answers whether the malicious behaviour happens at install time (during `docker build`) or at run time.

| ID | What happens | When it runs | Trigger | Expected | P |
|---|---|---|---|---|---|
| attack-1 | The app's `/update` calls `requestz_helper.check_update()`, which writes an embedded static binary to `/tmp/.x9` and runs it; the binary appends a line to `/etc/passwd` | Run time | `curl /update` after `envelope_ready` | D_exec undeclared plus D_write, one chain | P0 |
| attack-2 | `/update2` writes 300 new files under `/tmp/.cache` in 20 s and reads them back; no new executables | Run time | `curl /update2` | `D_beh` only | P0 |
| attack-2b | `/update3` opens 50 connections to an allowed sink service | Run time | `curl /update3` | `D_beh` | P1 |
| attack-3 | Copies `/usr/bin/ls` to `/tmp/.l` and runs it | Run time | `curl /update4` | `D_hash / relocated` | P1 |
| attack-4 | Overwrites `/usr/bin/ls` with the bytes of `/usr/bin/cat`, then runs `ls` | Run time | `curl /update5` | D_write, then `D_hash / modified` | P1 |
| attack-5 | Writes an embedded shared library to `/tmp/libx.so`, then starts `python3 -c pass` with `LD_PRELOAD=/tmp/libx.so` | Run time | `curl /update6` | `D_load / undeclared` | P1 |
| attack-6 | Changes a file's owner to uid 4242, which needs `CAP_CHOWN`, where the envelope's capability set lacks it | Run time | `curl /update7` | `D_cap` (INFERRED) | P1 |
| attack-7 | Connects to an address outside the egress set | Run time | `curl /update8` | `D_net` | P1 |
| attack-8 | A package's build step writes `/usr/local/bin/helperd` into the image during `docker build`; the app runs it later | Written at install time, runs at run time | `docker build`, then `curl /update9` | Only a weak outside-closure detection: the documented limit for build-time compromise | P1 |
| attack-9 | An unsigned image deployed in namespace `demo` | Deploy time | `kubectl apply` | Binding failure | P1 |
| trust-1 | A local OSV-format advisory marks `requestz-helper` as malicious (`MAL-…`) | Trust loop | Edit the advisory file | One trust alert; runtime state still conforming | P0 |
| trust-2 | Our signing key is marked revoked | Trust loop | Edit `run/keystatus.json` | One trust alert naming `key` | P0 |
| tamper-1 | One character changed in the violation log | After any run | Edit the file | `verify_log` fails at that record | P0 |
| benign-1 | Three `curl` calls, then `kubectl exec -it … -- sh -c 'ls /; cat /etc/hostname'` | Run time | Script | Nothing above Low | P0 |
| benign-2 | `pip install six` at runtime | Run time | `kubectl exec` | Reported by cause | P1 |
| benign-3 | DNS lookups (`socket.getaddrinfo`), which load glibc NSS libraries | Run time | App endpoint | Weak load class only | P1 |
| benign-4 | Writes to an `emptyDir` mounted over an image directory | Run time | App endpoint | Nothing under the mount rule | P1 |
| benign-5 | Log rotation: rename and recreate the app's log files | Run time | App endpoint | Nothing | P1 |
| benign-6 | A busybox sidecar in the same pod | Deploy time | Pod spec | Needs its own signed image, otherwise a binding failure | P1 |

All payloads are harmless test code and run only inside throwaway demo containers.

---

## 8. Event hooks (verified 27 September 2026)

| Class | Hook | Key fields | Source |
|---|---|---|---|
| D_exec, D_hash | Built-in `process_exec` events | binary, pid, parent | Tetragon default |
| D_write | kprobe `security_file_permission`, argument 1 is the access mask (0x02 = MAY_WRITE), with return value | file path, mask | [Tetragon `filename_monitoring.yaml`](https://github.com/cilium/tetragon/blob/main/examples/tracingpolicy/filename_monitoring.yaml) |
| Truncation | `security_path_truncate`; on kernels 6.2 and later, `security_file_truncate` | file path | [Tetragon filename-access docs](https://tetragon.io/docs/use-cases/filename-access/) |
| D_load | kprobe `security_mmap_file` with PROT_EXEC (0x04) in the protection flags | file path, prot | Same example policy |
| D_cap, ML-A labels | kprobe `cap_capable`; return 0 = granted, -1 = denied | capability | [Tetragon "Record Linux Capabilities Usage"](https://tetragon.io/docs/use-cases/security-profiles/record-linux-capabilities/) |
| D_net | kprobe or fentry `tcp_connect` | socket: destination address and port | [Tetragon hook points](https://tetragon.io/docs/concepts/tracing-policy/hooks/) |
| Scope | Namespace and pod-label filtering, done in the kernel | — | [Tetragon Kubernetes filtering](https://tetragon.io/docs/concepts/tracing-policy/k8s-filtering/) |

Filter every hook to namespace `demo` in the kernel. `security_file_permission` fires on every read and write, so filter on MAY_WRITE in the kernel as well.

---

## 9. Who does what, and when

Days follow the Sprint Handoff (§9): P0 is due by the Day 3 noon freeze.

| | R1 Testbed and evaluation | R2 Evidence and compiler | R3 Node runtime | R4 Alerts and integration |
|---|---|---|---|---|
| **Day 1** | Harness: registry, result files, `eval.report`; scenario runner; ML-A corpus list and runner; start profiling (MLA-03) | PH1-01, PH1-04; PH3-01, PH3-02; MLA-01; MLA-02 skeleton | Hooks for exec, write (all paths) and `cap_capable` (PH4-01, PH4-02a); filter with CF-01 | PH2-01, PH2-09; PH5-01 to 03; PH5-10, PH5-11 |
| **Day 2** | attack-1, attack-2, benign-1, trust-1 and tamper-1 scripts; Falco capture; profiling to at least 20 images | PH3-03 to 09; MLA-03 dataset join; MLA-04; MLA-06 | PH4-05, 06, 12, 14, 17; MLB-01, MLB-02; benign windows for MLB-03 | PH5-06, 08, 09; PH6-01, 02, 04, 06; mock integration |
| **Day 3** | E2E-01 to 03, E2E-11, E2E-12; EV-01 | P1: MLA-05, PH1-02, PH2-06, PH2-07, PH3-10 to 12, OH-04 | MLB-03 to 05 (P0); then CF-05, PH4-07 to 18, MLB-06 | Integration, freeze; then PH5-12, PH5-13, PH6-03, 05, 07 to 09 |
| **Day 4** | `REPORT.md`; slides; CF-02 to 04, CF-06; EV-02, EV-03, EV-07 | Slides; OH-05; update log entries for Phase 1–3 and ML-A | Slides; OH-01 to 03 | Slides; rehearsal |

**P0 load:** about 45 tests. Most are small, but three are not:

- **MLA-03 (profiling):** start it on Day 1. It needs Role 3's `cap_capable` policy, and Role 1 runs the corpus.
- **MLB-03 to 05:** they need the widened write hook.
- **EV-01:** it needs every scenario working.

If time runs out, cut P1 before touching P0.

---

## 10. From results to paper updates

Each row names a part of the draft, the tests that decide it, and the update if the result says so. Fill in the "Result" column as tests finish. Changes are applied to Aj Ohm's `.tex` once we have it.

| Draft item | Tests | Update if the result says so | Result |
|---|---|---|---|
| Eq. (5): only d_I is signed | PH1-02 | Sign every evidence object (C1) | |
| Eq. (55): strict exec rule | PH4-06, EV-02 | Split D_exec into undeclared and outside-closure (C2) | |
| Source of H(f) | PH4-07 to 09 | Name the hash source; add the hash guard (C3) | |
| Admission to envelope timing | PH2-10 | Describe asynchronous compilation, buffering and the measured window (C4) | |
| Training source of ℳ_I^beh | MLB-03, MLB-06 | State the training source; per-image or global model (C5) | |
| Scoring values | PH5-01 to 05 | Add the value tables and a worked example (M1, M16) | PH5-01 to 05 pass (29 Sep 2026, PR #17's code on Korn-PC). PH5-04 holds on S (Eq. 65). The whole-number display score ties an undeclared file with a declared one from depth 39 (100·S = 70 + 20δ/(1+δ)). So the update should also say that alerts are ranked by S, and that 100·S is rounded for display only. |
| S_beh against S_det | MLB-07 | Cap S_beh or give it its own queue (M2) | |
| Graph writes at runtime | PH3-10, OH-01 | Keep runtime graph writes off the event path (M3) | |
| Package scope in the graph | PH3-11 | Add a DECLARES edge; scope DEPENDS_ON per image (M4) | |
| Where detections are stored | PH5-09, PH5-10 | One place for detections; align the abstract (M5) | |
| Hash chain | PH5-12 | Add signed checkpoints (M6) | |
| Chains | PH5-13 | Restore chain grouping (M7) | |
| Egress N̂_I | PH4-16, MLA-08 | Define N̂_I (M8) | |
| Declared capabilities 𝒞^decl | MLA-01 | Name their source; use CONFIGURED for pod-spec values (M9) | |
| Writes under mounts | PH4-13 | Add the mount exclusion (M10) | |
| Event hooks | PH4-02a, PH4-02b | Name the hooks (M11) | Name the final configuration's hooks and in-kernel filters (Section 10.1, "Collection"): the original set cost up to +378% at p95 on file-writing requests, the filtered set at most +9.9% (9 Oct 2026). |
| Decision order | PH4-18 | State the order (M12) | |
| Evaluation plan | EV-01 to 07 | Extend it with ablations, the adversarial case and ML-A (M13) | Baselines and cost done (final run `run-final`, 9 Oct 2026; overhead `opt5`, 8 Oct). Update Section IV to what was run: four comparators (Falco, DeSFAM-E, signature verification alone, and Confine-E, the last three estimated or derived); the testbed (19 scenarios × 5 runs, known/unknown split); overhead against an unmonitored host as well as against collection alone. The kernel ring-buffer drop rate under burst load was not measured: measure it or drop it. Fix the "[?]" (Section 10.2). Ablations, the adversarial case and ML-A stay open (M13). |
| Cuckoo filter | CF-01 to 06, OH-05 | Keep it with numbers, or replace it with a hash-table index (M15) | |
| ML-A details | MLA-01 to 08 | Define Ω_I, the label set, the metrics and θ_C | |
| Results | All | Add a Results section; the draft has only an Evaluation Plan | Final numbers ready: Section 10.1 (proposed text and tables), citations in Section 10.2. |

### 10.1 Proposed Results section (final numbers, 9 October 2026)

All numbers come from one configuration: the optimised Tetragon policies (`node/tetragon/opt/`) with ML-B
trained under them. Accuracy is from the final comparison run (`run-final`, 9 October), runtime cost from
the overhead run `opt5` (8 October), on the demo VM (VirtualBox, Ubuntu 24.04, kernel 7.0, kind, Tetragon
1.7.1). Details and the history of the measurements: `docs/ROLE1-SUPERVISOR-QUESTIONS-2026-10-05.md`.

**Testbed.** One demo image (Python web app), 19 scenarios run 5 times each: 95 runs, 65 attack runs and
30 benign runs. The attack scenarios re-create, harmlessly, behaviours reported for real malicious
packages; 35 attack runs are known attacks (an advisory, signature or rule could describe them), 30 are
unknown. Every detector is built before the first attack: PROVBIND's envelope from signed build metadata,
ML-B from 7 h of benign traffic; seven leakage checks (Section 2.5 of the Role 1 doc) pass.

**Detection.**

| System | Kind | Caught | False alarms | Precision | Recall | F1 | FPR | Known | Unknown |
|---|---|---|---|---|---|---|---|---|---|
| **PROVBIND** | measured | 50/65 | 0/30 | 1.00 | 0.77 | **0.87** | **0.00** | 30/35 | 20/30 |
| Falco (default rules) | measured | 25/65 | 10/30 | 0.71 | 0.38 | 0.50 | 0.33 | 15/35 | 10/30 |
| DeSFAM-E | estimated | 34/65 | 23/30 | 0.60 | 0.52 | 0.56 | 0.77 | 10/35 | 24/30 |
| Confine-E | estimated | 0/65 | 5/30 | — | 0.00 | — | 0.17 | 0/35 | 0/30 |
| Signature verification only | derived | 5/65 | 0/30 | 1.00 | 0.08 | 0.14 | 0.00 | 5/35 | 0/30 |

PROVBIND misses only rk-2, ru-5 and au-2, its documented limits. The result is identical, scenario by
scenario, to the run of 2 October with the original policies, so the optimisation cost no accuracy here.

**Runtime cost** (medians of 3 repetitions, change against an unmonitored host):

| Metric | Falco | PROVBIND |
|---|---|---|
| request mix, p50 / p95 latency | +3.2% / +4.7% | −0.5% / −0.1% |
| request mix, throughput loss | 3.4% | none |
| file-writing requests, p50 / p95 latency | +8.2% / +7.7% | +9.9% / +8.0% |
| file-writing requests, throughput loss | 7.1% | 7.5% |
| worst case: file write / process start | +5.1% / +15.8% | +5.2% / +119% |
| monitor memory | 119 MB | 409 MB |

Relative to the runtime collection alone (Tetragon with the same policies), the baseline Section IV names,
PROVBIND adds at most 0.4% on the application metrics. Per-event verification takes 1.9 µs at p50 and
6.7 µs at p99 (OH-01, replay of the 2 October recording). Preparation per new image: PROVBIND 4.38 s
(envelope compile, 109 packages, 5,695 files); with ML-B, 7 h of benign traffic plus 0.82 s of training;
Falco none; Confine-E 32.8 s; DeSFAM-E 30.5 min of profiling.

**Collection.** The cost is the number of sensor events per request times the cost of moving each event to
the verifier. The final hooks: `security_file_permission` for writes (only paths beginning with `/` leave
the kernel), `security_path_truncate` and `security_file_truncate`, `cap_capable`, `security_mmap_file`
with `PROT_EXEC`, and `tcp_connect`, in the monitored namespace only. A repeated identical event is
reported once a minute (per process; across processes for library loads), and return probes are dropped
where the verifier does not use them. With the original, unfiltered set the same test cost +86% (request
mix, p95) and +378% (file-writing requests, p95).

**Limits.** One image on one VM; 5 runs per scenario (0/30 false alarms bounds the rate at about 10% with
95% confidence); harmless re-creations, not real samples; DeSFAM-E and Confine-E are estimated from their
published designs on recorded traces. The rate limit compares the first 40 bytes of each argument, which
for a path is its length and first 32 characters: two different paths that share both are reported once
a minute. Every new process still costs its start and exit events. A sensor restarted while the workload
runs stops reporting that workload's existing processes; the testbed restarts the app after the sensor and
checks that its events arrive before every measurement.

### 10.2 Proposed citations

| Where in the draft | Add | Why |
|---|---|---|
| Section IV, "not containerised [?]" | University of Glasgow, "SynthChain: A synthetic benchmark and forensic analysis of advanced and stealthy software supply chain attacks," arXiv:2603.16694, 2026 | the reference our DS2 draft has in this place (`synthchain2026`); it is missing from the new bibliography |
| Section IV, the unknown-attack method and the container testbed | M. Grimmer et al., "A Modern and Sophisticated Host Based Intrusion Detection Data Set," BSI IT-Sicherheitskongress, 2019; M. Grimmer et al., "Dataset Report: LID-DS 2021," CRITIS 2022, LNCS 13723, 2023; G. Creech and J. Hu, "Generation of a new IDS test dataset: Time to retire the KDD collection," IEEE WCNC, 2013 (ADFA-LD); W. Haider et al., Future Internet 8(3):29, 2016 | normal-only training and a container testbed with kernel-level recording, the methods our evaluation adapts |
| Section IV, "attack semantics are extracted and re-instantiated" | DataDog, malicious-software-packages-dataset (GitHub); M. Ohm et al., "Backstabber's Knife Collection," DIMVA 2020 | the source of the behaviours the scenarios re-create, and the taxonomy they follow |
| Section IV comparators; the architecture table ("Tetragon") | The Falco Project (falco.org); Cilium Tetragon (tetragon.io) | tools the draft uses and names without a reference |
| Related work or Section IV | A. A. Syairozi and Arizal, "Comparative Analysis of eBPF-Based Runtime Security Monitoring Tools in Monitoring and Threat Detection on Kubernetes," RITECH 2025, SciTePress, pp. 136–141 | a recent comparison of eBPF runtime monitors on Kubernetes, the setting we evaluate in |
| Optional | A. V. Kozachok et al., "From CVE to CWE: Syscall-Based HIDS Generalisation," arXiv:2606.22581, 2026 | newer work testing detection of unseen attacks the same way |

---

## 11. What will not be finished before the presentation

Say these plainly on the slides:

- **ML-A accuracy:** 20–40 images is a feasibility result, not a benchmark.
- **The full SynthChain reconstruction** (EV-04).
- **Overhead:** bare-metal numbers are pending. Laptop and kind numbers are indicative only.
- **Harder mimicry:** the low-and-slow attack (EV-05).
- **Key state:** real KMS key state for Phase 6 is emulated with `run/keystatus.json`.

---

## 12. Datasets

PROVBIND needs signed images **and** the kernel events those same images produce. No public dataset has both, as the draft says in §IV, so we build most datasets ourselves. External datasets supply attack behaviour, chain-level ground truth and real advisory formats.

### 12.1 Summary

| ID | Dataset | Used for | Tests | Source and access | Risk | P |
|---|---|---|---|---|---|---|
| D1 | ML-A capability corpus | Training and evaluating ML-A | MLA-03 to 07 | We build it: 20–40 images profiled under Tetragon `cap_capable` | None: benign public images | P0 |
| D2 | ML-B benign windows | Training and validating ML-B, one model per image | MLB-03 to 06 | We build it: the demo image under load for at least 3 hours, plus a held-out run | None | P0 |
| D3 | ML-C benign events | Training the baseline | EV-07 | We build it from the same runs as D2, all events, in separate files | None | P1 |
| D4 | Scenario library and ground truth | Testing the system | E2E, PH4, EV-01 to 03 | We build it: the Section 7 scenarios with harmless payloads, plus `ground_truth.csv` | None: harmless test code | P0 |
| D5 | SynthChain (sanitised release) | Paper evaluation: attack chains and chain-level ground truth to rebuild in our testbed | EV-04, EV-06 | Tan et al., arXiv:2603.16694. Public: telemetry, provenance and ground truth. Controlled access, for verified researchers only: payload and orchestration code | Low: the public release has no payloads | P2 |
| D6 | Datadog malicious packages | Behaviour references for realistic scenarios; `manifest.json` as a real list of malicious packages | Scenario design, PH6-04, PH6-05 | `github.com/DataDog/malicious-software-packages-dataset`, Apache-2.0, open | **High if run**: real malware in encrypted ZIPs | P1 |
| D7 | Backstabber's Knife Collection | Same use as D6: 174 packages from real attacks, npm, PyPI and RubyGems, 2015–2019 | Optional | Ohm et al., DIMVA 2020. Access on justified request, emailed from an institutional address | High if run | P2 |
| D8 | OpenSSF Malicious Packages | A real advisory feed and format for ComponentCheck | PH6-04, PH6-05 | `github.com/ossf/malicious-packages`, OSV format, `MAL-` IDs, `api.osv.dev`; open | None: reports only, no code | P1 |

### 12.2 Datasets we build (D1–D4)

| ID | Stored in | Size | Rules |
|---|---|---|---|
| D1 | `ml/data/labels.jsonl`, `ml/data/features.jsonl`, joined into `ml/data/dataset.jsonl` | 20 images minimum, 40 target; two runs of 120 s per image | Record each image's digest; report how often the two runs disagree |
| D2 | `ml/data/mlb/<digest>/train.jsonl`, `validation.jsonl`, `heldout.jsonl` | At least 360 windows for training and validation; at least 120 held out | Conforming events only; the held-out run starts at least an hour after the first |
| D3 | `eval/mlc/data/` | All events from the D2 runs | Never read from or write to D2's folders; separate code and model file |
| D4 | `testbed/scenarios/`, `run/ground_truth.csv` | Every scenario run **at least 3 times** | One ground-truth row per run; payloads stay harmless test code |

### 12.3 SynthChain (D5)

SynthChain covers seven supply-chain attack scenarios across PyPI, npm and a native C/C++ case, on Windows and Linux, with four hosts and one containerised environment. The scenarios are annotated with 14 MITRE ATT&CK tactics and 161 techniques.

- **What we use:** the scenario descriptions in the paper, and the public chain-level ground truth. The public artefacts are linked from the paper (`anonymous.4open.science/r/SSCMDataset-2E11`) and published on Zenodo.
- **What we cannot use directly:** their telemetry. It carries no signed evidence, most of it is not containerised, and it comes from different sensors (draft §IV).
- **Method:** for each Linux scenario that can run in a container, re-create the attack chain with harmless code in an attested image, label its stages, and report the reconstruction as part of the method, as the draft says.
- **Payload code:** optional, under controlled access for verified researchers. If we want it, Aj Ohm should request it from his address.
- **Paper:** SynthChain prints as "[?]" in the draft; restore the citation.

### 12.4 Real malicious packages (D6, D7): handling rules

The Datadog README states that the repository contains actively malicious software published by threat actors and should not be run. So:

1. **Downloading is low risk; running is not.** The samples are encrypted ZIPs (password `infected`), and nothing executes when you download or clone them.
2. **Never install, import or run a sample.** `pip install` and `npm install` run the package's install scripts, which is exactly how many of these packages attack.
3. **Work only in a dedicated virtual machine.** It must have no personal accounts, SSH keys or cloud credentials. Take a snapshot first, and disable networking while samples are extracted.
4. **Read, don't run.** Extract into a folder mounted `noexec`, open the files as text, and delete them afterwards. Otherwise keep the ZIPs encrypted.
5. **Don't clone the whole repository onto a personal laptop.** Download single files, or use a sparse checkout of the samples you need. Antivirus may quarantine extracted files, and campus IT may flag malware downloads. Tell Aj Ohm and follow SIIT policy.
6. **Never put a real sample** into an image, the registry, the demo PC or the team repository. The testbed contains only our harmless re-creations.
7. **The safe part:** each ecosystem's `manifest.json` lists only names and affected versions. It can be used anywhere as a list of malicious packages for the trust tests. An entry of `null` means every version is malicious; a list means only those versions were compromised.

**How we use them.**

1. Pick 5–10 samples that cover the behaviours our scenarios test: runtime drop-and-exec, library injection, exfiltration to an out-of-band endpoint, credential-file reads, and npm pre-install execution.
2. Describe each behaviour in `testbed/behaviours.md`, naming the source package.
3. Re-create it harmlessly in `requestz-helper`.

An analysis of 5,576 Datadog packages found that the most common behaviours were exfiltration via Burp Collaborator and pre-install command execution in npm scripts. Our scenarios cover both:

- exfiltration → attack-7, D_net;
- pre-install execution → attack-8, which is the install-time boundary.

**Caveat:** the Datadog dataset was found mostly by one ruleset (GuardDog), so it may not represent all supply-chain malware.

### 12.5 OpenSSF Malicious Packages (D8)

This is a public database of malicious-package reports in OSV format. IDs start with `MAL-`, and reports can be fetched from `api.osv.dev/v1/vulns/<ID>` or scanned with `osv-scanner`. It contains no code.

- **PH6-04:** our local advisory file copies the structure of a real `MAL-` report.
- **Real feed:** ComponentCheck can also query the real feed for the demo image's purls; the expected result is no match.
- **PH6-05:** uses a real CVE-style OSV entry to show that an ordinary vulnerability does not withdraw trust.

### 12.6 What to cite in the paper

- **SynthChain:** Tan et al., arXiv:2603.16694 (fixes the "[?]").
- **Datadog dataset:** cite it in the form its README gives.
- **Backstabber's Knife Collection:** Ohm, Plate, Sykosch and Meier, DIMVA 2020, if we use it.
- **OpenSSF Malicious Packages:** the repository.

Take every citation's exact form from its source; do not reconstruct one from memory.

---

## Changelog

| Version | Date | Change |
|---|---|---|
| 1.0 | 27 Sep 2026 | First version |
| 1.1 | 27 Sep 2026 | Section 12 added: every dataset (D1–D8) with source, access, risk and tests, plus handling rules for real malicious samples. ML-B benign run lengthened to at least 3 hours, with a threshold rule for small validation sets |
| 1.2 | 9 Oct 2026 | Section 10: results of the final evaluation filled in (Event hooks, Evaluation plan, Results), with the proposed Results section (10.1) and citations (10.2) |
