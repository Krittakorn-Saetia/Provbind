# Role 3 status: node runtime (Phase 4)

**Updated 28 September 2026** by Claude Code (cloud). Scope: `node/`, `ml/data/mlb/`, and `tests/capability/test_ph4_*.py`, `test_cf_05_*.py` and `test_mlb_*.py`.

## How this file started

The session that asked for this file expected a status file from an earlier Role 3 session ("session N"). **None was in the repository.** `main`, every branch, the full history and PRs #1–#10 held no Role 3 work; `node/` had only the test kit's `ref_cuckoo.py`. If session N's work exists somewhere unpushed, it has to be reconciled with the PRs below.

This file therefore rebuilds the Role 3 task list from two sources:
- Sprint Handoff §7 (Role 3's days and "done when");
- the Test Plan, which gives Role 3 33 test IDs (P0: PH4-01, 02a, 05, 06, 12, 14, 17, CF-01, MLB-01 to 05).

## Tasks

| Task | What | Tests | Status | PR |
|---|---|---|---|---|
| R3-T1 | Normaliser: Tetragon JSON → §4.3 events (Eq. 50), namespace filter, drop counts | PH4-01, PH4-02a, PH4-02b | Done in the cloud; field shapes from the Tetragon docs, to verify against a real recording | #11 |
| R3-T2 | TracingPolicies: write on all paths, truncate, `cap_capable`, executable mmap, `tcp_connect`; Helm export filter | PH4-02a, PH4-02b; MLA-03 (Role 1) | Written and statically tested; not yet loaded into Tetragon | #11 |
| R3-T3 | Envelope and bindings store: reload on change, J_I, one cached envelope per digest (Eq. 52) | PH4-04 | Done in the cloud; the live scale test is written (integration) | role3/verify |
| R3-T4 | Verifier: decision order, mount exclusion, binding failures, detection records (§4.4) | PH4-03, PH4-05 to 18 | Done in the cloud | role3/verify |
| R3-T5 | `python -m node.run`: live and replay, `events.jsonl` and `detections.jsonl`, cold-start holding | PH2-10 | Done in the cloud; windows appear in the summary. PH2-10's test file is outside this session's files (Q2) | role3/verify |
| R3-T6 | Replay harness: a recording plus `ground_truth.csv` → results per scenario; the synthetic §7 library | PH4-* | Done | role3/verify |
| R3-T7 | ML-B: gate, windows, Ψ_I, per-image Isolation Forest (as JSON, no pickle), g_I, θ_A, D_beh; range guard; D2 tooling (`python -m node.mlb`, `ml/data/mlb/`) | MLB-01 to 06 | Done in the cloud. MLB-01 and 02 pass (code properties). MLB-03 to 06 need real D2 | role3/mlb |
| R3-T8 | Cuckoo filter on the event path, on and off | CF-05 (CF-01 runs in the test kit's example) | To do | |
| R3-T9 | Runtime hashing of executed files (stretch). The pipeline already takes a `hasher` | PH4-07, 08, 18 | To do | |
| Demo PC | Load the policies, record `node/testdata/raw.jsonl` and a scenario session, run the live tests | All PH4 on real evidence; OH-02, OH-03 | Needs the demo PC | |

## Tests

"Cloud" is what `pytest -m "not integration"` records here. "Demo PC" is what turns a result into pass or fail. How to record the evidence: `node/README.md`, "Recipe on the demo PC".

| ID | P | File | Cloud result | Demo PC |
|---|---|---|---|---|
| PH4-01 | P0 | `test_ph4_01_02_events.py` | not_run (synthetic) | Live test, or `PROVBIND_RECORDING` plus `PROVBIND_ENVELOPE` |
| PH4-02a | P0 | `test_ph4_01_02_events.py` | not_run | Live test, or a recording with `write.yaml` and `cap.yaml` applied |
| PH4-02b | P1 | `test_ph4_01_02_events.py` | not_run | Live test, or a recording with `load.yaml` and `connect.yaml` applied |
| PH4-03 | P1 | `test_ph4_scenarios.py` | not_run | attack-9 in the recording |
| PH4-04 | P1 | `test_ph4_04_cache.py` (integration) | none (live only) | Live scale 5 → 0; needs the controller to drop bindings of deleted pods (Q5) |
| PH4-05 | P0 | `test_ph4_scenarios.py` | not_run | attack-1 in the recording |
| PH4-06 | P0 | `test_ph4_scenarios.py` | not_run | The benign rows of the recording |
| PH4-07 | P1 | `test_ph4_scenarios.py` | not_run | **Blocked** on a raw recording: no runtime hash source yet (C3, R3-T9) |
| PH4-08 | P1 | `test_ph4_scenarios.py` | not_run | **Blocked**, as PH4-07 |
| PH4-09 | P1 | `test_ph4_scenarios.py` | not_run | attack-3 in the recording |
| PH4-10 | P1 | `test_ph4_scenarios.py` | not_run | attack-5, with `load.yaml` |
| PH4-11 | P1 | `test_ph4_scenarios.py` | not_run | benign-3, with `load.yaml` |
| PH4-12 | P0 | `test_ph4_scenarios.py` | not_run | attack-1 in the recording |
| PH4-13 | P1 | `test_ph4_scenarios.py` | not_run | benign-4 in the recording |
| PH4-14 | P0 | `test_ph4_scenarios.py` | not_run | A write to `/tmp/new.txt` in a demo pod |
| PH4-15 | P1 | `test_ph4_scenarios.py` | not_run | attack-6, with `cap.yaml` |
| PH4-16 | P1 | `test_ph4_scenarios.py` | not_run | attack-7, with `connect.yaml` and `PROVBIND_EGRESS`; blocked without the list (M8) |
| PH4-17 | P0 | `test_ph4_17_records.py` | not_run (26 synthetic detections valid) | The recording's detections, or `PROVBIND_DETECTIONS` |
| PH4-18 | P1 | `test_ph4_scenarios.py` | not_run | **Blocked**, as PH4-07 |
| MLB-01 | P0 | `test_mlb_01_02_gate_windows.py` | **pass**: 12 contradicting events of 8 kinds fed, none reached a window | Also checks `PROVBIND_RECORDING` |
| MLB-02 | P0 | `test_mlb_01_02_gate_windows.py` | **pass**: 104 windows identical over 8 replays (hash seeds 0–5) | Also checks `PROVBIND_RECORDING` |
| MLB-03 | P0 | `test_mlb_03_06_model.py` | not_run (synthetic D2) | D2 in `ml/data/mlb/<hex>/`; writes the model beside the envelope |
| MLB-04 | P0 | `test_mlb_03_06_model.py` | not_run (synthetic held-out FPR 0%) | `heldout.jsonl` in D2 |
| MLB-05 | P0 | `test_mlb_03_06_model.py` | not_run (synthetic: D_beh in attack-2; the forest alone flags only an unrelated window) | D2 plus `PROVBIND_RECORDING` with an attack-2 row |
| MLB-06 | P1 | `test_mlb_03_06_model.py` | not_run (3 synthetic images) | D2 for 3 or more images |
| PH2-10, MLA-07, OH-01, OH-02, OH-03, OH-06 | P1–P2 | none | none | These IDs' file names are outside this session's allowed files (Q2) |
| All other R3 IDs | | not written yet | | |

A simulated demo-PC run (the synthetic library written out as a recording, a run folder and a `ground_truth.csv`) gave:
- **pass:** PH4-03, 05, 06, 09 to 15;
- **blocked:** PH4-07, 08 and 18 (no hash source), and PH4-16 until an egress list is given; with one, PH4-16 passes.

With synthetic D2 written to a D2 folder as well, MLB-01 to 05 passed, the model was written beside the envelope, and MLB-06 stayed not_run (one image).

## Questions for the team

- **Q1. Contract fields for cap and connect events.** `events.jsonl` (§4.3) has no field for a capability or a destination.
  - What happens now: these events are verified in memory but not written. A replay of `events.jsonl` therefore has no D_cap or D_net, and no ML-B features that count them.
  - Proposal: cap events get `cap` and `granted`; connect events get `daddr`, `dport` and `protocol`. Readers ignore unknown fields, so adding them is cheap (Sprint Handoff §4), but it is a contract change, so it needs the team.
- **Q2. Files outside this session's scope.**
  - `pytest.ini`'s `testpaths` does not include `node/tests`, so `pytest -q` from the root does not collect the node unit tests directly. The capability tests run them in a subprocess (PH4-01/02 run two suites; PH4-17 runs all of `node/tests`), as Role 2's PH3 tests do. Please add `node/tests`.
  - Six R3 test IDs need files outside the allowed patterns: `test_ph2_10_*.py`, `test_mla_07_*.py` and `test_oh_*.py`. The code they need is here (cold-start windows in the `node.run` summary; per-event latency with `Pipeline(timing=True)`). May a later session add them?
- **Q3. Profiling for MLA-03 (Role 1).** `cap.yaml` is namespaced to `demo`. Profile the ML-A corpus in `demo`, or copy the policy (and the export filter in `values.yaml`) to the corpus namespace.
- **Q4. Detection classes for Role 4's scorer.** The Test Plan needs classes beyond §4.4's table: D_load, D_cap, D_net, D_beh, binding / unverified and binding / no_envelope (see the table in `node/README.md`). Choices Role 4 should confirm:
  - **Weak classes:** D_exec / outside_closure and D_load / outside_closure (both capped at Low).
  - **Origins:** D_cap is INFERRED unless every capability is AUTHENTICATED; D_net is CONFIGURED (an operator list); binding failures are AUTHENTICATED.
  - **`context.layer`** is the layer index, as in the envelope's `files`.
  - **`context.declared`** is `null` for binding failures, because nothing is known about the file.
  - **Once per container:** binding failures are reported once per container and subclass.
- **Q5. Does the controller remove a binding when its pod goes?** Two things depend on it: evicting an envelope at 0 replicas (PH4-04), and not reporting a restarted pod's old container as unknown. The node remembers every container ever bound, so late exit events never become binding failures.
- **Q6. Egress (M8).** The envelope has no egress set, so D_net checks an operator allow list given with `--egress`, and its detections say CONFIGURED. If the team adds egress to the envelope (MLA-08, Role 2), the verifier should read it from there.
- **Q7. Answer to Role 2's question 6.** Yes: the node uses `compiler/indices.py` (J_I) and `compiler/paths.py` (realpath), read-only.

- **Q8. The range guard (ML-B), for the team and Aj Ohm.** An Isolation Forest cannot say "far beyond normal".
  - Why: a window beyond the training range follows the same path through every tree as the most extreme benign window, and a feature constant in training gets no split. On the synthetic data, attack-2's 200-write burst scored exactly θ_A (benign maximum: 15 writes), so the forest alone missed it in every seed.
  - Proposed fix: a window with any feature above twice its benign maximum is also D_beh. It caught the burst and added no held-out false positive.
  - Current state: on by default, reported side by side with the forest alone (Test Plan §0, rule 1).
  - For the update log (§10): "IF saturates outside its training range; add a range guard, or use a model that extrapolates". Keep it?
- **Q9. D2 length (Role 1's load generator).** A window starts at a process's first event, so 3 hours of the synthetic load gave about 290 windows, fewer than 100 for validation, and θ_A fell back to the 95th percentile. The plan expected 360. 4 hours gave the 99th percentile. Record at least 4 hours; `ml/data/mlb/README.md` has the steps.
- **Q10. Per-image or global (C5).** MLB-06 compares them once D2 exists for 3 images. Until then the demo uses the per-image model, as the draft says.

## Blockers

- **No Tetragon or cluster in the cloud.** Every live test (marked `integration`) and every scenario result needs the demo PC. That was expected.
- **No real Tetragon output in the repository yet.** Sprint Handoff §7, Day 1 asks for `node/testdata/raw.jsonl`. Until it exists, the normaliser's input shapes come from the Tetragon documentation, not from our version.
- **No D2 yet.** MLB-03 to 06 need the demo image's benign windows: 4 hours or more, plus an hour held out (Q9).
- **No runtime hash source (C3).** D_hash never fires on a raw recording, so PH4-07, 08 and 18 record `blocked`. R3-T9 is the stretch fix: hashing `/proc/<pid>/exe`, after checking Tetragon's PID namespace in kind.
