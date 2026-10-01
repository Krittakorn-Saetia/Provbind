# Role 3 status: node runtime (Phase 4)

**Updated 1 October 2026** by Claude Code (cloud), with the first results from the demo VM (see "Results on the demo VM"). Scope: `node/`, `ml/data/mlb/`, and `tests/capability/test_ph4_*.py`, `test_cf_05_*.py` and `test_mlb_*.py`.

## How this file started

The session that asked for this file expected a status file from an earlier Role 3 session ("session N"). **None was in the repository.** `main`, every branch, the full history and PRs #1–#10 held no Role 3 work; `node/` had only the test kit's `ref_cuckoo.py`. If session N's work exists somewhere unpushed, it has to be reconciled with the PRs below.

This file therefore rebuilds the Role 3 task list from two sources:
- Sprint Handoff §7 (Role 3's days and "done when");
- the Test Plan, which gives Role 3 33 test IDs (P0: PH4-01, 02a, 05, 06, 12, 14, 17, CF-01, MLB-01 to 05).

## Pull requests

They are stacked: **merge them in this order.** Each targets `main`, and each diff also shows the PRs below it until those merge.

| PR | Branch | Tasks |
|---|---|---|
| [#11](https://github.com/Krittakorn-Saetia/Provbind/pull/11) | `role3/normalize` | R3-T1, R3-T2: normaliser, TracingPolicies; PH4-01, PH4-02a/b |
| [#12](https://github.com/Krittakorn-Saetia/Provbind/pull/12) | `role3/verify` | R3-T3 to T6: store, verifier, pipeline, `node.run`, replay harness; PH4-03 to 18 |
| [#13](https://github.com/Krittakorn-Saetia/Provbind/pull/13) | `role3/mlb` | R3-T7: ML-B, D2 tooling; MLB-01 to 06 |
| [#14](https://github.com/Krittakorn-Saetia/Provbind/pull/14) | `role3/cf05` | R3-T8: Cuckoo filter on the event path; CF-05; this final status |
| [#15](https://github.com/Krittakorn-Saetia/Provbind/pull/15) | `role3/handoffs` | Handoffs to Roles 1, 2 and 4 (`node/handoff/`). Documentation only, not stacked: merge any time |

#11 to #15 are merged. Open, from the demo-VM work (1 October):

| PR | Branch | What |
|---|---|---|
| [#20](https://github.com/Krittakorn-Saetia/Provbind/pull/20) | `role3/kind-hook` | The normaliser drops kind's OCI hook and its children (182 false detections per pod start) |
| [#21](https://github.com/Krittakorn-Saetia/Provbind/pull/21) | `role3/mlb05-mixed` | MLB-05 records not_run, not fail, with real D2 and no recording. **Merge before #22** |
| [#22](https://github.com/Krittakorn-Saetia/Provbind/pull/22) | `role3/d2-demo-app` | Dataset D2 for the demo app (261 / 113 / 140 windows) |
| this PR | `role3/vm-results` | This status update. Stacked on #20 |

**Numbers**, with all four merged:
- `pytest -m "not integration"`: 417 passed, 17 deselected (`main` alone: 392 and 13). That includes 25 new capability tests; 4 more are integration.
- `pytest node/tests`: 319 unit tests, run inside PH4-17 until `testpaths` includes them (Q2).
- With `requirements-role2.txt` alone (no numpy, scikit-learn or LightGBM, as on Korn's PC): 365 passed, 4 skipped, 0 failed. The ML-B tests that train a model skip cleanly, as MLA-04/05 do. A fix in #13 did that, after hiding those packages showed the tests failing.

## Tasks

| Task | What | Tests | Status | PR |
|---|---|---|---|---|
| R3-T1 | Normaliser: Tetragon JSON → §4.3 events (Eq. 50), namespace filter, drop counts | PH4-01, PH4-02a, PH4-02b | Done, and checked on real Tetragon 1.7.1 output (no unexplained drops). Runtime steps dropped: runc init, kind's hook (#20) | [#11](https://github.com/Krittakorn-Saetia/Provbind/pull/11) |
| R3-T2 | TracingPolicies: write on all paths, truncate, `cap_capable`, executable mmap, `tcp_connect`; Helm export filter | PH4-02a, PH4-02b; MLA-03 (Role 1) | Write, truncate and cap load and fire on the demo VM (as cluster-wide copies, see findings). Load and connect not yet applied | [#11](https://github.com/Krittakorn-Saetia/Provbind/pull/11) |
| R3-T3 | Envelope and bindings store: reload on change, J_I, one cached envelope per digest (Eq. 52) | PH4-04 | Done in the cloud; the live scale test is written (integration) | [#12](https://github.com/Krittakorn-Saetia/Provbind/pull/12) |
| R3-T4 | Verifier: decision order, mount exclusion, binding failures, detection records (§4.4) | PH4-03, PH4-05 to 18 | Done in the cloud | [#12](https://github.com/Krittakorn-Saetia/Provbind/pull/12) |
| R3-T5 | `python -m node.run`: live and replay, `events.jsonl` and `detections.jsonl`, cold-start holding | PH2-10 | Done in the cloud; windows appear in the summary. PH2-10's test file was added by Role 2 (Q2) | [#12](https://github.com/Krittakorn-Saetia/Provbind/pull/12) |
| R3-T6 | Replay harness: a recording plus `ground_truth.csv` → results per scenario; the synthetic §7 library | PH4-* | Done | [#12](https://github.com/Krittakorn-Saetia/Provbind/pull/12) |
| R3-T7 | ML-B: gate, windows, Ψ_I, per-image Isolation Forest (as JSON, no pickle), g_I, θ_A, D_beh; range guard; D2 tooling (`python -m node.mlb`, `ml/data/mlb/`) | MLB-01 to 06 | Done. Trained on real D2 (#22); MLB-01 to 05 pass on the demo VM | [#13](https://github.com/Krittakorn-Saetia/Provbind/pull/13) |
| R3-T8 | Cuckoo filter on the event path, on and off (`--cuckoo`); a full filter is dropped loudly (CF-06's concern) | CF-05; CF-01 (the node's filter holds every declared path: unit test) | Done in the cloud. Synthetic: the filter doubles the per-event latency, so the §6.3 rule says drop | [#14](https://github.com/Krittakorn-Saetia/Provbind/pull/14) |
| R3-T9 | Runtime hashing of executed files. The pipeline already takes a `hasher` | PH4-07, 08, 18; the symlink gap (findings) | To do. **No longer only a stretch:** it is the only way to close the symlink gap found on the VM | |
| Demo PC | Load the policies, record `node/testdata/raw.jsonl` and a scenario session, run the live tests | All PH4 on real evidence; OH-02, OH-03 | Done on the demo VM, 1 October: see "Results on the demo VM". `raw.jsonl` recorded (not committed: host details) | |

## Results on the demo VM (1 October)

**Setup.**
- VirtualBox VM: kernel 6.14, cgroup v2 with the systemd driver; kind v1.37 with Tetragon 1.7.1.
- Image: the demo app `sha256:4ce219578835…`, signed with the team key. Capability list: ML-A or the curated allowlist, not yet confirmed (see `node/handoff/ROLE3-VM-TO-ROLE2.md` §2).
- Node code: #20. Policies: `write`, `truncate` and `cap`, as cluster-wide copies.
- Scenarios: 3 rounds of benign-1, attack-1, attack-2, ph4-14 and trust-1 (restored after each), 40 s apart, then tamper-1 (16 ground-truth rows).
- Recording: one session of 21 minutes, 2,967 events, with `node.run --mlb`.

| ID | Result | Evidence |
|---|---|---|
| PH4-01 | **fail (a finding)** | 15 exec events, 6 with a path that is not real: Tetragon reports `/usr/bin/sh`, a symlink to `dash`. See findings |
| PH4-02a | **pass** | exec 15, write 2,430, cap 508 in namespace `demo` |
| PH4-02b | **fail** | load 0, connect 0: `load.yaml` and `connect.yaml` were not applied (left off for the demo, as the handoff says) |
| PH4-05 | **pass** | D_exec / undeclared for `/tmp/.x9` in runs [1, 1, 1] |
| PH4-06 | **pass** | 6 benign runs: only the weak class (D_exec / outside_closure, Low) |
| PH4-12 | **pass** | D_write on `/etc/passwd` in runs [1, 1, 1] |
| PH4-14 | **pass** | 8 writes to `/tmp/new.txt`, 0 detections for it |
| PH4-17 | **pass** | 36 detections, 0 incomplete |
| PH4-03, 07 to 11, 13, 15, 16, 18 | not_run | No row in the ground truth: attack-3 to attack-9, benign-3 and benign-4 have no scenario scripts yet (Role 1) |
| MLB-01, 02 | **pass** | 30 contradicting events fed, none reached a window; windows identical over replays |
| MLB-03 | **pass** | IF_I on 261 windows; θ_A = 0.657 at the 99th percentile of 113 validation windows |
| MLB-04 | **pass** | Held-out FPR **0.0071** (1 of 140); the range guard added 0 |
| MLB-05 | **pass** | D_beh in every attack-2 run: **[3, 5, 5]**; 0 deterministic detections in attack-2 |
| MLB-06 | not_run | D2 for one image |
| CF-05 | **pass** | 2,967 real events, 5 replays per mode; detections identical with and without the filter |

**Other numbers.**
- **No false alarms on 9.5 h of benign load (D2):** 2,742 events, all conforming, 0 detections.
- **ML-B in the scenario run:** 13 of the 14 D_beh fall in attack-2 rows. The 14th is attack-1's payload (see findings). **0 D_beh in any benign row.**
- **D2's rate:** about 53 windows per hour. The app makes kernel events only on `/cache` requests (about 15% of `make loadgen`), so reaching 360 windows took 7 h, in two parts on one pod (#22).

## Tests (cloud results, before the demo VM)

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
| CF-01 | P0 | `test_cf_reference_example.py` (test kit, not Role 3's file) | not_run without an envelope | `PROVBIND_ENVELOPE=run/envelopes/<hex>.json`. The node builds the same reference filter; `node/tests/test_cuckoo_path.py` checks that it holds every declared path |
| CF-05 | P1 | `test_cf_05_event_path.py` | not_run. Synthetic: p50 4.4 µs without the filter, 8.8 µs with it; detections identical; decision **drop** | `PROVBIND_RECORDING` |
| PH2-10 | P1 | `test_ph2_10_cold_start.py` (Role 2, 29 Sep) | not_run. Synthetic, live `node.run` with the binding written 0.5 s late: one window of about 0.8 s, 0 events lost | `PROVBIND_NODE_SUMMARY` (a `node.run --summary` file from a run that deployed a pod) |
| MLA-07 | P1 | `test_mla_07_dcap_per_method.py` (Role 2, 29 Sep) | not_run. The synthetic benign rows have no capability events, so both envelopes give 0 D_cap | `PROVBIND_RECORDING` with `cap.yaml`, plus `PROVBIND_MLA07_ENVELOPES="<ML-A>,<allowlist>"` |
| OH-01 | P1 | `test_oh_node_cost.py` (Role 2, 29 Sep) | not_run. About 6,500 synthetic events: p50 about 5 µs, p99 about 18 µs | `PROVBIND_RECORDING` with 100,000 events or more |
| OH-02 | P1 | `test_oh_node_cost.py` | not_run. `node.run --replay`'s CPU seconds and peak memory | `PROVBIND_RECORDING`, plus `PROVBIND_TETRAGON_CPU_S` and `PROVBIND_TETRAGON_RSS_KB` from Tetragon alone under the same load |
| OH-03 | P1 | `test_oh_node_cost.py` | not_run. A synthetic storm of 10,000 execs: all reach the node (no ring buffer involved) | `PROVBIND_OH03_STORM` (a recording of the storm) |
| OH-06 | P2 | `test_oh_node_cost.py` | not_run. Synthetic replicas of one image: hit rate 1.0 at 1, 10 and 50 | `PROVBIND_OH06_SUMMARIES` (three `node.run --summary` files from the scale test) |
| All other R3 IDs | | not written yet | | |

A simulated demo-PC run (the synthetic library written out as a recording, a run folder and a `ground_truth.csv`) gave:
- **pass:** PH4-03, 05, 06, 09 to 15;
- **blocked:** PH4-07, 08 and 18 (no hash source), and PH4-16 until an egress list is given; with one, PH4-16 passes.

With synthetic D2 written to a D2 folder as well, MLB-01 to 05 passed, the model was written beside the envelope, and MLB-06 stayed not_run (one image).

## Questions for the team

- **Q1. Contract fields for cap and connect events.** `events.jsonl` (§4.3) has no field for a capability or a destination.
  - What happens now: these events are verified in memory but not written. A replay of `events.jsonl` therefore has no D_cap or D_net, and no ML-B features that count them.
  - Proposal: cap events get `cap` and `granted`; connect events get `daddr`, `dport` and `protocol`. Readers ignore unknown fields, so adding them is cheap (Sprint Handoff §4), but it is a contract change, so it needs the team.
- **Q2. Files outside this session's scope.** *Answered 29 September: Role 2 added `node/tests` to `testpaths` (#11) and wrote the six test files (#14); see `docs/ROLE3-FIXES-2026-09-29.md`.*
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

## Demo-VM findings (30 September and 1 October)

- **kind's OCI hook scored as the app.** At every pod start runc runs `/kind/bin/mount-product-files.sh` inside the new container; it and its children (`mount`, `jq`, `cp`) use `CAP_SYS_ADMIN`. One demo-app start gave 182 detections (176 D_cap, 6 D_exec), none from the app. The normaliser now drops the hook and its descendants (`drop:runtime_hook`), matched by a `/kind/bin` script, a runtime parent and a host task cwd. The profiling labels (`testbed/profiling`, Role 1) may need the same rule: they use `is_runtime_init` only.
- **Namespaced policies loaded but never fired** (NPOST 0) on a VirtualBox VM with kernel 6.14, cgroup v2 and the systemd driver: Tetragon's policy filter logged `failed to find cgroup id`. `cgidmap` (CRI) made it worse: no pod on any event. Workaround used: the same policies as cluster-wide `TracingPolicy`; the export allow list and the normaliser still keep only `demo`. Role 1's VM (kernel 7.0) did not need it.

- **Tetragon reports the path a program was started with, not the real file (PH4-01).** In the demo image `/usr/bin/sh` is a symlink to `dash`; every `sh` exec arrives as `/usr/bin/sh`. Tetragon 1.7.1's exec event has no other path field (no `binary_properties`).
  - Detections are still right: the node resolves runtime paths through the envelope's `symlinks` (`compiler.paths.realpath`), so `sh` became `dash`, declared, and scored outside_closure (Low), not undeclared.
  - **The gap:** the node resolves symlinks as they were in the image, not as they are in the container now. A symlink repointed at runtime (for example `/usr/bin/sh` → `/tmp/evil`, then run `sh`) is resolved to `dash` and scores Low. Writes do not catch it: making a symlink is not a write, and no policy hooks symlink, rename or unlink. Runtime hashing (R3-T9) closes it, because the executed file's hash would not be dash's.
  - Proposed for the Test Plan's update log (§10), for the team to decide: "Tetragon reports the exec path as invoked, symlinks unresolved; PH4-01's real-path check fails by design. The node canonicalises through the image's symlinks; a runtime-repointed symlink is undetected until R3-T9." `CLAUDE.md`'s rule about real paths holds for the envelope's keys, not for Tetragon's events.
- **A D_beh can fall after its scenario's row.** attack-1's payload `/tmp/.x9` keeps running after the row ends; its window closed 30 s later and scored D_beh (0.663 > θ_A) outside every row. It is malicious, not a false positive. Role 4's chains should join it to attack-1 by `pid` and `time`, not by row.

## Blockers

- **No Tetragon or cluster in the cloud.** Every live test (marked `integration`) and every scenario result needs the demo PC. That was expected.
- **Real Tetragon output is recorded but not committed.** `node/testdata/raw.jsonl` exists on the demo VM; it holds host details (cwd paths, node names), so it needs a review before it goes into the repository.
- **Scenario scripts for attack-3 to attack-9, benign-3 and benign-4 (Role 1).** Without them, 11 PH4 IDs stay not_run.
- **No runtime hash source (C3).** D_hash never fires on a raw recording, so PH4-07, 08 and 18 record `blocked`. R3-T9 is the stretch fix: hashing `/proc/<pid>/exe`, after checking Tetragon's PID namespace in kind.

## Next steps

1. **Merge #20, then #21, then #22**, then this PR.
2. **R3-T9, runtime hashing.** Check Tetragon's PID namespace in kind first, then hash `/proc/<pid>/exe` through the pipeline's `hasher` hook. That unblocks PH4-07, 08 and 18 and closes the symlink gap.
3. **PH4-02b:** apply `load.yaml` and `connect.yaml` (cluster-wide copies) for a short recording, then remove them again; they change ML-B's input.
4. **Role 1:** scenario scripts for attack-3 to attack-9, benign-3 and benign-4; then rerun the PH4 tests on a new recording.
5. **PH4-04 (integration) and OH-01 to 03** on the demo VM: OH-01 needs a recording of 100,000 events or more.
6. **Decide (team):** the PH4-01 proposal for the update log; the namespaced-policy workaround (does Role 1's VM need it too?).
6. ~~If Q2 is allowed: test files for PH2-10, MLA-07 and OH-01 to 03, OH-06.~~ Done by Role 2 on 29 September at Korn's request, together with Q2's `testpaths` (see `docs/ROLE3-FIXES-2026-09-29.md`).
