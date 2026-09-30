# Role 3 status: node runtime (Phase 4)

**Updated 28 September 2026** by Claude Code (cloud). Scope: `node/`, `ml/data/mlb/`, and `tests/capability/test_ph4_*.py`, `test_cf_05_*.py` and `test_mlb_*.py`.

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

**Numbers**, with all four merged:
- `pytest -m "not integration"`: 417 passed, 17 deselected (`main` alone: 392 and 13). That includes 25 new capability tests; 4 more are integration.
- `pytest node/tests`: 319 unit tests, run inside PH4-17 until `testpaths` includes them (Q2).
- With `requirements-role2.txt` alone (no numpy, scikit-learn or LightGBM, as on Korn's PC): 365 passed, 4 skipped, 0 failed. The ML-B tests that train a model skip cleanly, as MLA-04/05 do. A fix in #13 did that, after hiding those packages showed the tests failing.

## Tasks

| Task | What | Tests | Status | PR |
|---|---|---|---|---|
| R3-T1 | Normaliser: Tetragon JSON → §4.3 events (Eq. 50), namespace filter, drop counts | PH4-01, PH4-02a, PH4-02b | Done in the cloud; field shapes from the Tetragon docs, to verify against a real recording | [#11](https://github.com/Krittakorn-Saetia/Provbind/pull/11) |
| R3-T2 | TracingPolicies: write on all paths, truncate, `cap_capable`, executable mmap, `tcp_connect`; Helm export filter | PH4-02a, PH4-02b; MLA-03 (Role 1) | Written and statically tested; not yet loaded into Tetragon | [#11](https://github.com/Krittakorn-Saetia/Provbind/pull/11) |
| R3-T3 | Envelope and bindings store: reload on change, J_I, one cached envelope per digest (Eq. 52) | PH4-04 | Done in the cloud; the live scale test is written (integration) | [#12](https://github.com/Krittakorn-Saetia/Provbind/pull/12) |
| R3-T4 | Verifier: decision order, mount exclusion, binding failures, detection records (§4.4) | PH4-03, PH4-05 to 18 | Done in the cloud | [#12](https://github.com/Krittakorn-Saetia/Provbind/pull/12) |
| R3-T5 | `python -m node.run`: live and replay, `events.jsonl` and `detections.jsonl`, cold-start holding | PH2-10 | Done in the cloud; windows appear in the summary. PH2-10's test file was added by Role 2 (Q2) | [#12](https://github.com/Krittakorn-Saetia/Provbind/pull/12) |
| R3-T6 | Replay harness: a recording plus `ground_truth.csv` → results per scenario; the synthetic §7 library | PH4-* | Done | [#12](https://github.com/Krittakorn-Saetia/Provbind/pull/12) |
| R3-T7 | ML-B: gate, windows, Ψ_I, per-image Isolation Forest (as JSON, no pickle), g_I, θ_A, D_beh; range guard; D2 tooling (`python -m node.mlb`, `ml/data/mlb/`) | MLB-01 to 06 | Done in the cloud. MLB-01 and 02 pass (code properties). MLB-03 to 06 need real D2 | [#13](https://github.com/Krittakorn-Saetia/Provbind/pull/13) |
| R3-T8 | Cuckoo filter on the event path, on and off (`--cuckoo`); a full filter is dropped loudly (CF-06's concern) | CF-05; CF-01 (the node's filter holds every declared path: unit test) | Done in the cloud. Synthetic: the filter doubles the per-event latency, so the §6.3 rule says drop | [#14](https://github.com/Krittakorn-Saetia/Provbind/pull/14) |
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

## Demo-VM findings (30 September)

- **kind's OCI hook scored as the app.** At every pod start runc runs `/kind/bin/mount-product-files.sh` inside the new container; it and its children (`mount`, `jq`, `cp`) use `CAP_SYS_ADMIN`. One demo-app start gave 182 detections (176 D_cap, 6 D_exec), none from the app. The normaliser now drops the hook and its descendants (`drop:runtime_hook`), matched by a `/kind/bin` script, a runtime parent and a host task cwd. The profiling labels (`testbed/profiling`, Role 1) may need the same rule: they use `is_runtime_init` only.
- **Namespaced policies loaded but never fired** (NPOST 0) on a VirtualBox VM with kernel 6.14, cgroup v2 and the systemd driver: Tetragon's policy filter logged `failed to find cgroup id`. `cgidmap` (CRI) made it worse: no pod on any event. Workaround used: the same policies as cluster-wide `TracingPolicy`; the export allow list and the normaliser still keep only `demo`. Role 1's VM (kernel 7.0) did not need it.

## Blockers

- **No Tetragon or cluster in the cloud.** Every live test (marked `integration`) and every scenario result needs the demo PC. That was expected.
- **No real Tetragon output in the repository yet.** Sprint Handoff §7, Day 1 asks for `node/testdata/raw.jsonl`. Until it exists, the normaliser's input shapes come from the Tetragon documentation, not from our version.
- **No D2 yet.** MLB-03 to 06 need the demo image's benign windows: 4 hours or more, plus an hour held out (Q9).
- **No runtime hash source (C3).** D_hash never fires on a raw recording, so PH4-07, 08 and 18 record `blocked`. R3-T9 is the stretch fix: hashing `/proc/<pid>/exe`, after checking Tetragon's PID namespace in kind.

## Next steps

1. **Merge #11 to #14 in order.** (`node/tests` is now in `pytest.ini`'s `testpaths`: Q2, done in #11.)
2. **Demo PC, Day 1 work:**
   - load `node/tetragon/values.yaml` and the policies;
   - save 5 minutes of output as `node/testdata/raw.jsonl`;
   - run `python -m node.run --replay node/testdata/raw.jsonl` and fix any field the normaliser drops (its summary counts drops by reason);
   - run `pytest -m integration tests/capability/test_ph4_01_02_events.py`.
3. **Demo PC, scenarios.** Record one session while Role 1's scenarios run (`node/README.md`, "Recipe on the demo PC"). Then run the PH4 tests and CF-05 with `PROVBIND_RECORDING`, and PH4-04 live.
4. **Demo PC, ML-B.** Build D2 (4 hours or more, plus a held-out hour: `ml/data/mlb/README.md`), then run the MLB tests.
5. **Stretch, R3-T9: runtime hashing.** Check Tetragon's PID namespace in kind first, then hash `/proc/<pid>/exe` through the pipeline's `hasher` hook. That unblocks PH4-07, 08 and 18.
6. ~~If Q2 is allowed: test files for PH2-10, MLA-07 and OH-01 to 03, OH-06.~~ Done by Role 2 on 29 September at Korn's request, together with Q2's `testpaths` (see `docs/ROLE3-FIXES-2026-09-29.md`).
