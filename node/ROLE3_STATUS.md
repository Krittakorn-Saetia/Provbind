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
| R3-T1 | Normaliser: Tetragon JSON → §4.3 events (Eq. 50), namespace filter, drop counts | PH4-01, PH4-02a, PH4-02b | Done in the cloud; field shapes from the Tetragon docs, to verify against a real recording | role3/normalize |
| R3-T2 | TracingPolicies: write on all paths, truncate, `cap_capable`, executable mmap, `tcp_connect`; Helm export filter | PH4-02a, PH4-02b; MLA-03 (Role 1) | Written and statically tested; not yet loaded into Tetragon | role3/normalize |
| R3-T3 | Envelope and bindings store: reload on change, J_I, one cached envelope per digest (Eq. 52) | PH4-04, OH-06 | To do | |
| R3-T4 | Verifier: decision order, mount exclusion, binding failures, detection records (§4.4) | PH4-03, PH4-05 to 18 | To do | |
| R3-T5 | `python -m node.run`: live and replay, `events.jsonl` and `detections.jsonl`, cold-start buffering | PH2-10, OH-01 | To do | |
| R3-T6 | Replay harness: a recording plus `ground_truth.csv` → per-scenario results | PH4-* | To do | |
| R3-T7 | ML-B: gate, windows, Ψ_I, per-image Isolation Forest, g_I, θ_A, D_beh; D2 tooling | MLB-01 to 06 | To do | |
| R3-T8 | Cuckoo filter on the event path, on and off | CF-05 (CF-01 runs in the test kit's example) | To do | |
| R3-T9 | Runtime hashing of executed files (stretch) | PH4-07 to 09 | To do | |
| Demo PC | Load the policies, record `node/testdata/raw.jsonl`, live runs, overhead | PH4-01/02 live, OH-02, OH-03 | Needs the demo PC | |

## Tests

"Cloud" is what `pytest -m "not integration"` records here. "Demo PC" is what turns a result into pass or fail.

| ID | P | File | Cloud result | Demo PC |
|---|---|---|---|---|
| PH4-01 | P0 | `test_ph4_01_02_events.py` | not_run (synthetic) | Live test (integration), or `PROVBIND_RECORDING` plus `PROVBIND_ENVELOPE` |
| PH4-02a | P0 | `test_ph4_01_02_events.py` | not_run (synthetic) | Live test, or a recording with `write.yaml` and `cap.yaml` applied |
| PH4-02b | P1 | `test_ph4_01_02_events.py` | not_run (synthetic) | Live test, or a recording with `load.yaml` and `connect.yaml` applied |
| PH2-10, MLA-07, OH-01, OH-02, OH-03, OH-06 | P1–P2 | none | none | These IDs' file names are outside this session's allowed files; see Q2 |
| All other R3 IDs | | not written yet | | |

## Questions for the team

- **Q1. Contract fields for cap and connect events.** `events.jsonl` (§4.3) has no field for a capability or a destination.
  - What happens now: these events are verified in memory but not written, so a replay of `events.jsonl` cannot reproduce D_cap, D_net or the ML-B features that count them.
  - Proposal: cap events get `cap` and `granted`; connect events get `daddr`, `dport` and `protocol`. Readers ignore unknown fields, so adding them is cheap (Sprint Handoff §4), but it is a contract change, so it needs the team.
- **Q2. Files outside this session's scope.**
  - `pytest.ini`'s `testpaths` does not include `node/tests`, so `pytest -q` from the root does not collect the node unit tests directly. The capability tests run them in a subprocess, as Role 2's PH3 tests do. Please add `node/tests` (a one-line change to a file this session may not edit).
  - Six R3 test IDs need files outside the allowed patterns: `test_ph2_10_*.py`, `test_mla_07_*.py` and `test_oh_*.py`. May a later session add them?
- **Q3. Profiling for MLA-03 (Role 1).** `cap.yaml` is namespaced to `demo`. Profile the ML-A corpus in `demo`, or copy the policy (and the export filter in `values.yaml`) to the corpus namespace.

## Blockers

- **No Tetragon or cluster in the cloud.** Every live test (marked `integration`) and every scenario result needs the demo PC. That was expected.
- **No real Tetragon output in the repository yet.** Sprint Handoff §7, Day 1 asks for `node/testdata/raw.jsonl`. Until it exists, the normaliser's input shapes come from the Tetragon documentation, not from our version.
