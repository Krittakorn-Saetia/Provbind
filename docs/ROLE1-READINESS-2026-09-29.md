# Is PROVBIND ready to execute? Role 1's check, 29 September 2026

**Verdict: the code is ready; the project is not yet executable from `main`.** Every role's code merges
cleanly and passes its tests together, and the data path between roles works end to end. What stands
between us and the demo PC run is merging the open PRs, the signing key, and about 9 hours of data
collection that has to be scheduled now.

## 1. What was checked (cloud session, no cluster)

| Check | Result |
|---|---|
| `main` + Role 3's PRs #11–#15 + Role 4's #17 + Role 1's #16 merged | **No conflicts** |
| `pytest -m "not integration"` on that merge (full `requirements.txt`) | **1053 passed, 0 failed** (32 integration tests need the cluster) |
| Every Makefile target (26), with Role 4's additions | `make -n` passes |
| Role 3-shaped detections → Role 4's `alerts.run` → Role 1's `compare.py` and E2E-01 | Scores **90 and 72, one chain**; table and E2E-01 correct |
| `tamper.sh` → Role 4's `verify_log` → E2E-12 | Breaks at exactly the edited record (hash mismatch, not a parse error); E2E-12 pass |
| `trust2.sh` → Role 4's `alerts.trust set-key` | `keystatus.json` in the trust loop's format; `RESTORE=1` undoes it |
| Formats Role 1 depends on (alerts, trust alerts, `verify_log.Result`, bindings, advisories) | All match Role 4's code |
| Role 1's `cap_capable` parser vs Role 3's `node/tetragon/cap.yaml` | Same event shape (Korn checked; confirmed) |

## 2. Blockers, in order

1. **Merge the open PRs into `main`.** `main` has only Role 2's work: no `node/` runtime, `controller/` or
   `alerts/`, so nothing runs end to end from it. The order tested here: #11 → #14 (Role 3's stack; #14
   contains the others), #15, #17, #16. #17 already contains an older copy of #16; merging #16 after it
   brings in Role 1's fixes of 29 September without conflicts.
2. **The signing key.** Korn sends `cosign.key` and its password privately. Key at `pipeline/keys/cosign.key`
   (git ignores it); **never commit or paste it**. `export COSIGN_PASSWORD` before building **and** before
   `make profile`, or cosign waits at a hidden prompt.
3. **Nothing has run on a real cluster yet.** Unverified until the demo PC: Tetragon's real event shapes
   (`node/testdata/raw.jsonl`), the export container name `export-stdout`, the Helm value names, Falco
   with the modern eBPF driver, and Neo4j (PH3-10/11 were tested only against a fake driver).
   On a kernel older than 6.2, remove `security_file_truncate` from `node/tetragon/truncate.yaml`.

## 3. Demo PC run order

Long runs dominate: profiling ≈ 2.5 h and D2 ≥ 6 h. Start them first.

| # | Step | Command | Time |
|---|---|---|---|
| 0 | Pull merged `main`; install everything | `git pull`; `pip install -r requirements.txt` | |
| 1 | Cluster, Tetragon (Role 3's values and policies), Falco, Neo4j | `make up` | 15 min |
| 2 | 5 min of real Tetragon output, replayed (Role 3 §3) | see `node/handoff/ROLE3-TO-ROLE1.md` §3 | 10 min |
| 3 | Build, sign, compile stand-in and demo app; Role 2's checks; send both envelope paths to Role 3 | `docs/ROLE2-HANDOFF-TO-ROLE1.md` §5.2 | 30 min |
| 4 | **ML-A profiling (MLA-03), with controller, alerts and node stopped** | `make profile` | ≈ 2.5 h |
| 5 | D1 and ML-A: compile the corpus with `--features-out`, `ml.dataset`, `ml.train`; then **recompile the demo envelope** so it carries ML-A capabilities | Role 2 handoff §6.3 | 30 min |
| 6 | Start the pipeline | `make controller`, `make alerts`, `make trust-loop`, node with `tee $PROVBIND_RUN/rec.jsonl`, `eval/capture_falco.sh &` | |
| 7 | **D2 first benign run: 4 h**, nothing else touching the pod | `make loadgen` (while Role 3's recording runs) | 4 h |
| 8 | Wait ≥ 1 h, then the **held-out hour** | `DURATION=3600 make loadgen` | 2 h |
| 9 | Build ML-B windows and train (`node.mlb windows/split/train`), restart the node with `--mlb` | `ml/data/mlb/README.md` | 20 min |
| 10 | Scenarios, **each at least 3 times** (D4) | `make benign`, `make attack`, `make attack2`, `make ph4-14`, `make trust` then `RESTORE=1 make trust`, `make trust2` then `RESTORE=1 make trust2` | 1 h |
| 11 | **Tamper last**: it breaks the log for every later alert | `make tamper`; afterwards restore `log/violations.jsonl.orig` | |
| 12 | Judge and report, always with the real inputs set | capability tests with `PROVBIND_ENVELOPE`, `PROVBIND_SBOM`, `PROVBIND_RECORDING`, `PROVBIND_EGRESS`; `make compare`; `make report` | |

**Run-order rules that matter:**
- **Profiling needs the controller, alerts and node stopped:** its pods run in `demo`, which they watch.
- **Without step 5, envelopes have `"capabilities": []`,** so every capability the app uses is a D_cap,
  benign-1 included. Record it if you skip step 5; don't hide it.
- **Nothing else in the demo pod during a scenario or D2.** Triggers now go through `kubectl port-forward`,
  so they add no events of their own; a hand-typed `kubectl exec` still would.
- **After a pod restart, wait ≥ 30 s before attack-2:** ML-B ignores processes younger than 10 s.
- **Rerunning tests without the environment variables overwrites real results with synthetic `not_run`.**

## 4. What will look wrong but is expected

- **D_hash never fires** (no runtime hash source, C3): attack-3 shows `D_exec / undeclared`, and
  PH4-07/08/18 stay `blocked`.
- **`events.jsonl` has no cap or connect events** (Role 3's Q1).
- **PH1-03 is `blocked` offline** (`PROVBIND_OFFLINE=1`): no transparency record by design.
- **Profiled corpus images have `source_commit: null`:** they were re-tagged, not built by us.

## 5. Open team decisions (not code)

The log key's location; `allowed_caps` in `bindings.json` (where Eq. 34's cap is applied); Role 3's
Q1, Q6 and Q8–Q10; the trust score of 70. Role 1's answer to Role 3's Q3: **profile in `demo`**; Q9: **yes,
`make loadgen` runs for any `DURATION`**.

## 6. The Datadog dataset (D6)

| Use | Ready? |
|---|---|
| **Behaviour references** for our harmless scenarios, named in `testbed/behaviours.md` | Template ready; the "modelled on" column is filled after reading 5–10 samples **in a dedicated VM** (§12.4) |
| **`manifest.json` as a list of malicious packages** for the trust tests (PH6-04/05) | Not wired in: Role 4's ComponentCheck reads OSV files in `run/advisories/` and withdraws trust only for `MAL-` IDs. A small converter (manifest → OSV) is possible once the team agrees an ID convention for Datadog entries |

Rules, from Test Plan §12.4 and CLAUDE.md: never install, import or run a sample; read samples only in a
dedicated VM, `noexec`, networking off; never put a sample in an image, the registry, the demo PC or this
repository; tell Aj Ohm and follow SIIT policy. Nothing was downloaded in this session.

**A gap the dataset exposes:** credential-file reads, one of §12.4's behaviours, have no deterministic
hook (PROVBIND hooks exec, write, exec-mmap, capability and connect). Add a read hook for a few protected
paths, or state the limit in the paper.

## 7. Role 1 status after today

| Item | Status |
|---|---|
| trust-2 script (P0) | **Done** (`make trust2`) |
| MLA-03 test (P0) | **Done** (`tests/capability/test_mla_03_labels.py`) |
| Demo app pinned to the stand-in's base (both `FROM` lines) | **Done** |
| `profile_corpus.sh` stops hiding errors | **Done**, plus five hidden bugs fixed (commit message of `a8e5152`) |
| D2 load generator | **Done** (`make loadgen`), with the app's own benign cache writes (`/cache`) |
| ph4-14 row for Role 3 | **Done** (`make ph4-14`) |
| `testbed/behaviours.md` (§12.4) | Template done; samples to be read in the VM |
| P1: `/update3`–`/update9`, attack-9, benign-2 to 6, E2E-04 to 10, EV-02, EV-03, EV-07 | Not started |
