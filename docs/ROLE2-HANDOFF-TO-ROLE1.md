# Handoff from Role 2 to Role 1: running Role 2's part on the demo PC, and Role 1 against the test plan

**From:** Role 2 (Korn) · **For:** Role 1 (testbed and evaluation) · **Date:** 29 September 2026

**Checked against:** the *Capability Test Plan* v1.1 (`docs/PROVBIND-Capability-Test-Plan.md`), `main` at `bddcced`, and your PR #16 (`6bd783f`), alone and merged with Role 3's PRs #14 and #15.

**How it was checked:** on Korn-PC, under WSL2 Ubuntu 22.04 with Python 3.11.16, in throwaway checkouts. Nothing was changed in your code.

---

## 1. The short version

- **PR #16 works.**
  - On its own: **461 tests pass, 0 fail.**
  - Merged with Role 3's PRs: 485 pass. The only failure is in Role 3's code, not yours.
  - All 12 shell scripts parse, and every script the Makefile runs is executable.
  - All 16 Makefile targets pass `make -n`. `make help`, `make report` and `make corpus-check` run correctly.
- **You now have real numbers for CF-02, CF-03 and CF-04,** measured on the real stand-in envelope (§3.2).
- **The demo PC run is on your machine.** Section 5 is Role 2's part of it, step by step: building, signing and compiling the stand-in and demo images.
- **Gaps against the plan:**
  - MLA-03 (P0) has no test.
  - The **trust-2** scenario (P0) has no script.
  - The demo app implements 2 of its 9 scenario endpoints.
  - 5 of the plan's 19 scenarios have scripts.
  - P1 tests E2E-04 to 10, EV-02, EV-03 and EV-07 have no test files.
  - `testbed/behaviours.md` (plan §12.4) doesn't exist yet.
- **Know these two things before you run anything** (§5.3):
  - the envelopes Role 2 compiles have **no capabilities**, so any capability the app uses shows up as D_cap;
  - the envelope's **Rekor log index is null** with cosign v3, a Role 2 bug with a fix pending.

---

## 2. What was checked, and the results

| Check | Result |
|---|---|
| PR #16 alone, `pytest -q -m "not integration"` | 461 passed |
| `main` + #14 + #15 + #16 merged | No conflicts. 485 passed, 1 failed (Role 3's live-mode test, not yours) |
| Python files compile | All of them |
| `bash -n` on all 12 shell scripts | All parse |
| Scripts the Makefile runs with `./` | All executable in git (mode 100755) |
| `make -n` on all 16 targets | All ok |
| `make help`, `make corpus-check`, `make report` | Run correctly |
| `make compare` with an empty run folder | Stops with "no ground-truth rows", which is correct |
| `ml/corpus.yaml` | 24 images, including `standin-app` and `demo-app` (plan §4.1 asks for at least 20) |
| Profiling pods (`profile_corpus.sh`) | Plain `kubectl run`, so default pods. That matches what ML-A assumes (§6). |
| Your `cap_capable` parser against Role 3's `node/tetragon/cap.yaml` | Same shape: `function_name`, `capability_arg`, `return.int_arg`. The policy is in namespace `demo`, where you profile. |
| Registry | `kind-with-registry.sh` uses `localhost:5001`, the same as `pipeline/build-and-attest.sh` |

---

## 3. Role 1's tests against the test plan

### 3.1 Status of every Role 1 test ID

Statuses are from a run of all merged PRs, with `PROVBIND_ENVELOPE` set to the real stand-in envelope:

| ID | P | Test file | Status | What it needs |
|---|---|---|---|---|
| MLA-03 | P0 | **none** | not_run | `ml/data/labels.jsonl` from the profiling run. Suggested test: at least 20 rows, one per digest, labels only from `ml.alg1.ALL_CAPS`, and `run_disagreement` recorded. |
| E2E-01 | P0 | yes | not_run | Demo-PC run of attack-1: `alerts.jsonl`, `falco.jsonl`, `ground_truth.csv` |
| E2E-02 | P0 | yes | not_run | Demo-PC run of benign-1. Read §5.3 first: the missing capabilities can put D_cap detections into a benign run. |
| E2E-03 | P0 | yes | not_run | Demo-PC run of attack-2 (with ML-B trained, D2) |
| E2E-11 | P0 | yes | not_run | Demo-PC run of trust-1 |
| E2E-12 | P0 | yes | not_run | Demo-PC run of tamper-1 (`log/violations.jsonl`, `verify_log`) |
| EV-01 | P0 | yes | not_run | Every E2E scenario run, plus Falco capture |
| CF-02 | P1 | yes (in the kit's `test_cf_reference_example.py`) | **pass** | Real numbers in §3.2. The plan wants them on the demo envelope, so rerun with `PROVBIND_ENVELOPE=<demo envelope>`. |
| CF-03 | P1 | yes | **pass** | Same: rerun on the demo envelope |
| CF-04 | P1 | yes | **pass** | Same |
| CF-06 | P1 | yes | **pass** | A property of the reference filter; no envelope needed |
| E2E-04 to E2E-10 | P1 | **none** | not_run | Scenario endpoints `/update4` to `/update9` return 501; attack-9 has no script |
| EV-02 | P1 | **none** | not_run | benign-2 to benign-6 (no scripts yet) |
| EV-03 | P1 | **none** | not_run | Ablation runs |
| EV-07 | P1 | **none** | not_run | ML-C: its own code, data (`eval/mlc/data/`, dataset D3) and model. Nothing exists yet. |
| EV-04, EV-05, EV-06 | P2 | none | not_run | After the presentation (plan §11) |

### 3.2 First real numbers: the Cuckoo filter on the stand-in envelope

Measured on Korn-PC with the real stand-in envelope (5,725 paths) and the reference filter (`node/ref_cuckoo.py`). The laptop numbers are indicative only (plan §3.12).

| Test | Result |
|---|---|
| CF-01 (Role 3) | 5,725 paths, **0 false negatives** |
| CF-02 | False-positive rate **2.16%** at 8 bits (theory 3.13%); **0.0083%** at 16 bits (theory 0.0122%). Both are under theory. |
| CF-03 | Filter **16 KB**, set container **512 KB**, dict container 203 KB. The path strings (576 KB) exist anyway. |
| CF-04 | Filter **2.6 µs** per hit and **2.9 µs** per miss, against **91 ns and 74 ns** for a set: about 30× slower per lookup |
| CF-06 | 2,048 slots; the first failed insert, at 2,000 items (load 0.977), is reported, and there's no silent loss |

This matches the plan's prediction (§6.2): the filter saves memory but costs lookup time. CF-05 (Role 3) decides whether to keep it.

---

## 4. Scenario library (plan §7) against what exists

| Scenario | P | Trigger | Demo-app endpoint | Script | Status |
|---|---|---|---|---|---|
| attack-1 | P0 | `curl /update` | implemented | `attack.sh` | ready |
| attack-2 | P0 | `curl /update2` | implemented | `attack2.sh` | ready |
| trust-1 | P0 | edit the advisory file | — | `trust.sh` | ready |
| **trust-2** | **P0** | edit `run/keystatus.json` (key revoked) | — | **none** | **missing, and needed for PH6-02** |
| tamper-1 | P0 | edit one character in the violation log | — | `tamper.sh` | ready |
| benign-1 | P0 | 3 `curl` calls, then `kubectl exec … sh -c 'ls /; cat /etc/hostname'` | — | `benign.sh` | ready |
| attack-2b | P1 | `curl /update3` | returns 501 | none | not started |
| attack-3 to attack-7 | P1 | `curl /update4` to `/update8` | return 501 | none | not started |
| attack-8 | P1 | build step writes `/usr/local/bin/helperd`, then `/update9` | returns 501 | none | not started |
| attack-9 | P1 | deploy an unsigned image | — | none | not started |
| benign-2 to benign-6 | P1 | see plan §7 | — | none | not started |

**Two plan rules to keep in mind:**
- **Dataset D4:** every scenario is run **at least 3 times**, with one ground-truth row per run.
- **§12.4:** describe the real-sample behaviours each scenario re-creates in `testbed/behaviours.md`. That file doesn't exist yet.

---

## 5. Running Role 2's part on the demo PC

### 5.1 What the demo PC needs

- **Tools.** Record each version in `testbed/VERSIONS.md` (Korn-PC's column is already filled in):
  - Docker with buildx;
  - kind, kubectl and helm;
  - crane, cosign (v2.6+ or v3.x), syft and jq;
  - Python 3.11.
- **Python packages.** Install the whole `requirements.txt`, not only `requirements-role2.txt`. Role 3's tests need PyYAML, and ML-A needs numpy, scikit-learn and LightGBM.
- **The signing key.** Signing must use the team key, because everything verifies against the committed `pipeline/keys/cosign.pub`.
  - Korn will send you `cosign.key` and its password **privately**, in separate messages.
  - Put the key at `pipeline/keys/cosign.key`. Git already ignores it.
  - **Never commit it, and never paste the key or the password into Claude.**
  - Profiling needs the key too: `profile_corpus.sh` re-tags and attests each corpus image.

### 5.2 Steps, in order

```bash
# 0. Once: the cluster and the local registry at localhost:5001
make up

# 1. Pin the base image (Role 1's handoff asks for this; the stand-in isn't pinned either).
crane digest python:3.11-slim            # -> sha256:...
#    In testbed/demo-app/Dockerfile replace BOTH "FROM python:3.11-slim" lines, and in
#    testbed/standin-app/Dockerfile the one line, with python:3.11-slim@sha256:<that digest>.
#    Commit before building: an uncommitted change makes the provenance record
#    uncommittedChanges = true.

# 2. The key password, typed so it stays out of your shell history
read -rsp 'cosign key password: ' COSIGN_PASSWORD && echo && export COSIGN_PASSWORD

# 3. Build, push, sign and attest (each prints the image's ref@digest)
STANDIN_REF=$(pipeline/build-and-attest.sh testbed/standin-app standin-app) && echo "$STANDIN_REF"
DEMO_REF=$(pipeline/build-and-attest.sh testbed/demo-app demo-app) && echo "$DEMO_REF"

# 4. Compile the envelopes (each prints run/envelopes/<hex>.json)
python -m compiler.compile "$STANDIN_REF" --run ./run
python -m compiler.compile "$DEMO_REF" --run ./run

# 5. Check Role 2's part
PROVBIND_STANDIN_REF="$STANDIN_REF" pytest -q -m integration     # Role 2's 13 must pass; Role 3's cluster tests run too
PROVBIND_ENVELOPE=run/envelopes/<standin hex>.json pytest -q \
  tests/capability/test_ph3_04_depth.py tests/capability/test_ph3_07_closure.py
PROVBIND_ENVELOPE=run/envelopes/<demo hex>.json pytest -q \
  tests/capability/test_ph3_08_origins.py tests/capability/test_ph3_09_indices.py \
  tests/capability/test_mla_02_features.py \
  tests/capability/test_cf_reference_example.py tests/capability/test_cf_03_memory.py tests/capability/test_cf_04_lookup.py
python -m eval.report --run ./run
```

**Notes on these steps:**

- **Signing online or offline.** Signing is online by default: it uploads to Sigstore's public Rekor log, which is fine for these test images. Without internet, set `PROVBIND_OFFLINE=1` for **both** the build and the compile, and tell the team the demo skips transparency.
- **Run PH3-04 on the stand-in only.** It checks `requests` at depth 1 and `urllib3` at depth 2, and the demo app has neither: its `requirements.txt` is comments only, and `requestz-helper` has no dependencies. On the demo envelope, PH3-04 would fail by design.
- **Each test overwrites its own result file,** so the table's last run wins. The commands above record PH3-04 and PH3-07 from the stand-in, and the rest from the demo image.
- **`test_debug_sbom_has_dependency_edges` reads the SBOM copy the build left in `run/attest/`.** Run the integration tests on the machine that built the images, with the same run folder.
- **Send both envelope paths to Role 3,** and use them for `PROVBIND_ENVELOPE` in your own CF tests.

### 5.3 What to expect

- **Both envelopes will have `"capabilities": []`.**
  - Why: the curated allowlist only covers gunicorn, uvicorn and iputils-ping, and both apps expose port 8080, which is above 1024.
  - The node treats an empty list as "no capability allowed", so any capability the app actually uses becomes a D_cap detection. That can happen in benign-1 too.
  - That comes from the allowlist, not from the verifier; MLA-07 measures exactly this. Record what happens, don't hide it.
  - ML-A replaces the allowlist once D1 exists and a model is trained (§6).
- **`rekor_log_index` will be null,** even when signing is online. With cosign v3, `cosign verify` no longer prints the log entry. The details and the fix are on branch `local/rekor-bug`, and the fix is pending. Until it's in, don't claim the transparency link (PH1-03).
- **New digests.** Rebuilding on the demo PC gives new digests. Korn-PC's stand-in (`sha256:0a6bfbb0…`) won't exist there, so use the new references everywhere: `PROVBIND_STANDIN_REF`, the corpus, the bindings.
- **Two-stage Dockerfile.** The demo app has two stages, and `gen_provenance.py` records the *first* `FROM` as the base image (the builder stage). That's harmless here because both stages use the same base, but only if both lines are pinned to the **same** digest.
- **`unresolved_fraction` will be about 0.2.** Half of it comes from 14 Windows launcher programs inside pip and setuptools, which syft lists without a package URL. No effect on your tests.
- **Expected compile time is about 8 s per image.** On Korn-PC the stand-in took 8.0 s and produced a 1.4 MB envelope.

---

## 6. ML-A dataset D1 (MLA-03 → Role 2's T13 step 3)

- **Your `labels.jsonl` format works for Role 2** as described in your handoff: one row per image, keyed by digest.
- **Keep profiling in default pods** (plain `kubectl run`, as now) for all 24 images.
  - The compiler computes ML-A's features for a default pod, so the labels must come from default pods too, or training and use won't match.
  - If an image needs a non-default pod, record its `securityContext` in that image's `meta.json`.
- **Role 2 fills in `allowed` at the join.** Role 2's training data needs the pod's allowed set for each row. For default pods, that's the runtime's 14 default capabilities, which Role 2 will add, so nothing changes on your side.
- **Role 2 still owes the feature half.** It's a `--features-out` flag on the compiler that writes each image's features while the image is open. Until it exists, `ml/data/dataset.jsonl` can't be built.
- **Record every image's digest,** as the plan asks (§12.2). The stand-in and the demo app are in the corpus, and their digests will be the demo PC's.

---

## 7. What Role 2 still owes Role 1

| Item | Status |
|---|---|
| The Rekor log-index fix (`compiler/evidence.py`) | Pending with the cloud session; details on branch `local/rekor-bug` |
| `--features-out` for the ML-A feature join | Not started |
| Recorders for PH1-01, PH1-04 (P0), and PH3-12, OH-04, OH-05 (P1) | Not started. The underlying checks already pass in Role 2's integration tests. |
| An ML-A model, to replace the empty allowlist capabilities | After D1 exists |

---

## 8. Checklist

- [ ] Get `cosign.key` and its password from Korn privately; key at `pipeline/keys/cosign.key`
- [ ] `make up`; pin the base images; commit
- [ ] Build and compile the stand-in and the demo app (§5.2); send both envelope paths to Role 3
- [ ] Role 2's checks on the demo PC: 13 integration tests; PH3-04 and 07 (stand-in); PH3-08 and 09, MLA-02 (demo)
- [ ] Rerun CF-02, 03 and 04 on the demo envelope
- [ ] Write the **trust-2** script (P0)
- [ ] Add a test for **MLA-03** (P0)
- [ ] Profile the corpus in default pods; hand over `ml/data/labels.jsonl`
- [ ] Run every scenario at least 3 times (D4)
- [ ] `testbed/behaviours.md` (§12.4)
- [ ] P1 when time allows: `/update3` to `/update9`, attack-9, benign-2 to benign-6, E2E-04 to 10, EV-02, EV-03, EV-07
