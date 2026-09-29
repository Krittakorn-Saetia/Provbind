# Handoff from Role 2 to Role 1: running Role 2's part on the demo PC, and Role 1 against the test plan

**From:** Role 2 (Korn) · **For:** Role 1 (testbed and evaluation) · **Date:** 29 September 2026, last updated after Role 2's fixes were merged into `main`

**Checked against:** the *Capability Test Plan* v1.1 (`docs/PROVBIND-Capability-Test-Plan.md`), `main` at `bddcced`, and your PR #16 (`6bd783f`), alone and merged with Role 3's PRs #14 and #15, on today's `main` with Role 2's fixes merged.

**How it was checked:** on Korn-PC, under WSL2 Ubuntu 22.04 with Python 3.11.16, in throwaway checkouts. Nothing was changed in your code.

**Update: Role 2's fixes and new tests for you are on `main`** (merged on 29 September; `main` at `98f9337`). Pull `main` before the demo PC run.

| Change | Merged in | What it changes for you |
|---|---|---|
| Re-tag mode in `gen_provenance.py` | `bd8ee6c` | Your `profile_corpus.sh` call to `gen_provenance.py` works now. Before, it failed silently (§6.1). |
| PH1-01 and PH1-04 tests | `cef222c` | New tests for PH1-01 and PH1-04 run with the integration tests (§5.2, step 5) |
| Role 2's P1 tests | `cef222c` | PH1-02, PH1-03, PH2-06, PH2-07, PH3-03, PH3-05, PH3-12, OH-04 and OH-05 (§5.2, step 5) |
| Stand-in base image pinned | `b5ca0b1` | The stand-in's base image is pinned. Use the same digest for the demo app (§5.2, step 1). |
| Offline signing on cosign v3 | `ee0a153` | `PROVBIND_OFFLINE=1` works with cosign v3 now. Before, an offline build failed at `cosign sign` (§5.2, notes). |
| Evidence fixes | `9b39599` | The envelope records the Rekor log index again, so PH1-03 passes. The compiler now refuses an image that was attested but never signed (§5.3). |
| Dataset D1 code | `27fb90e` | The feature half of dataset D1: `--features-out` on the compiler, and `python -m ml.dataset` to join it to your labels (§6.3) |
| Packages without a purl left out | `8055b1a` | `unresolved_fraction` drops from about 0.2 to about 0.1 (§5.3) |
| T2 SBOM-edges test | `684fd90` | The T2 test that checks the SBOM's dependency edges no longer needs the build's run folder (§5.2, notes) |
| Build script executable again | `98f9337` | The offline-signing change had dropped `pipeline/build-and-attest.sh`'s executable bit, so `make demo-app` would have stopped with "Permission denied". A test now guards it. |

Your PR #16 and Role 3's PRs still merge cleanly onto this `main`: 574 unit tests pass, and the only failure is Role 3's (§2).

---

## 1. The short version

- **PR #16 works.**
  - On its own: **461 tests pass, 0 fail.**
  - Merged with Role 3's PRs: 485 pass. On today's `main`, with Role 2's fixes: 574 pass. The only failure is in Role 3's code, not yours.
  - All 12 shell scripts parse, and every script the Makefile runs is executable.
  - All 16 Makefile targets pass `make -n`. `make help`, `make report` and `make corpus-check` run correctly.
- **You now have real numbers for CF-02, CF-03 and CF-04,** measured on the real stand-in envelope (§3.2).
- **A Role 2 bug would have silently broken your ML-A profiling.** Every corpus image would have been left without signed provenance, and the compiler rejects such an image.
  - It's fixed on `main` (a re-tag mode in `gen_provenance.py`).
  - Your script still hides errors like this one, though. Please change that (§6.1).
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
  - the compiler now **refuses an image that was attested but never signed** (exit 2). Your profiling script ignores a failed `cosign sign`, so such an image would only fail later, at the compile (§6.1).
- **Role 2's half of dataset D1 is ready** (on `main`). After your profiling run, §6.3 builds `ml/data/dataset.jsonl` on the demo PC.

---

## 2. What was checked, and the results

| Check | Result |
|---|---|
| PR #16 alone, `pytest -q -m "not integration"` | 461 passed |
| `main` + #14 + #15 + #16 merged | No conflicts. 485 passed, 1 failed (Role 3's live-mode test, not yours) |
| The same on today's `main`, with Role 2's fixes merged | No conflicts. 574 passed, 1 failed (the same Role 3 test) |
| Python files compile | All of them |
| `bash -n` on all 12 shell scripts | All parse |
| Scripts the Makefile runs with `./` | All executable in git (mode 100755) |
| `make -n` on all 16 targets | All ok |
| `make help`, `make corpus-check`, `make report` | Run correctly |
| `make compare` with an empty run folder | Stops with "no ground-truth rows", which is correct |
| `ml/corpus.yaml` | 24 images, including `standin-app` and `demo-app` (plan §4.1 asks for at least 20) |
| Profiling pods (`profile_corpus.sh`) | Plain `kubectl run`, so default pods. That matches what ML-A assumes (§6). |
| Your profiling script's call to Role 2's `gen_provenance.py` | **Failed:** exit 2 and an empty provenance file. It went unnoticed because the script sends its errors to `/dev/null` and ignores failures. Works now with the re-tag mode, merged into `main` (§6.1). |
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
  - **Export `COSIGN_PASSWORD` before `make profile` too,** with the `read -rsp` line in §5.2. The script signs every corpus image. Without the variable, cosign can sit waiting for a password at a prompt the script writes into its log file, so the run just looks stuck.

### 5.2 Steps, in order

```bash
# 0. Role 2's fixes (merged into main), then the cluster
#    and the local registry at localhost:5001
git pull origin main
make up

# 1. Pin the demo app to the stand-in's base image. The stand-in is already pinned:
#      FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
#    Put the same reference in BOTH FROM lines of testbed/demo-app/Dockerfile (keep "AS builder"
#    on the first). Commit before building: an uncommitted change makes the provenance record
#    uncommittedChanges = true.

# 2. The key password, typed so it stays out of your shell history
read -rsp 'cosign key password: ' COSIGN_PASSWORD && echo && export COSIGN_PASSWORD

# 3. Build, push, sign and attest (each prints the image's ref@digest)
STANDIN_REF=$(pipeline/build-and-attest.sh testbed/standin-app standin-app) && echo "$STANDIN_REF"
DEMO_REF=$(pipeline/build-and-attest.sh testbed/demo-app demo-app) && echo "$DEMO_REF"

# 4. Compile the envelopes (each prints run/envelopes/<hex>.json)
python -m compiler.compile "$STANDIN_REF" --run ./run
python -m compiler.compile "$DEMO_REF" --run ./run

# 5. Check Role 2's part. First the two envelope paths that step 4 printed:
STANDIN_ENV=run/envelopes/<standin hex>.json
DEMO_ENV=run/envelopes/<demo hex>.json

#    Integration: Role 2's 19 tests (the 14 on the stand-in, PH1-01 to PH1-04 on both images, and
#    PH3-03 on the stand-in's envelope). All 19 pass on Korn-PC. Role 3's cluster tests run too.
PROVBIND_STANDIN_REF="$STANDIN_REF" PROVBIND_DEMO_REF="$DEMO_REF" PROVBIND_ENVELOPE="$STANDIN_ENV" \
  pytest -q -m integration

#    Real data from the stand-in
PROVBIND_ENVELOPE="$STANDIN_ENV" PROVBIND_SBOM=run/attest/standin-app/sbom.json pytest -q \
  tests/capability/test_ph3_04_depth.py tests/capability/test_ph3_07_closure.py \
  tests/capability/test_ph3_05_unresolved.py

#    Real data from the demo image
PROVBIND_ENVELOPE="$DEMO_ENV" pytest -q \
  tests/capability/test_ph3_08_origins.py tests/capability/test_ph3_09_indices.py \
  tests/capability/test_mla_02_features.py \
  tests/capability/test_cf_reference_example.py tests/capability/test_cf_03_memory.py tests/capability/test_cf_04_lookup.py

#    Every envelope in run/envelopes/ (so no PROVBIND_ENVELOPE here), and the unit-level PH2-06 and PH2-07
pytest -q tests/capability/test_ph3_12_oh_04_05_cost.py tests/capability/test_ph2_06_07_bindings.py

python -m eval.report --run ./run
```

**Notes on these steps:**

- **Signing online or offline.** Signing is online by default: it uploads to Sigstore's public Rekor log, which is fine for these test images. Without internet, set `PROVBIND_OFFLINE=1` for **both** the build and the compile, and tell the team the demo skips transparency.
  - Offline signing works with cosign v3 since 29 September. Before that, the build failed at `cosign sign`. It was checked on Korn-PC with cosign v3.1.3, including an offline compile of the result.
  - Offline, PH1-03 records `blocked`, because there's no transparency record by design.
- **Run PH3-04 on the stand-in only.** It checks `requests` at depth 1 and `urllib3` at depth 2, and the demo app has neither: its `requirements.txt` is comments only, and `requestz-helper` has no dependencies. On the demo envelope, PH3-04 would fail by design.
- **Each test overwrites its own result file,** so the table's last run wins.
  - The commands above record PH3-04, 05 and 07 from the stand-in; PH3-08, 09, MLA-02 and CF-02 to 04 from the demo image; and PH3-12, OH-04 and OH-05 from both.
  - **Set `PROVBIND_ENVELOPE` (and `PROVBIND_SBOM`) whenever you rerun these tests after the real run.** Without them, the tests fall back to synthetic data and overwrite the real results with `not_run`. It happened once on Korn-PC.
- **What the new P1 tests do on your machine:**
  - **PH1-02** makes a throwaway key in a temporary folder, and a small repository (`provbind-ph1-02-…`) in the local registry on each run. It never touches `cosign.key`, and uploads nothing to Rekor.
  - **PH1-03** passes on an envelope compiled with today's `main`. On an envelope compiled before it, it shows as `xfailed` and records `fail` with "recompile it".
  - **PH3-03** fetches every layer of the image with `crane`.
- **Results on Korn-PC's stand-in, for comparison:**

  | Test | Result |
  |---|---|
  | PH1-02 | pass |
  | PH1-03 | pass: log index 2972903426, the same in the envelope |
  | PH2-06, PH2-07 | pass |
  | PH3-03 | 5 of 5 files match |
  | PH3-05 | 6 packages without edges, all with a null depth |
  | PH3-12 | 5.4 s with the blob cache warm (7.9 s cold), 1.5 MB |
  | OH-04 | lookup tables built in 6 ms |
  | OH-05 | about 410 KB per 1,000 files |
- **PH1-01 and PH1-04 cover both images in one result** when `PROVBIND_DEMO_REF` is set, and only the stand-in without it. They only verify; they never sign. On Korn-PC's stand-in both pass: 1 image signature, every subject the image digest, 88 dependency entries, 244 edges.
- **The SBOM-edges test now reads the verified attestation** (`test_attested_sbom_has_dependency_edges`). Before, it read the copy the build left in `run/attest/`, so it failed on any other machine or run folder.
- **Send both envelope paths to Role 3,** and use them for `PROVBIND_ENVELOPE` in your own CF tests.

### 5.3 What to expect

- **Both envelopes will have `"capabilities": []`.**
  - Why: the curated allowlist only covers gunicorn, uvicorn and iputils-ping, and both apps expose port 8080, which is above 1024.
  - The node treats an empty list as "no capability allowed", so any capability the app actually uses becomes a D_cap detection. That can happen in benign-1 too.
  - That comes from the allowlist, not from the verifier; MLA-07 measures exactly this. Record what happens, don't hide it.
  - ML-A replaces the allowlist once D1 exists and a model is trained (§6).
- **`rekor_log_index` is recorded when signing is online** (the stand-in's is 2972903426). Before the fix of 29 September it was always null, because cosign v3's `cosign verify` no longer prints the log entry. Offline it is null by design.
- **An image that was attested but never signed is refused:** exit 2, "v_sig: cosign verified no image signature". cosign v3's own `cosign verify` still passes such an image, so the compiler checks for the signature itself.
- **New digests.** Rebuilding on the demo PC gives new digests. Korn-PC's stand-in (`sha256:0a6bfbb0…`) won't exist there, so use the new references everywhere: `PROVBIND_STANDIN_REF`, the corpus, the bindings.
- **Two-stage Dockerfile.** The demo app has two stages, and `gen_provenance.py` records the *first* `FROM` as the base image (the builder stage). That's harmless here because both stages use the same base, but only if both lines are pinned to the **same** digest, the stand-in's (step 1).
- **`unresolved_fraction` will be about 0.1** (0.097 on the stand-in). Syft lists 14 Windows launcher programs inside pip and setuptools with no package URL. They are now left out of `packages`; before, they doubled this number. No effect on your tests.
- **Expected compile time is 5–8 s per image.** On Korn-PC the stand-in took 8.0 s the first time and 5.4 s with its layers cached, and produced a 1.5 MB envelope.

---

## 6. ML-A dataset D1 (MLA-03 → Role 2's T13 step 3)

### 6.1 A profiling bug, fixed on Role 2's side

**What was wrong.**

1. `retag_and_attest` in `testbed/profile_corpus.sh` runs `gen_provenance.py --subject "$ref" --commit "$(git rev-parse --short HEAD)"`.
2. Role 2's script only had build mode (`--context`), so it **exited 2 and wrote an empty `prov.json`**. The script's `2>/dev/null` and `|| true` hid that.
3. `cosign attest --type slsaprovenance1` then failed on the empty file, hidden the same way.
4. `cosign sign … || true` hides a failed signature the same way. Since 29 September, the compiler refuses an image without an image signature (exit 2), so that image would drop out of D1 at the compile, after its profiling runs.

So every corpus image would have been left without a signed provenance. Role 2's compiler rejects such an image with exit 2, which means no features and no ML-A dataset. It would only have shown up at the dataset join, long after the profiling run.

**The fix** (now on `main`) is a re-tag mode that accepts your exact call. Nothing in your script has to change for it to work.

- A public image re-tagged into our registry wasn't built by us, so its provenance names **no source commit**, and its envelope's `source_commit` is `null`. That's expected.
- The PROVBIND commit that ran the profiling is kept in the provenance as `internalParameters.harnessCommit`. Your short SHA is expanded to the full one.
- The compiler accepts the result. Checked: your exact line, run from the repository root, now exits 0.

**Please change on your side:**

1. **Stop hiding errors in `retag_and_attest`.**
   - Keep `gen_provenance.py`'s stderr, and check that `prov.json` isn't empty.
   - When `cosign sign` or `cosign attest` fails, stop (or at least skip and report that image) instead of `|| true`.
   - A corpus image without verified evidence is useless for ML-A, and the failure otherwise only surfaces much later as a compiler exit 2.
2. **Optional:** pass `--source "$image"` too, so each provenance records which public image was re-tagged (for example `nginx:1.27`).
3. **Export `COSIGN_PASSWORD` before `make profile`** (§5.1).

### 6.2 The labels and the join

- **Your `labels.jsonl` format works for Role 2** as described in your handoff: one row per image, keyed by digest.
- **Keep profiling in default pods** (plain `kubectl run`, as now) for all 24 images.
  - The compiler computes ML-A's features for a default pod, so the labels must come from default pods too, or training and use won't match.
  - If an image can't run in a default pod, leave it out of the corpus and tell Korn. `python -m ml.dataset` assumes default pods, and refuses a label row that records a pod of its own (`allowed`, `securityContext` or `deployment`).
- **Role 2 fills in `allowed` at the join.** Role 2's training data needs the pod's allowed set for each row. For default pods, that's the runtime's 14 default capabilities, which `ml.dataset` adds, so nothing changes on your side.
- **Record every image's digest,** as the plan asks (§12.2). The stand-in and the demo app are in the corpus, and their digests will be the demo PC's.

### 6.3 Building D1 on the demo PC (Role 2's step, after `make profile`)

The feature half is ready on `main`. The compiler writes each image's 46 ML-A features while it has the image open, and `ml.dataset` joins them to your labels by digest. Run it on the demo PC after profiling. Compiling only verifies, so it needs no key password:

```bash
# 1. Compile every profiled image, appending its features. The registry name is the slug
#    profile_corpus.sh used, which is also the folder name under ml/data/raw/.
for meta in ml/data/raw/*/meta.json; do
  name=$(basename "$(dirname "$meta")"); digest=$(jq -r .digest "$meta")
  python -m compiler.compile "localhost:5001/$name@$digest" --run ./run --features-out ml/data/features.jsonl
done

# 2. Join by digest into dataset D1. It lists any digest found in only one of the two files.
python -m ml.dataset --labels ml/data/labels.jsonl --features ml/data/features.jsonl --out ml/data/dataset.jsonl

# 3. Train and evaluate ML-A (at least 20 images), then record MLA-04 and MLA-05 on the real data
python -m ml.train --data ml/data/dataset.jsonl --out ml/model --report run/results/MLA-04/report.json
pytest -q tests/capability/test_mla_04_05_train.py
```

- A compile that exits 2 means that image's evidence didn't verify: usually a failed `cosign sign` or `cosign attest` during profiling (§6.1). Its digest then shows up as "labels but no features" at step 2.
- Checked on Korn-PC with the stand-in and a test label row: one feature line with 46 features and the envelope's purls, and the joined row loads with `ml.train`.

---

## 7. What Role 2 still owes Role 1

| Item | Status |
|---|---|
| Re-tag mode in `gen_provenance.py`, for your profiling | **Done**, on `main` |
| Tests that record PH1-01 and PH1-04 (P0) | **Done**, on `main`. Both pass on Korn-PC's stand-in. |
| Role 2's P1 tests: PH1-02, PH1-03, PH2-06, PH2-07, PH3-03, PH3-05, PH3-12, OH-04, OH-05 | **Done**, on `main`. All pass on Korn-PC. |
| The stand-in's base image pinned | **Done**, on `main` |
| Offline signing with cosign v3 (`PROVBIND_OFFLINE=1`) | **Done**, on `main` |
| The Rekor log-index fix, and v_sig checking for an image signature (`compiler/evidence.py`) | **Done**, on `main` |
| `--features-out` and the `ml.dataset` join for D1 | **Done**, on `main` (§6.3) |
| Packages without a purl left out of the envelope | **Done**, on `main` |
| An ML-A model, to replace the empty allowlist capabilities | After D1 exists (§6.3, step 3) |

---

## 8. Checklist

- [ ] Get `cosign.key` and its password from Korn privately; key at `pipeline/keys/cosign.key`
- [ ] `git pull origin main` (Role 2's fixes are merged)
- [ ] `make up`; pin the demo app to the stand-in's digest (both `FROM` lines); commit
- [ ] Build and compile the stand-in and the demo app (§5.2); send both envelope paths to Role 3
- [ ] Role 2's checks on the demo PC (§5.2, step 5):
  - 19 integration tests, all passing on Korn-PC;
  - PH3-04, 05 and 07 on the stand-in;
  - PH3-08, 09 and MLA-02 on the demo image;
  - PH3-12, OH-04 and OH-05 on every envelope;
  - PH2-06 and PH2-07.
- [ ] Rerun CF-02, 03 and 04 on the demo envelope
- [ ] Write the **trust-2** script (P0)
- [ ] Add a test for **MLA-03** (P0)
- [ ] `profile_corpus.sh`: stop hiding errors in `retag_and_attest`; optionally pass `--source "$image"` (§6.1)
- [ ] Export `COSIGN_PASSWORD`, then profile the corpus in default pods; hand over `ml/data/labels.jsonl`
- [ ] Then Role 2's step on the demo PC: compile the corpus with `--features-out`, `ml.dataset`, `ml.train` (§6.3)
- [ ] Run every scenario at least 3 times (D4)
- [ ] `testbed/behaviours.md` (§12.4)
- [ ] P1 when time allows: `/update3` to `/update9`, attack-9, benign-2 to benign-6, E2E-04 to 10, EV-02, EV-03, EV-07
