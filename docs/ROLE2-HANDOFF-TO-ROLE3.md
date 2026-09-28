# Handoff from Role 2 to Role 3: test results, three problems, the envelopes you'll read, and Role 3 against the test plan

**From:** Role 2 (Korn) · **For:** Role 3 (node runtime) · **Date:** 29 September 2026

**Checked against:** the *Capability Test Plan* v1.1 (`docs/PROVBIND-Capability-Test-Plan.md`), `main` at `bddcced`, and your PRs as submitted: #11 `897bc19`, #12 `48b30e0`, #13 `39ec78f`, #14 `72ea99f`, #15 `c4527f9`. They were checked alone and merged with Role 1's PR #16.

**How it was checked:** on Korn-PC, under WSL2 Ubuntu 22.04 with Python 3.11.16 and every package in `requirements.txt` installed (including PyYAML), in throwaway checkouts. Nothing was changed in your code.

This document replaces the shorter note on branch `local/role3-note`.

---

## 1. The short version

- **Your PRs merge onto `main` with no conflicts,** also together with Role 1's #16.
  - Every Python file compiles, and your Tetragon policies are in place.
  - Nothing in Role 2's code breaks the node. The node imports `compiler/indices.py` and `compiler/paths.py`, and both work as you expect.
- **One bug makes PRs #12, #13 and #14 fail on every machine now:** a live-mode test built on fixed timestamps (§3, Problem 1).
- **Two smaller problems:**
  - `node/tests` isn't in `pytest.ini`'s `testpaths` (Problem 2);
  - one test file needs PyYAML at import (Problem 3).
- **Against the plan, you have a test for all 13 P0 IDs.** Recorded now:
  - CF-01, MLB-01 and MLB-02 **pass**;
  - PH4-17 **fails** (Problem 1);
  - the other P0 tests wait for real recordings and dataset D2 from the demo PC.
  - P1 has no tests yet for PH2-10, MLA-07 and OH-01 to OH-03.
- **The envelopes you'll read have no capabilities** (§6.2), so every granted capability check becomes D_cap. Their Rekor log index is null, but the node doesn't read it.

---

## 2. Test results

| Ref | `pytest -q -m "not integration"` | `pytest -q node/tests` |
|---|---|---|
| `main` | 392 passed | (no node tests) |
| PR #11 | 395 passed | 103 passed |
| PR #12 | 409 passed, **1 failed** (PH4-17) | 254 passed, **1 failed** |
| PR #13 | 415 passed, **1 failed** (PH4-17) | 303 passed, **1 failed** |
| PR #14 | 416 passed, **1 failed** (PH4-17) | 318 passed, **1 failed** |
| PR #15 | 392 passed | (no node tests) |
| `main` + #14 + #15 + #16 | 485 passed, **1 failed** (PH4-17) | 318 passed, **1 failed** |
| The same, with `node/tests` in `testpaths` | 803 passed, **2 failed** | — |

**Integration:** with every PR merged, `pytest -m integration` ran Role 2's 13 tests against the real stand-in image.
- 12 passed.
- The 13th reads the build's debug copy of the SBOM from the run folder, and passed once it was run against the folder the image was built in.
- Your 4 cluster tests (PH4-01/02 and PH4-04) skipped, because Korn-PC has no cluster (`kubectl` has no server).

Every failure in the table comes from Problem 1.

---

## 3. Three problems to fix

### Problem 1: a live-mode test fails once its fixed timestamps are more than an hour old

**Symptom.** `node/tests/test_run.py::test_live_mode_picks_up_bindings_written_later` fails on every run (8 out of 8):

```
{('D_exec', 'undeclared'): 1} != {('D_exec', 'undeclared'): 2}
{('D_write', 'declared_file'): 1} != {('D_write', 'declared_file'): 2}
{('D_exec', 'outside_closure'): 1} != {('D_exec', 'outside_closure'): 3}
{('binding', 'unknown_container'): 2} != {('binding', 'unknown_container'): 1}
```

`tests/capability/test_ph4_17_records.py` fails too, because it runs the whole `node/tests` suite (line 37) and sees that failure. So PH4-17 (P0) records `fail`.

**Cause.** The synthetic events have fixed timestamps, but live mode compares them with the real clock:

- `node/synth.py:241`: `library()` always builds `Session(start="2026-09-28T10:00:00Z")`.
- `node/run.py:101`: live mode calls `pipeline.tick(time.time_ns())`, the wall clock.
- `node/pipeline.py:134`: a held container is released only while `now - held.first_t < self.grace`.

The test passes `--grace 3600`. Once the wall clock is more than an hour past 2026-09-28T10:00Z, every held container has already "waited" too long. Its events are reported as `binding / unknown_container`, and the detections the test expects never happen. At the time of the check it was 2026-09-28T17:05Z, 7 hours later. The test passed in your session only because it ran within that hour. **It now fails everywhere, including the cloud and the demo PC.**

**Proof.**

- It isn't a timing race. `node.run` starts in 0.08 s, and the test still fails with its two 0.5 s waits raised to 3 s.
- With only `"--grace", "3600"` changed to `"--grace", "100000000"`, the test **passes**. (That edit was in a throwaway copy.)

**The node's behaviour is right.** Real Tetragon events carry real times, and replay mode uses the event clock. Only the test data is stale. The live-mode path (`node/run.py:101`) is the only place in `node/` that mixes event time with the wall clock.

**Suggested fix.**

1. Add a `start` parameter to `library()`, defaulting to `"2026-09-28T10:00:00Z"`, so the replay tests' expectations don't change.
2. In the live-mode test, build the library with the current UTC time instead of using the module-level `lib` fixture.

`benign_session` (`node/synth.py:348`) has the same fixed default (`"2026-09-28T11:00:00Z"`). Give any live-mode use of it the same treatment.

**Why it matters.** PR #12 introduces the test, and #13 and #14 inherit it. Merged as they are, they would make `main` fail from the first run.

### Problem 2: the node's 319 unit tests aren't in `pytest.ini`'s `testpaths`

`pytest.ini` has `testpaths = compiler/tests pipeline/tests tests`. So `pytest -q`, the unit-test command in `CLAUDE.md` and in Role 1's `make test`, never collects `node/tests`. After everything merges, `pytest -q` runs 486 tests and silently skips the node's 319. The only coverage left is PH4-17, which runs them in a subprocess as a single test. This is your open question Q2.

**Checked.** With `node/tests` added (`testpaths = compiler/tests pipeline/tests tests node/tests`), the merged tree collects cleanly: 805 tests, 803 passed, and the other 2 are Problem 1. There are no module-name clashes, because `node/tests/__init__.py` exists.

**Suggested fix:** add `node/tests` to `testpaths` in one of your PRs. `pytest.ini` is shared, so mention it in the PR description.

### Problem 3: `node/tests/test_policies.py` needs PyYAML, which a Role-2-only install doesn't have

`node/tests/test_policies.py:8` imports `yaml` at the top. PyYAML is in `requirements.txt` but not in `requirements-role2.txt`. On a venv built from `requirements-role2.txt` alone, the file fails to load:

```
node/tests/test_policies.py:8: in <module>
    import yaml
E   ModuleNotFoundError: No module named 'yaml'
```

**Effects:**

- On that venv, PR #14 merged onto `main` gave **4 failures**: PH4-01, PH4-02a, PH4-02b and PH4-17, which run that file.
- Once Problem 2's fix is in, the import error would stop `pytest -q` at collection for anyone with a Role-2-only install.
- It contradicts your handoff (§8, "Role-2-only installs work … 365 passed, 4 skipped").

**Only the tests need it.** No runtime code in `node/` imports `yaml` (checked by grep).

**Suggested fix:** at the top of `node/tests/test_policies.py`, use `yaml = pytest.importorskip("yaml")`. That's the same pattern Role 2 used for LightGBM in PR #10.

---

## 4. Role 3's tests against the test plan

Statuses are from a run of all PRs merged, with `PROVBIND_ENVELOPE` set to the real stand-in envelope.

### 4.1 P0: all 13 have a test

| ID | Status | What it needs to pass for real |
|---|---|---|
| CF-01 | **pass** | Nothing more. On the real stand-in envelope: 5,725 paths, 0 false negatives. |
| MLB-01 | **pass** | Nothing more |
| MLB-02 | **pass** | Nothing more |
| PH4-17 | **fail** | Problem 1 |
| PH4-01, PH4-02a | not_run (synthetic) | A real Tetragon recording from the demo PC (`PROVBIND_RECORDING`), or the live test with the cluster |
| PH4-05, PH4-12 | not_run (synthetic) | attack-1 on the demo PC |
| PH4-06 | not_run (synthetic) | benign-1 and the benign catalogue under both rules |
| PH4-14 | not_run (synthetic) | A write to `/tmp/new.txt` in a demo pod |
| MLB-03, MLB-04 | not_run (synthetic D2) | Dataset D2: the demo image under load for at least 3 h, plus a held-out run of at least 1 h, starting at least 1 h later (plan §5, §12.2) |
| MLB-05 | not_run (synthetic) | attack-2 on the demo PC with the trained model |

### 4.2 P1 and P2

- **P1 with a test, not_run:** PH4-02b, 03, 04, 07 to 11, 13, 15, 16 and 18; CF-05; MLB-06. They need recordings, or scenarios that aren't implemented yet. Role 1's `/update3` to `/update9` return 501, so attack-2b and attack-3 to attack-8 can't run yet.
- **P1 with no test:** PH2-10 (the cold-start window; `node/pipeline.py` already collects the `cold` statistics), MLA-07, and OH-01 to OH-03.
- **P2 with no test:** OH-06.

### 4.3 Input for CF-05 and fail point M15

Role 1's CF tests ran on the same real envelope:

| Measure | Filter (16-bit) | Plain set |
|---|---|---|
| Memory | 16 KB | 512 KB (the path strings, 576 KB, exist anyway) |
| Lookup, hit | 2.6 µs | 91 ns |
| Lookup, miss | 2.9 µs | 74 ns |
| False-positive rate | 0.0083% (theory 0.0122%) | none |

The filter is about 30× slower per lookup, as the plan predicted (§6.2). CF-05 decides whether to keep it (§6.3).

---

## 5. Event hooks against the plan (§8)

Every hook the plan names is present, and each policy is filtered to namespace `demo`:

| Class | Plan's hook | Policy | Notes |
|---|---|---|---|
| D_exec, D_hash | built-in `process_exec` | Tetragon default | |
| D_write | `security_file_permission`, MAY_WRITE (0x02), with return value | `write.yaml` | Filtered on MAY_WRITE in the kernel. **No path filter**, as ML-B needs (plan §5). |
| Truncation | `security_path_truncate`, and `security_file_truncate` on kernels 6.2+ | `truncate.yaml` | Both calls are present |
| D_load | `security_mmap_file` with PROT_EXEC | `load.yaml` | |
| D_cap, ML-A labels | `cap_capable`, return 0 means granted | `cap.yaml` | Same event shape Role 1's `testbed/profiling/labels.py` parses (`capability_arg`, `return.int_arg`) |
| D_net | `tcp_connect` | `connect.yaml` | |

**Still to check on the demo PC** (your VERIFY markers): that the cap event carries `capability_arg` with the capability's name, and the Tetragon export container's name that Role 1's profiling script reads.

---

## 6. The envelopes you'll read

### 6.1 Where they come from

- The **demo PC runs on Role 1's computer.** Role 1 builds, signs and compiles the stand-in and the demo app with Role 2's commands (see `docs/ROLE2-HANDOFF-TO-ROLE1.md` §5), and sends you both paths.
- **Rebuilding changes the digests.** The Korn-PC stand-in (`sha256:0a6bfbb0…`) won't exist on the demo PC, so take the file names from Role 1.
- Files are named `$PROVBIND_RUN/envelopes/<hex>.json` and **written atomically** (temp file, `fsync`, rename), as your store expects. That won't change.

### 6.2 What's in them: the real stand-in on Korn-PC

| Field | Value |
|---|---|
| Files | 5,725 |
| Symlinks | 506 |
| Packages | 127 |
| Size | 1.4 MB |
| Compile time | 8.0 s |
| `closure` (5) | `ld-linux-x86-64.so.2`, `libc.so.6`, `libm.so.6`, `/usr/local/bin/python3.11`, `/usr/local/lib/libpython3.11.so.1.0`. `ls` and `dash` are in `files` but not the closure. |
| `capabilities` | **`[]`**. The allowlist has no entry for the stand-in's packages, and it exposes only 8080. The demo app will be the same: no Python requirements, and port 8080. |
| `verification` | All five checks true |
| `image.rekor_log_index` | **null**. A Role 2 bug with cosign v3; the fix is pending on branch `local/rekor-bug`. The node doesn't read this field. |
| `packages` keys | 113 are purls. **14 are syft `bom-ref` IDs**, for Windows launcher programs inside pip and setuptools that syft lists without a purl. No `files[].package` points at them, so J_pkg and J_depth are unaffected. |

**What that means at run time:**

- **The empty capability list makes every granted capability check a D_cap detection,** origin INFERRED (your rule for an empty list), during benign runs too.
  - That's the allowlist's fault, not the verifier's; it's exactly what MLA-07 measures.
  - It will change once ML-A has a trained model (after dataset D1).
  - Until then, expect D_cap noise on real runs, and report it as it is.
- **`files[].package` is null for 1,766 of the 5,725 files,** so `context.depth` is null for them. They include the Python interpreter (`/usr/local/bin/python3.11`, `libpython3.11.so.1.0`) and `/app/app.py`, as the handoff notes predicted. `/usr/bin/ls` and `/usr/bin/dash` are owned by `coreutils` and `dash`.

---

## 7. Interfaces between Role 2 and Role 3

- **`compiler.indices.build`, `Indices`, `compiler.paths.realpath` and `SymlinkLoop` stay as they are.** Role 2 will tell you before changing any of them, or the envelope's fields or file naming.
- **Those are the only Role 2 modules your code imports:** `node/store.py`, plus `realpath` in one capability test. That's all that needs to stay stable for you.

  *Correction (29 September):* an earlier version of this section said your tests also import other Role 2 modules and test helpers (`compiler.tests.helpers`, `compiler.tests.test_compile`). They don't. Those imports are in Role 2's own tests (`tests/ml/`, `tests/capability/`), and a search of mine had wrongly lumped them in with yours.

---

## 8. Answers to your handoff (`node/handoff/ROLE3-TO-ROLE2.md`)

| Your item | Answer |
|---|---|
| T12 step 3: the stand-in's envelope | Compiled on Korn-PC; PH3-04, 07, 08 and 09 pass on it. For the demo PC, Role 1 compiles it there and sends you the path (§6.1). |
| The demo app's envelope | Same: Role 1 builds and compiles it on the demo PC |
| Two envelopes of the demo image for MLA-07 | Needs a trained ML-A model, so after D1 is profiled and joined. The allowlist one is `PROVBIND_CAPS_MODEL=none`. Not before then. |
| Keep `indices.py` and `paths.py` | Yes (§7) |
| Decision 4 (`allowed_caps`) | Still open |
| Egress (M8, MLA-08) | Role 2 isn't adding an egress field now (MLA-08 is P2 and not started). Keep `--egress FILE`. |
| Q6: does the node use `compiler/indices.py` | Answered by your handoff: yes. Role 2 records it. |

---

## 9. Checklist

- [ ] Problem 1: `library(start=…)` and a current start time in the live-mode test; then PH4-17 passes
- [ ] Problem 2: `node/tests` in `pytest.ini`'s `testpaths`
- [ ] Problem 3: `yaml = pytest.importorskip("yaml")` in `node/tests/test_policies.py`
- [ ] Merge #11 → #14 in order, then #15, once the above is in
- [ ] On the demo PC: record real Tetragon streams for PH4-01, 02a, 05, 06, 12 and 14
- [ ] On the demo PC: dataset D2 (at least 3 h benign, plus 1 h held out) for MLB-03 to 05
- [ ] Confirm the VERIFY items (`capability_arg` name; the export container)
- [ ] P1 tests still missing: PH2-10, MLA-07 (after ML-A), OH-01 to OH-03
