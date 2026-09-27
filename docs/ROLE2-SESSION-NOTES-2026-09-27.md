# Role 2 session notes, 26–27 September 2026

A log of everything Claude Code (cloud) did for Role 2 in this session. It covers:
- what was built and why;
- what each Python file does and the algorithm behind it;
- the tools used and the bugs found;
- the data everything was tested on, and the results.

The work ran from 26 September 20:55 UTC to 27 September 19:00 UTC, which is 27 September 03:55 to 28 September 02:00 in Thailand.

---

## 1. Is the repo up to date?

Yes. Every commit is pushed, and all eight branches were identical to GitHub on the last check. **Nothing is merged yet:** `main` is unchanged, and each piece of work waits in its own pull request.

| PR | Branch → base | What it holds |
|---|---|---|
| [PR #1](https://github.com/Krittakorn-Saetia/Provbind/pull/1) | `claude/serene-feynman-xqeqez` → `main` | Review notes, pipeline changes, the whole compiler (T1–T11), Windows and Python 3.10 fixes, status (T12 step 1) |
| [PR #2](https://github.com/Krittakorn-Saetia/Provbind/pull/2) | `cloud/t13-alg1` → PR #1's branch | T13 step 1: Algorithm 1 (`ml/alg1.py`), MLA-01 |
| [PR #3](https://github.com/Krittakorn-Saetia/Provbind/pull/3) | `cloud/t13-features` → `cloud/t13-alg1` | T13 step 2: features Ω_I (`ml/features.py`, `ml/features.md`), MLA-02 |
| [PR #4](https://github.com/Krittakorn-Saetia/Provbind/pull/4) | `cloud/t13-mla06` → `cloud/t13-features` | T13 step 5: MLA-06 |
| [PR #5](https://github.com/Krittakorn-Saetia/Provbind/pull/5) | `cloud/t13-train` → `cloud/t13-mla06` | T13 step 4: training and evaluation (`ml/train.py`), MLA-04 and MLA-05 |
| [PR #6](https://github.com/Krittakorn-Saetia/Provbind/pull/6) | `cloud/t13-caps-hook` → `cloud/t13-train` | T13 step 6: the compiler uses the model (`compiler/caps.py`) |
| [PR #7](https://github.com/Krittakorn-Saetia/Provbind/pull/7) | `cloud/ph3-tests` → PR #1's branch | PH3 capability tests and the indices J_I (`compiler/indices.py`) |
| [PR #8](https://github.com/Krittakorn-Saetia/Provbind/pull/8) | `cloud/status-14` → PR #1's branch | Handoff §14: T13 in progress |
| this file's PR | `cloud/session-notes` → PR #1's branch | These notes |

**Merge order.**
1. PR #1 first.
2. Then PR #2 to PR #6, in order. PRs #2–#6 are stacked, so delete each head branch after it merges; GitHub then retargets the next PR.
3. PR #7, PR #8 and this one can merge any time after PR #1. They share no files with the stacked PRs.

**To try everything together before merging.** Build a local branch and don't push it:

```bash
git fetch origin
git checkout -b try-all origin/cloud/t13-caps-hook
git merge origin/cloud/ph3-tests origin/cloud/status-14 origin/cloud/session-notes
pytest -q -m "not integration"          # 391 passed on 27 Sep
```

---

## 2. What happened, in order

1. **Reviewed the Role 2 handoff** (`docs/ROLE2-HANDOFF-NOTES.md`, commit `72f540a`).
   - It lists six open decisions, D1–D6, each with a proposed default. Korn agreed them all ("defaults OK"), and they were folded into the handoff (`0d7449a`).
   - D1 found a real gap in the spec's layer algorithm; see §6.
2. **Pipeline** (`6a32c79`).
   - Builds are pinned to `linux/amd64`.
   - `PROVBIND_OFFLINE=1` signs without Rekor.
   - The provenance records uncommitted changes.
   - Added T1 and T2 tests.
3. **The compiler, T3–T11** (`306ef3f` … `e570e68`).
   - One module per task, each with unit tests, built in handoff order.
   - The layer union was mutation-checked against a single-pass version.
4. **Windows fix** (`02fd96d`). Korn's PowerShell run showed 2 failures, WinError 32, in the CLI tests; see §6.
5. **Korn's PC results recorded** (`0237485`).
   - T1 keys done and T2 stand-in done: `localhost:5001/standin-app@sha256:0a6bfbb07745da4c50e29e159cf426b05ff4481540a9894c746e1190961944a3`.
   - 13 integration tests green; compile takes 6.9 s under WSL2.
   - Tool versions went into `testbed/VERSIONS.md`.
6. **Python 3.10 fix** (`ac79af6`). Korn found it on Ubuntu 22.04; see §6.
7. **Dataset research for the conference paper** (chat only, no files). §7.4 lists what was found.
8. **T13 ML-A**, PRs #2–#6: Algorithm 1, the features, the bound test, training and evaluation, and the compiler hook.
9. **PH3 capability tests and indices**, PR #7.
10. **Status table**, PR #8.
11. **These notes.**

Rules kept throughout:
- `contracts/` and `bindings.json` are unchanged, and `docs/reference/` wasn't touched.
- No private key was read or committed, and `run/` wasn't committed.
- No real malicious sample was downloaded.
- No Docker, kind or Tetragon ran in the cloud; only `pytest -m "not integration"`.
- One network block, `arxiv.org` during the dataset research, was reported and not worked around.

---

## 3. The big picture

```
PHASE 1  pipeline/build-and-attest.sh    build → push → SBOM (syft) → provenance → sign → attest → self-verify
                     │  image ref@digest, signed, with 2 attestations
                     ▼
PHASE 3  python -m compiler.compile <ref@digest>
         oci.preflight      crane manifest               registry can't serve it → exit 3
         evidence.collect   cosign verify(-attestation)  v_sig, v_B, v_P fail → exit 2
         oci.fetch          crane blobs + sha256          v_M, v_C, blob hash fail → exit 2
         layers.union       two-pass layer union          files, links, dirs
         paths.canonicalise real paths (merged /usr)      /bin/ls → /usr/bin/ls
         closure.closure    what the entrypoint runs      executables + libraries
         sbom.depths        dependency depth δ            requests 1, urllib3 2
         owners.match       which package owns each file  Φ
         caps.for_image     capabilities                  ML-A model if present, else allowlist
         compile            assemble, validate, write     run/envelopes/<digest>.json
                     │
                     ▼
Role 3's verifier reads the envelope; compiler/indices.py gives it the lookup tables J_I (Eq. 37)
```

The ML-A part (T13), inside `caps.for_image` when a model exists:

```
envelope + image config + ELF imports + pod ──Ω_I (ml/features.py)──► z_I: 46 numbers + 1 per vocabulary package
z_I ──one LightGBM model per capability (ml/train.py)──► p(c), a probability for each capability
p(c), θ_C, 𝒞_K8s, declared set ──Algorithm 1 (ml/alg1.py)──► the capability list, each with an origin label
```

---

## 4. The code, file by file

About 2,800 lines of non-test code, and 391 unit tests plus 13 integration tests with every branch merged.

### 4.1 Pipeline (Phase 1)

**`pipeline/build-and-attest.sh`** turns a build context into a signed, attested image. stdout carries only the pushed reference `<registry>/<name>@sha256:…`; every log goes to stderr.

1. `docker build --platform linux/amd64 --provenance=false --sbom=false`, then push to `localhost:5001`.
   - Pinning the platform means an Apple Silicon Mac still builds what the demo PC runs.
   - Turning off buildx's own attestations keeps a plain manifest rather than an index.
2. `crane digest` gives the digest.
3. `syft` writes a CycloneDX SBOM. The script warns if the SBOM has no dependency edges, which would make every depth null.
4. `gen_provenance.py` writes the SLSA v1 provenance.
5. `cosign sign`, then `cosign attest` twice: `--type cyclonedx` and `--type slsaprovenance1`.
6. Self-check with the public key: `cosign verify` plus `verify-attestation` for both types.

`PROVBIND_OFFLINE=1` signs with `--tlog-upload=false` and verifies with `--insecure-ignore-tlog=true`, for a demo without internet access. The array expansion is safe under macOS's bash 3.2.

**`pipeline/gen_provenance.py`** prints a SLSA v1 provenance *predicate*; cosign wraps it in an in-toto statement whose subject is the image digest.

- It uses only field names from the SLSA v1 spec, because cosign drops unknown ones silently.
- It records the builder id, the git commit, and the base image's digest, via `crane digest` when the `FROM` isn't pinned.
- It sets `internalParameters.uncommittedChanges` when git sees changes or untracked files (decision D6), so a provenance from a dirty tree can't claim a clean commit.

Tests: `pipeline/tests/`, 10 unit tests plus the T2 integration tests.

### 4.2 Compiler (Phase 3, tasks T3–T11)

**`compiler/evidence.py` (T3): verified evidence.** Paper Eqs. 10–18; 40 tests.
- **Input.** Only what cosign has verified against our public key: the image signature (v_sig), the CycloneDX SBOM attestation (v_B) and the SLSA provenance attestation (v_P). The debug copies in `run/attest/` are never read.
- **Parsing.** It reads the three shapes cosign prints (DSSE envelope, Sigstore bundle, bare statement), because v2 and v3 differ.
- **Binding.** A statement binds only if its `predicateType` is right and its subjects name the image digest. A statement for another image fails with `EvidenceError`, which is exit 2.
- **Several attestations** (decision D2). It picks the newest by the predicate's own timestamp: CycloneDX `metadata.timestamp`, SLSA `runDetails.metadata.finishedOn`. On a tie, the last line wins.
- **What it extracts.**
  - `builder_id` from `runDetails.builder.id`;
  - `source_commit` from the first `gitCommit` among the resolved dependencies;
  - the Rekor `logIndex`, via a depth-first search for the first `logIndex` or `log_index`.

**`compiler/oci.py` (T4): fetch the image with `crane`.** 29 tests.
- `preflight` fetches only the manifest; if the registry can't serve it, that's exit 3 (decision D3).
- Integrity checks: the manifest's sha256 must equal the digest (v_M), and likewise the config (v_C) and every layer blob. Any mismatch raises `IntegrityError`, which is exit 2.
- For an image index it picks the `linux/amd64` entry, skipping buildx attestation manifests, and rejects other platforms (D6).
- Blobs go into a content-addressed cache: download to a temp file, verify, then rename. A cached blob is reused only if its hash still matches.
- `--registry-name` is the host to fetch from; `image.ref` stays as given (D4).

**`compiler/layers.py` (T5): the two-pass layer union.** Handoff §7.1; 36 tests.
- Layers apply in manifest order. Each layer is processed in two passes:
  - **Pass 1:** whiteouts (`.wh.<name>`) and opaque markers (`.wh..wh..opq`) delete **lower** entries only.
  - **Pass 2:** the layer's own entries go in. A new non-directory removes the lower path *and its whole subtree*; a new directory replaces a lower file or link at the same path (decision D1).
- Gzip, zstd and plain tar are recognised by media type, or by magic bytes when the type is unknown.
- Each file gets a SHA-256 and a mode string such as `"0755"`, or `"04755"` for setuid.
- Each layer is decompressed once into a temp folder outside `run/`, so later steps can read file bytes cheaply.

**`compiler/paths.py` (T6): real paths.** Handoff §7.2; 20 tests.
- `realpath` resolves every symlink at any position in a path, the way the kernel does.
  - A relative target resolves against the link's directory, and `..` applies after resolution.
  - More than 40 hops raises `SymlinkLoop`, like the kernel's ELOOP.
- `canonicalise` moves every key under its parent's real path, so `/bin/ls` becomes `/usr/bin/ls` on merged-/usr images. This matters because Tetragon reports real paths. When two keys collide, the higher layer wins.
- `resolve_links` fills the envelope's `symlinks` section.

**`compiler/closure.py` (T7): what the entrypoint can execute or load.** Handoff §7.3; 31 tests. A worklist search that follows what the kernel and `ld.so` would:
1. Start from `Entrypoint[0]`, or `Cmd[0]` if there is no entrypoint. Resolve it the way `execvp` does: on `PATH`, or relative to `WorkingDir`.
2. For a script, follow the `#!` interpreter, including `env` and `env -S`.
3. For an ELF, add its `PT_INTERP` (the dynamic loader).
4. Find each `DT_NEEDED` library in `ld.so`'s order:
   - `DT_RPATH`, only when there is no `DT_RUNPATH`;
   - `LD_LIBRARY_PATH` from the image's `Env`;
   - `DT_RUNPATH`;
   - `/etc/ld.so.conf`, with its include globs;
   - `/lib`, `/usr/lib`, `/lib64`, `/usr/lib64`.
5. Along the way:
   - `$ORIGIN` expands to the object's directory;
   - a candidate with the wrong ELF class or machine is skipped, as `ld.so` does;
   - a missing library is logged and never stops compilation.

Arguments are deliberately not parsed, and `dlopen` libraries are not in the closure. Tool: `pyelftools`.

**`compiler/sbom.py` (T8): dependency depth δ.** Handoff §7.4, Eq. 29; 15 tests.
- A synthetic application root at depth 0 links to every component that has outgoing edges but no incoming ones. A **multi-source breadth-first search** then gives each package its shortest distance.
- A package in no edge at all gets depth `null`, meaning unresolved, **never 1**. syft's edges are incomplete, so a missing edge says nothing (fail point M16).
- Duplicate purls keep the smallest non-null depth. `unresolved_fraction` is the share of null depths.

**`compiler/owners.py` (T9): which package owns each file (Φ).** Handoff §7.5, Eq. 30; 19 tests.
- **dpkg:** `/var/lib/dpkg/status` gives the installed packages, and `info/<name>.list` or `<name>:<arch>.list` gives their files.
- **pip:** each `*.dist-info` has `METADATA` (name and version) and `RECORD`, a CSV of paths relative to site-packages, including `../../../bin/foo`.
- Every listed path goes through `realpath` (merged /usr). When both claim a file, pip wins over dpkg.
- Records are matched to SBOM purls:
  - deb matches on (name, version);
  - pypi matches on the PEP 503-normalised name and the version;
  - qualifiers such as `?arch=amd64` are ignored.
- No match gives package `null`, and it is logged (decision D5).

**`compiler/purls.py`**: package URL helpers built on `packageurl-python`: `parse`, PEP 503 names, and `identity` (type, namespace, name, with no version or qualifiers).

**`compiler/caps.py` (T10, plus T13 step 6): the envelope's `capabilities`.** 26 tests, plus 9 with a trained model.
- **Without a model:** the hand-written allowlist `compiler/caps_allowlist.json` maps packages to capabilities. Port rule: an exposed port below 1024 adds `CAP_NET_BIND_SERVICE`. Every entry is `INFERRED`.
- **With `ml/model/model.json` present** (PR #6): features z_I from the image, the model's probabilities, then Algorithm 1. Each entry is `INFERRED` with its `"probability"` rounded to 4 places, for example `{"cap": "CAP_NET_RAW", "origin": "INFERRED", "probability": 0.9999}`. The schema allows extra fields, so the contract is unchanged.
- **Imports.** numpy and LightGBM are imported only when a model exists, so compiling without one needs only the compiler's own libraries.
- **A broken model is bad input,** exit 3, checked before any network work. The compiler never falls back to the allowlist silently.
- **`PROVBIND_CAPS_MODEL`** names another model folder, or `none` for the allowlist only, for MLA-07's side-by-side runs.
- **𝒞_K8s** (the pod's allowed set, Eq. 34) is the `allowed` parameter. The compiler leaves it unset because it can't know the pod (handoff §13, decision 4).

**`compiler/compile.py` (T11): the CLI that runs everything.** 25 tests, including a golden-file test.
- It times each step (`timings_ms`) and validates the envelope against `contracts/envelope.schema.json` with `jsonschema`.
- It writes the envelope atomically:
  - a temp file opened with `open(…, "x")`;
  - `fsync`, then `os.replace`;
  - LF line endings, so the bytes are the same on every OS.
- stdout carries only the envelope path.
- Exit codes: 0 written, 1 unexpected error, 2 evidence or hash failure, 3 bad input. Nothing is written unless the exit is 0.

**`compiler/indices.py` (PR #7): the runtime lookup tables J_I of Eq. 37,** built from an envelope as plain dicts with O(1) lookups. 3 tests.

| Index | Maps | Used for |
|---|---|---|
| J_path | path → (sha256, layer index) | Is this file declared, and is its content unchanged? |
| J_hash | sha256 → set of paths | Declared content found at an undeclared path (a relocated binary) |
| J_layer | path → layer digest | Layer attribution without a graph query |
| J_pkg | path → package purl or null | The owning package |
| J_depth | package purl → δ or null | Dependency depth for scoring |

It writes nothing new to the run folder; the node can rebuild the tables from the envelope.

### 4.3 ML-A, capability inference (T13, PRs #2–#6)

**`ml/alg1.py`: Algorithm 1, lines 3–14 of Aj Ohm's draft.** 37 unit tests.

```
3:  Ĉ_inf  ← {c | p(c) ≥ θ_C}               keep capabilities the model is confident about (θ_C = 0.5)
4:  Ĉ_inf  ← Ĉ_inf ∩ 𝒞_K8s                   never more than the pod allows (Eq. 34)
5:  𝒞_decl ← 𝒞_decl ∩ 𝒞_K8s                  same for declared capabilities
6:  𝒞      ← 𝒞_decl ∪ Ĉ_inf
7-13: origin = AUTHENTICATED if declared, else INFERRED
```

- **Input.** It takes probabilities, not a model, so it could be tested before any model existed.
- **Parameters for the draft's two open points** (Test Plan rule 1: run both readings):
  - `allowed=None` skips lines 4–5, for when the pod is applied later;
  - `declared_origin=CONFIGURED` is the fix proposed for fail point M9.
- **`effective_set`** computes 𝒞_K8s the way containerd builds it from a pod's `securityContext`:
  - start from the runtime's 14 default capabilities;
  - apply `add: [ALL]`, then `drop: [ALL]`, then the individual adds, then the individual drops;
  - a privileged pod gets all 41 kernel capabilities.
- **Validation.** Names are normalised (`net_raw` → `CAP_NET_RAW`). Unknown names, probabilities outside [0, 1] and NaN are rejected.

**`ml/features.py` and `ml/features.md`: the feature extractor Ω_I, Eq. 32.** 41 unit tests.
- **Why it exists.** The draft names Ω_I's inputs but never its features, so `ml/features.md` is now that definition for the paper.
- **The vector.** 46 fixed numbers, plus one 0/1 flag for each of the 100 most common packages in the training images (the vocabulary). That makes 146 features.

| Group | Features |
|---|---|
| Configuration (5) | runs as root, `User` set, number of exposed ports, any port below 1024, number of env vars |
| Packages (13 + vocabulary) | package count per ecosystem (apk, cargo, composer, deb, gem, generic, golang, maven, npm, nuget, pypi, rpm, other); `pkg.has.<type>/<name>` per vocabulary entry |
| Closure (6) | closure size; Python, Node, Java or shell interpreter present; static binary (no dynamic loader) |
| ELF imports (19) | whether any closure binary imports `socket`, `bind`, `listen`, `connect`, `setuid`, `setgid`, `setgroups`, `chown`, `fchown`, `chmod`, `mount`, `umount2`, `ptrace`, `capset`, `prctl`, `chroot`, `setns`, `unshare`, `sethostname` |
| Deployment (3) | privileged; capabilities added beyond the defaults; defaults dropped |

- **ELF imports** are undefined dynamic symbols. `closure_imports()` reads them with `pyelftools` from `.dynsym`, or through the dynamic segment for stripped binaries. Without the image they are NaN, meaning missing, which LightGBM handles.
- **Deterministic:** no clock, no randomness, no dependence on dict or set order (MLA-02).

**`ml/train.py`: training and evaluation.** Test Plan §§4.2–4.7; 37 unit tests.
- **Model.** `MultiOutputClassifier(LGBMClassifier(n_estimators=200, num_leaves=15, min_child_samples=2, learning_rate=0.05))`.
  - That is one gradient-boosted tree model per capability ("binary relevance").
  - Only labels with at least 3 positive images are trained (§4.2); rarer ones are reported as too rare.
  - A label that is always on, or always off, in the training images gets a constant, because LightGBM can't fit one class.
- **Cross-validation.** 5 folds, repeated 3 times, split **by image digest**.
  - Each fold rebuilds the package vocabulary and the trainable labels from its own training images, so nothing leaks from the test images.
  - Each repeat predicts every image once, from a model that never saw it. Metrics are computed per repeat and reported as mean ± standard deviation.
- **Predicted set.** Algorithm 1 with each image's own 𝒞_K8s, so the metrics measure what would go into the envelope.
- **Metrics (§4.5).**
  - **Under-prediction rate:** used but not predicted, divided by used. Each one would be a false D_cap alert.
  - **Over-prediction rate:** predicted but not used, divided by predicted. Each one widens the envelope.
  - Both are swept over θ_C from 0.2 to 0.8. Also per-label precision, recall and F1; micro- and macro-F1; subset accuracy; Hamming loss.
  - The micro-F1, macro-F1, Hamming loss and subset accuracy were checked against scikit-learn.
- **Baselines (§4.6)**, on the same folds and capped at 𝒞_K8s: the curated allowlist plus the port rule, the empty set, the pod's full default set, and the per-label majority.
- **Model file.** `ml/model/model.json` holds the feature names, the vocabulary, the constants and one LightGBM text model per capability.
  - It is **JSON, not a pickle**, because the compiler loads it, and a pickle can run code.
  - Loading checks the format, the features version, the feature names, the capability names and each tree model's feature count.
- **CLI.** `python -m ml.train --data ml/data/dataset.jsonl --out ml/model --report <json>`.
- **Dataset format.** One JSON object per image, with `digest`, `features` (the 46), `packages` (purls), `labels`, `allowed` and optional `exposed_ports`.

### 4.4 Tests

| Folder | Unit tests | What |
|---|---|---|
| `compiler/tests/` | 253 | T3–T11, indices, the model hook, the golden envelope; `helpers.py` builds images, ELFs, tars, a fake registry and a fake cosign in memory |
| `pipeline/tests/` | 10 | T1 provenance, the build script's flags and stdout (with fake tools) |
| `tests/ml/` | 115 | `test_alg1.py` (37), `test_features.py` (41), `test_train.py` (37); helpers `alg1_cases.py`, `features_doc.py`, `synthetic.py` |
| `tests/capability/` | 13 | the registry tests below, each recorded with `record_result` |
| integration (PC only) | 13 | Docker, the local registry and the stand-in image |

**Mutation testing.** I planted small bugs on purpose, then checked that the tests fail:
- `ml/train.py`: 18 planted bugs, among them a train/test leak, swapped rate denominators, θ ignored in the sweep, and constants lost on load;
- the model hook: 13;
- `compiler/indices.py`: 6;
- Algorithm 1: 3;
- MLA-06: 1;
- MLA-02: 2;
- the layer union: single-pass whiteouts.

All were caught. Where a test first missed one, the test was strengthened (see §6).

---

## 5. Algorithms and tools

**Algorithms used**

| Algorithm | Where |
|---|---|
| Two-pass OCI layer union with whiteouts and opaque markers | `compiler/layers.py` |
| Kernel-style symlink resolution with a 40-hop loop limit | `compiler/paths.py` |
| Worklist search following shebangs, PT_INTERP and `ld.so`'s library search order | `compiler/closure.py` |
| Multi-source breadth-first search from a synthetic root (shortest depth) | `compiler/sbom.py` |
| Record parsing and matching on (name, version) with PEP 503 normalisation | `compiler/owners.py` |
| Hash maps for O(1) lookups (Eq. 37) | `compiler/indices.py` |
| Algorithm 1: threshold, cap at 𝒞_K8s, union with declared, origin labels | `ml/alg1.py` |
| containerd's capability rules for a securityContext | `ml/alg1.py` |
| Feature extraction with a document-frequency vocabulary (top 100 package ids) | `ml/features.py` |
| Gradient-boosted decision trees (LightGBM), one binary model per capability | `ml/train.py` |
| Grouped, repeated k-fold cross-validation (5×3, grouped by image) | `ml/train.py` |
| Property-based test on 500 random files, plus 500 random non-members | PH3-09 |
| Mutation testing | everywhere (see §4.4) |

**Tools**

| Tool | Used for | Version seen |
|---|---|---|
| Python | everything | 3.11 is the team standard (3.11.16 on Korn's PC); the timestamp fix was also tested on 3.10, 3.12 and 3.13 |
| pytest, pyflakes | tests, static checks | |
| Docker (buildx) | building `linux/amd64` images | 29.5.3 on Korn's PC |
| crane | manifests, blobs, digests | 0.22.1 |
| syft | CycloneDX SBOM | 1.52.0 |
| cosign | sign, attest, verify, Rekor | v3.1.3 |
| jq | counting SBOM edges in the build script | |
| pyelftools | ELF headers, PT_INTERP, DT_NEEDED, dynamic symbols | |
| zstandard | zstd-compressed layers | |
| packageurl-python | parsing purls | |
| jsonschema | validating the envelope (Draft 2020-12) | |
| numpy, scikit-learn, LightGBM | ML-A | cloud tests ran numpy 2.4.6, scikit-learn 1.9.1, LightGBM 4.7.0 |
| Tetragon | planned: labels from `cap_capable` (MLA-03, Roles 1 and 3) | |

---

## 6. Bugs and problems found

**In the specification** (found in the review, agreed as D1–D6, folded into the handoff):

| # | Problem | Fix |
|---|---|---|
| D1 | §7.1's union missed three OCI cases: a symlink or file replacing a directory, and a directory replacing a symlink. The envelope could then show phantom files such as `/y/a` | Pass 2 removes the lower path and subtree; 3 new T5 tests |
| D2 | "Use the newest attestation" had no clock (cosign's output order means nothing) | Newest by the predicate's own timestamp |
| D3 | Exit codes: an unreachable registry exited 2, but the table said 3; hash mismatches had no code | Preflight with `crane manifest` → 3; any hash mismatch → 2 |
| D4 | `--registry-name` was never defined | It is the host to fetch from |
| D5 | A file claimed by dpkg or pip, but not in the SBOM | `package: null`, logged |
| D6 | The build script didn't pin the platform, flag dirty trees, or have an offline mode | All three added |

**In the code:**

| # | Bug | How it was found | Fix |
|---|---|---|---|
| 1 | Windows: `os.fchmod` doesn't exist before Python 3.13. The error path deleted the temp file while it was still open, which Windows refuses (WinError 32), so 2 CLI tests failed | Korn's PowerShell run | Create the temp file with `open(…, "x")`, always close it before rename or delete, and write LF only (`02fd96d`) |
| 2 | Python 3.10's `fromisoformat` accepts only 3 or 6 fraction digits. A timestamp like `12:34:56.5` became "no timestamp", which could change which attestation D2 picks | Korn, on Ubuntu 22.04 | Pad or cut the fraction to 6 digits first (`ac79af6`) |
| 3 | A loop variable shadowed a `__future__` import | pyflakes | Renamed (`746d488`) |
| 4 | `ml/features.py`: an ELF with a dynamic segment but no `DT_SYMTAB` was logged as unreadable instead of "imports nothing" | Surfaced when the compiler ran the model on the test image | Return an empty set; new test (PR #6) |
| 5 | The MLA-01 test compared `NET_BIND_SERVICE` with `CAP_NET_BIND_SERVICE` without normalising, so it reported a false failure | Its first run | Normalise first (before commit) |
| 6 | `ml/features.md` said 50 features; the tables add up to 46 | Checking the doc against the code | Doc and test fixed (before commit) |
| 7 | The MLA-02 determinism check was flaky: it caught a planted set-order bug only 2 of 3 times, because Python's hash seed is random per process | Mutation testing | Run six child processes with fixed seeds 0–5; now 5 of 5 (before commit) |
| 8 | LightGBM can't fit a label with one class: `predict_proba` returns one column | While writing `train.py` | Such labels get a constant probability |
| 9 | Three weak tests in `test_train.py` missed planted bugs: the majority-tie rule, constants lost on load, θ ignored in the sweep | Mutation testing | Tests strengthened; 18 of 18 caught |
| 10 | A compile test passed on an empty list: the model predicted nothing for the test image | Checking the actual output | The fixture now trains on images like that one, so a real prediction (p = 0.9999) is required |
| 11 | PH3-09's inverse check was O(hashes × files), which is too slow on a real 10,000-file envelope | Code review before commit | O(files) single pass |
| 12 | Called `get_interpreter` instead of pyelftools' `get_interp_name` | Test run | Fixed during development |

**Design points found** (for the paper, not bugs in our code):
- **Install-time payloads.** Many malicious PyPI packages run their payload at install time. Inside `docker build`, that happens *before* signing, so PROVBIND would sign the result rather than flag it. The paper must separate install-time samples from run-time ones.
- **Algorithm 1 vs per-image envelopes.** Algorithm 1 caps at the pod's allowed set, but envelopes are per image, so the cap must be applied per pod (§13, decision 4, still open).
- **Declared capabilities** have no stated source in the draft (M9); `CONFIGURED` is available as a parameter.

**Environment:**
- `arxiv.org` was blocked by the sandbox's network policy during the research. It was reported, not worked around.
- There was no PDF text tool, so `pypdf` was installed in a scratch environment only, never in the repo, to read the reference PDF.

---

## 7. Data

### 7.1 Real data

- **The stand-in image**, built and signed on Korn's PC: `localhost:5001/standin-app@sha256:0a6bfbb0…44a3`.
  - The 13 integration tests passed on it.
  - Compile time was 6.9 s under WSL2 (evidence 3.3 s, fetch 1.5 s, union 1.4 s).
- **No ML dataset exists yet.** D1 will come from profiling at least 20 images under Tetragon's `cap_capable` policy (MLA-03, Role 1): two 120-second runs per image, where the label is every capability with a granted check.
  - Role 1 writes `ml/data/labels.jsonl`.
  - Our features go to `ml/data/features.jsonl`.
  - The two are joined by digest into `ml/data/dataset.jsonl` (T13 step 3, not done yet).

### 7.2 Synthetic data (made for testing; every synthetic result is recorded as `not_run`)

- **`tests/ml/synthetic.py`: a 40-image dataset.** Each image comes from an archetype and runs through the real feature extractor.

| Archetype | Images | Packages | Port, user | Capabilities used |
|---|---|---|---|---|
| webserver | 7 | nginx, libc6, libssl3 (deb) | 80, root | NET_BIND_SERVICE, SETUID, SETGID, CHOWN, DAC_OVERRIDE |
| datastore | 5 | postgresql-16, libc6, gosu | 5432, root | SETUID, SETGID, CHOWN, FOWNER, DAC_OVERRIDE |
| cache | 5 | redis-server, libc6, gosu | 6379, root | SETUID, SETGID |
| python_app | 6 | flask, werkzeug (pypi) | 8080, `app` | none |
| python_low_port | 3 | gunicorn, flask | 80, root | NET_BIND_SERVICE |
| node_app | 4 | express, lodash (npm) | 3000, `node` | none |
| go_static | 3 | one Go module, static binary | 8080, uid 65532 | none |
| ping | 4 | iputils-ping, libc6 | none, root | NET_RAW |
| shell_job | 1 | busybox (apk) | none, root | none |
| supervisor | 2 | supervisor (pypi) | 9001, root | KILL, SETUID, SETGID |

  Random variation, seeded so every run is identical:
  - 0–3 extra packages and 1–6 environment variables per image;
  - 15% of pods drop ALL and add only NET_BIND_SERVICE;
  - 10% of images have unknown ELF imports;
  - 10% label noise: one capability added or removed, like two profiling runs that disagree.
- **The golden envelope** (`compiler/tests/golden/envelope.json`): built from a stand-in-shaped image made in memory.
  - Merged /usr, Python in `/usr/local`, dpkg and pip records;
  - a whiteout, a setuid file, and one package the SBOM doesn't list.
- **The synthetic SBOM** in `compiler/tests/test_compile.py`: requests → urllib3, and coreutils and dash → libc6.
- **PH3-09's envelope:** the golden one plus 5,000 generated files. One in ten repeats earlier content; one in three has no package.
- **MLA-06's pods:** 6 named securityContexts plus 1,000 random ones.
- **MLA-01's cases:** 12 hand-computed cases in `tests/ml/alg1_cases.py`.

### 7.3 Environment variables for real artifacts

The capability tests switch from synthetic to real data with these:
- `PROVBIND_ENVELOPE`: the stand-in's envelope, for PH3-04, PH3-08, PH3-09 and MLA-02;
- `PROVBIND_SBOM`: its SBOM, for PH3-04;
- `PROVBIND_ML_DATASET`: D1, for MLA-04 and MLA-05; `ml/data/dataset.jsonl` is used if it exists.

### 7.4 Dataset research for the conference paper (no files, no downloads)

**Malicious packages:**
- [DataDog's dataset](https://github.com/DataDog/malicious-software-packages-dataset): 28,623 vetted npm and PyPI packages in encrypted zips. It warns of selection bias.
- [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry): more than 10,000 malicious PyPI packages (ASE 2023).
- [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages): reports only, no samples.
- [Backstabber's Knife Collection](https://dasfreak.github.io/Backstabbers-Knife-Collection/): 174 packages. Access needs an email from an institutional address.

**Runtime attacks:** [Falco event-generator](https://github.com/falcosecurity/event-generator).

**Benign baseline:** [top-pypi-packages](https://hugovk.dev/top-pypi-packages/), the 15,000 most-downloaded PyPI packages, citable with DOIs.

**Capability ground truth:**
- [Tetragon's capability recording](https://tetragon.io/docs/use-cases/security-profiles/record-linux-capabilities/);
- bcc's [`capable`](https://github.com/iovisor/bcc/blob/master/tools/capable_example.txt);
- [Decap (RAID 2022)](https://dl.acm.org/doi/abs/10.1145/3545948.3545978), static inference, with [code](https://github.com/hasanmdme/decap).

Test plan §12.4 still applies: never download or commit real malicious samples in the repo.

---

## 8. Results

### 8.1 Unit tests

391 passed and 13 deselected (integration), with every branch merged locally on 27 September. 239 of them existed before the T13 work.

| Branch | Unit tests |
|---|---|
| PR #1 | 239 |
| PR #7 | 248 |
| PR #6, the ML chain's tip | 382 |

### 8.2 Capability tests (the ones Role 2 owns and ran)

| ID | P | Status | What was measured |
|---|---|---|---|
| MLA-01 | P0 | **pass** | 12 cases, 0 mismatches, 0 outside 𝒞_K8s |
| MLA-02 | P0 | **pass** | 13 extractions (this process plus 6 hash seeds × 2 input orders) identical; 0 undocumented features |
| MLA-06 | P0 | **pass** | 1,006 pods, 15,531 predictions from a worst-case model, 0 outside 𝒞_K8s |
| PH3-01 | P0 | **pass** | T5 unit tests: 36 passed |
| PH3-02 | P0 | **pass** | T6 unit tests: 20 passed |
| PH3-06 | P0 | **pass** | T9 unit tests: 19 passed |
| PH3-04 | P0 | not_run | Synthetic SBOM gives requests 1, urllib3 2 (T8: 15 passed); needs the stand-in's envelope or SBOM |
| PH3-08 | P0 | not_run | Golden envelope: 0 problems; needs the stand-in's envelope |
| PH3-09 | P0 | not_run | 500 of 5,030 synthetic files: 100% agreement, 0 non-member hits; needs the stand-in's envelope |
| MLA-04 | P0 | not_run | Pipeline works end to end on synthetic data; needs D1 (MLA-03) |
| MLA-05 | P1 | not_run | Comparison table produced on synthetic data; needs D1 |

**Checked on purpose:**
- the golden envelope passed through `PROVBIND_ENVELOPE` gives pass on PH3-04, 08 and 09;
- a tampered envelope gives fail on PH3-08 and PH3-09;
- a 40-image dataset file gives pass on MLA-04 and MLA-05;
- a 10-image file gives `blocked` (§4.7 needs at least 20).

### 8.3 ML-A on synthetic data: not a result, only proof that the pipeline works

5 folds × 3 repeats, 40 synthetic images, θ_C = 0.5, mean ± std over the repeats:

| Method | Under-prediction | Over-prediction | Micro-F1 | Macro-F1 |
|---|---|---|---|---|
| ML-A (LightGBM) | 0.164 ± 0.033 | 0.101 ± 0.021 | 0.866 ± 0.026 | 0.549 ± 0.021 |
| Curated allowlist + port rule | 0.813 | 0.000 | 0.315 | 0.172 |
| Empty set | 1.000 | 0.000 | 0.000 | 0.000 |
| Pod's full default set | 0.000 | 0.836 | 0.282 | 0.313 |
| Per-label majority | 1.000 | 0.000 | 0.000 | 0.000 |

The synthetic labels were written to be learnable, so these numbers say nothing about real images. The real run needs D1.

---

## 9. How to run things

```bash
# unit tests (cloud and PC)
pytest -q -m "not integration"

# capability tests; results in run/results/<ID>.json, report in run/results/REPORT.md
pytest -q -m "not integration" tests/capability
python -m eval.report

# PH3-04, 08 and 09 for real, on the PC, after T12 step 3 writes the stand-in's envelope
PROVBIND_ENVELOPE=run/envelopes/<digest-hex>.json pytest -q \
  tests/capability/test_ph3_04_depth.py tests/capability/test_ph3_08_origins.py tests/capability/test_ph3_09_indices.py

# train ML-A once D1 exists (ml/ is on the PR #2–#6 branches until they merge)
python -m ml.train --data ml/data/dataset.jsonl --out ml/model --report run/results/MLA-04/report.json

# compile: uses ml/model/ when it exists, otherwise the allowlist
python -m compiler.compile <ref@digest> --run $PROVBIND_RUN
PROVBIND_CAPS_MODEL=none python -m compiler.compile <ref@digest> --run $PROVBIND_RUN   # allowlist only
```

---

## 10. Next steps and open questions

**Next steps:**
- **T12 step 3.** Write the stand-in's envelope with the CLI, give it to Role 3, and run PH3-04, 08 and 09 on it.
- **T12 step 2.** Compile the demo app when Role 1 delivers `testbed/demo-app/`.
- **T13 step 3.** When Role 1's `ml/data/labels.jsonl` arrives, join it to our features, train on the demo PC, and rerun MLA-04 and MLA-05 on real data.

**Open questions for Korn:**
1. **Compiler dependencies.** `compiler/CLAUDE.md` allows only a few extra libraries. The model hook imports numpy and LightGBM only when a model exists. Is that acceptable?
2. **Step 3 formats.** What columns will `labels.jsonl` have? Proposal: a `--features-out ml/data/features.jsonl` flag on the compiler, because the ELF imports can only be read while the image is open.
3. **The trained model.** Commit `ml/model/model.json` (a few MB), or keep it on the demo PC?
4. **The θ_C plot.** §4.5 asks for one; the sweep is written as a table because matplotlib isn't in `requirements.txt`. Add it, or plot in the paper?
5. **Decision 4** (where Eq. 34's cap is applied): `allowed_caps` in `bindings.json` needs Roles 3 and 4.
6. **Role 3's verifier.** Should `node/verify.py` use `compiler/indices.py`?
7. **PH2-06 and PH2-07.** Should they get capability test files? They are outside my file list.
