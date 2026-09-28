# Handoff from Role 3 to Role 2: the envelope at runtime, the compiler modules we use, and ML-A

**From:** Role 3 (node runtime). **For:** Role 2 (evidence and compiler). **Date:** 28 September 2026.

**State.** Role 3's code is in four stacked PRs. Merge them in order:

| PR | What it holds |
|---|---|
| [#11](https://github.com/Krittakorn-Saetia/Provbind/pull/11) | Normaliser and Tetragon policies |
| [#12](https://github.com/Krittakorn-Saetia/Provbind/pull/12) | Verifier and `node.run` |
| [#13](https://github.com/Krittakorn-Saetia/Provbind/pull/13) | ML-B |
| [#14](https://github.com/Krittakorn-Saetia/Provbind/pull/14) | Cuckoo filter and CF-05 |

For how to run and test the node, see `node/README.md`. For every task and open question, see `node/ROLE3_STATUS.md`.

## 1. The short version

Your envelope is what the node checks every kernel event against. We don't change it; we read it. Four things matter to you:
1. **The node imports two of your modules**, `compiler/indices.py` and `compiler/paths.py`. Please keep their interfaces (§3). This also answers your question 6: yes, the node uses `compiler/indices.py`.
2. **What your envelope says decides the verdicts** at runtime (§4). A path missing from `files` becomes a Critical detection.
3. **We need the stand-in's and the demo app's envelopes on the demo PC** (§5). That is your T12 step 3.
4. **Two open decisions touch you**, `allowed_caps` and egress (§6). ML-A's labels can come through our parser (§7).

## 2. How the node reads an envelope

`node/store.py`, class `Store`:

- **Which file.** For each verified binding in `bindings.json`, the node looks for `$PROVBIND_RUN/envelopes/<hex>.json`, which is your compiler's naming. It also accepts `envelopes/<digest>.json`, as Sprint Handoff §3.2 names it.
- **Ready means:** the file exists, parses, and its `image.digest` is the digest it is filed under. A file that fails is logged. That container's events are held, not verified, until the file changes.
- **Reload.** The node re-reads a file whose (mtime, size, inode) changed. **A recompile is picked up without restarting the node.** You already write atomically (temp file, then rename). Please keep that: the node trusts any file that exists.
- **One copy per digest.** It is kept while any verified container uses it, and evicted after the last one goes (Eq. 52).

**Fields the node reads.** `Envelope.prepare` raises an error if any of them is missing.

| Field | What the node does with it |
|---|---|
| `image.digest` | Identity check against the file name and the binding |
| `files{path: {sha256, layer, package}}` | Builds J_I with your `compiler.indices.build`. Declared or not, compared by exact path. `sha256` is compared with a runtime hash when one exists (D_hash; 64 lower-case hex digits, no prefix). `layer` becomes `context.layer` in detections (the index); `package` becomes `context.package`. |
| `packages{purl: {depth}}` | `context.depth`, through J_depth. **`files[].package` must be a key here**, or the depth is null. |
| `symlinks` | The fallback when a runtime path is not in `files`: the path is resolved through the image's links with your `compiler.paths.realpath`. Mount paths from the binding are resolved the same way, so `/var/run/...` also covers `/run/...`. |
| `closure` | In the closure: conforming. Declared but outside it: `outside_closure`, weak, capped at Low (C2). |
| `capabilities[{cap, origin}]` | D_cap: a granted capability check whose capability is not listed |
| `layers[{index, digest}]` | `indices.build` checks that each file's layer exists |

**Not read by the node:** `image.ref`, `builder_id`, `source_commit`, `rekor_log_index` (Role 4 uses those), `unresolved_fraction`, `compiled_at`, `verification`, `timings_ms`. Adding fields is safe. Renaming or removing one that the node reads breaks it: tell us first (Sprint Handoff §4).

## 3. Your code that the node imports (read-only)

| Import | Used for |
|---|---|
| `compiler.indices.build(envelope) -> Indices(path, hash, layer, pkg, depth)` | J_I for every envelope. `path[p] = (sha256, layer)`; `hash[sha256] = frozenset(paths)`, used for D_hash / relocated. |
| `compiler.paths.realpath(path, links)` and `SymlinkLoop` | Canonical runtime and mount paths. A loop makes the path undeclared. |

Many of the node's 319 unit tests (`node/tests/`) go through both modules, so a change that breaks the node shows up there. `pytest.ini`'s `testpaths` doesn't include `node/tests` yet (Q2), so run `pytest node/tests` explicitly. PH4-17 also runs that suite.

## 4. What your envelope decides at runtime

| If the envelope… | …then at runtime | How bad |
|---|---|---|
| lacks a file the image really has (a missed layer, a wrongly canonicalised path) | Executing it is `D_exec / undeclared` | **Critical, 90** in the demo scoring |
| lists a file under a non-real path (`/bin/ls` on merged `/usr`) | Tetragon reports the real path (`/usr/bin/ls`), which is not a key, so executing it is `D_exec / undeclared`. The symlink fallback resolves runtime paths, not your keys. | **Critical**. Keys must be real paths (T6; PH3-02 tests it) |
| misses something in the entrypoint's closure | `outside_closure` for it | Low (weak class) |
| has an empty or too-short `capabilities` list | Every granted check of a missing capability is `D_cap`, origin INFERRED | False positives on benign runs; MLA-07 measures this |
| has a `files[].package` that is not a key of `packages` | `context.depth` is null, so Role 4 scores ρ = 0.5 | Mis-ranked alerts |

**D_cap's origin** follows your `capabilities` list:
- INFERRED if any entry is INFERRED, or the list is empty;
- otherwise CONFIGURED if any entry is CONFIGURED;
- otherwise (every entry AUTHENTICATED) AUTHENTICATED.

With the allowlist or ML-A, that is INFERRED, which is what PH4-15 expects.

## 5. What Role 3 needs from you

- [ ] **T12 step 3.** The stand-in's envelope, written by the CLI into the demo PC's run folder (`$PROVBIND_RUN/envelopes/<hex>.json`). Then the demo app's envelope, once Role 1 delivers `testbed/demo-app/`.
- [ ] **The path, or `PROVBIND_ENVELOPE`.** Our PH4-01 uses the envelope's `symlinks` to check that Tetragon reports real paths. It is the same variable your PH3 tests use.
- [ ] **Two envelopes of the demo image, for MLA-07** (Role 3's test; no file yet, Q2). One with ML-A, and one with the allowlist only (`PROVBIND_CAPS_MODEL=none`), in separate run folders. MLA-07 compares D_cap counts on the benign scenarios with each.
- [ ] **A heads-up before any change** to the envelope's fields or its file naming.

## 6. Open decisions involving Role 2

- **Decision 4: where Eq. 34's cap is applied (`allowed_caps`).** The node does not read `allowed_caps`, because it is not in the bindings contract. If Roles 2, 3 and 4 agree to add it, the node will intersect it with the envelope's capabilities before checking D_cap. Nothing changes until then.
- **Egress (M8, MLA-08).** The envelope has no egress set, so D_net checks an operator allow list given with `node.run --egress FILE`, and its detections say origin CONFIGURED. If you add egress to the envelope, agree the field name with us, and the verifier will read it from there.
- **Runtime hashes (C3).** D_hash compares against your `files[].sha256`, which is already right. The missing piece is on our side: the node has no hash source yet, so D_hash never fires, and PH4-07, 08 and 18 record `blocked`.

## 7. ML-A (T13) and the node

**MLA-03 labels come from Tetragon.** `node/tetragon/cap.yaml` is the capability policy Role 1 profiles with. `node/normalize.py` turns each check into an event whose `cap` is the capability and whose `granted` is True, False (denied) or None (no return value). For joining labels to your features, that parser is ready to use:

```python
from node.normalize import Normalizer
norm = Normalizer(namespaces=("demo",))
for line in open("profile.jsonl"):
    ev = norm(line)
    if ev is not None and ev.kind == "cap" and ev.granted:
        observed[ev.pod].add(ev.cap)          # granted checks are labels; denied ones are attempts
```

**ML-B is separate from ML-A.** It lives in `node/mlb.py` and `node/forest.py`, with its own features, data (`ml/data/mlb/`) and model files (JSON beside the envelope, `<hex>.mlb/model.json`). It shares no code with `ml/*.py`.

## 8. Your environment

- **Role-2-only installs work.** The node's tests pass with `requirements-role2.txt` alone. The ML-B tests that train a model skip cleanly without numpy and scikit-learn, as your MLA-04/05 do. That fix is in #13, after we found the failure by hiding those packages. Result: 365 passed, 4 skipped, 0 failed. With everything installed: 417 passed.
- **Live mode needs Linux or WSL2.** `node.run` reads stdin with `select()`. Replay mode (`--replay FILE`) runs anywhere.
- **Shared variables.** `PROVBIND_ENVELOPE` and `PROVBIND_RUN` mean the same in your tests and ours.

## 9. Checklist

- [ ] The stand-in's envelope is in the demo PC's run folder, and its path is sent to Role 3
- [ ] The demo app's envelope, the same way, when `testbed/demo-app/` arrives
- [ ] Two envelopes (ML-A and allowlist) of the demo image, for MLA-07
- [ ] `compiler/indices.py` and `compiler/paths.py` keep their interfaces, or Role 3 is told first
- [ ] Decision 4 (`allowed_caps`) and egress (M8) settled with Roles 3 and 4
