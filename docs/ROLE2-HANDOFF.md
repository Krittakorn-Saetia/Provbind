# Role 2 Handoff: Evidence and Compiler

**PROVBIND sprint · Draft v0.1 · 26 September 2026 · Owner: Korn**

This file is the complete specification for Role 2, written so that Claude Code can build from it. It extends the team's *PROVBIND Sprint Handoff v1.0*. That handoff's Sections 3–4 (run folder, commands, contracts) are binding here, and where the two disagree, the sprint handoff wins until the team agrees a change.

---

## 0. How to use this with Claude Code

1. **Copy the kit's contents into the repo root.** `docs/`, `contracts/`, `pipeline/`, `compiler/` and `testbed/` merge into the team repo.
   - If the repo already has a `.gitignore`, add the kit's lines to it instead of replacing it.
   - The root `CLAUDE.md` and the two files in `contracts/` are meant for the whole team, so show them to Role 4 before committing.
2. **Start Claude Code in the repo root.** It loads `CLAUDE.md` at startup, and loads `compiler/CLAUDE.md` when it works on files in `compiler/`.
3. **Give it the first prompt from `docs/PROMPTS.md`.** It asks Claude Code to read this file and plan before writing any code.
4. **Work task by task (Section 6).** A task is done when its tests pass.
   - After each task, update the status table in Section 14.
   - Commit after each green task.
5. **Never hand Claude Code `pipeline/keys/cosign.key`, and never commit it.** The scripts read it from disk.

---

## 1. Mission

Role 2 turns source code into **signed evidence** (Phase 1) and turns that evidence into the **envelope** (Phase 3). The envelope is the file every other role checks runtime behaviour against.

You deliver three things:

| Deliverable | Form | Consumer |
|---|---|---|
| A signed image with two signed attestations (CycloneDX SBOM, SLSA v1 provenance) | Image in `localhost:5001`, signatures and attestations stored by cosign | Role 4's controller verifies them |
| `envelopes/<digest>.json` | JSON matching `contracts/envelope.schema.json` | Role 3 (verifier), Role 4 (scoring, Neo4j) |
| Two commands | `pipeline/build-and-attest.sh <dir> <name>` and `python -m compiler.compile <ref@digest> --run $RUN` | `make demo` (Role 4) |

**Done when:** the demo image's envelope has

- `python3.11`, `libpython3.11` and libc in `closure`;
- `/usr/bin/ls` and `/usr/bin/dash` in `files` but not in `closure`;
- no entry for `/tmp/.x9`;
- every file of the test package owned by its `pkg:pypi/…` purl;

and it validates against the schema.

---

## 2. Context in sixty seconds

PROVBIND watches running containers and asks one question per kernel event: **does this contradict what was signed about the image?** It does not ask "is this unusual?".

The **envelope** is the signed claims compiled into a form that can be looked up fast:

- **Files:** which files exist, with which SHA-256, from which layer.
- **Ownership:** which package owns each file.
- **Depth:** how deep each package sits in the dependency graph.
- **Closure:** which executables and libraries the entrypoint can reach.

Role 3 checks every exec and write event against this file. A wrong envelope never crashes anything; it just makes Role 3 report wrong answers. **Correctness beats speed and features in this role.**

The rule that makes the envelope trustworthy: **the compiler reads only evidence that cosign has verified against our public key.** Unverified files in `run/attest/` are for debugging only.

---

## 3. Inputs and outputs

| Input | From | Until it arrives |
|---|---|---|
| `testbed/demo-app/` source (Dockerfile, app, test package) | Role 1, end of Day 1 | Use `testbed/standin-app/` from this kit |
| Local registry `localhost:5001` | Role 1's PC (kind local-registry script) | `docker run -d -p 5001:5000 --name registry registry:2` on your own machine |
| cosign key pair | You (Task 1) | — |

| Output | Written to | Rule |
|---|---|---|
| SBOM, provenance, cosign logs | `$PROVBIND_RUN/attest/<name>/` | Debug copies only; never read by the compiler |
| Envelope | `$PROVBIND_RUN/envelopes/<digest-hex>.json` | Write to a temp file, then rename, so readers never see half a file |
| Blob cache | `$PROVBIND_RUN/cache/blobs/<hex>` | Content-addressed; verify each blob's SHA-256 on download |

`<digest-hex>` is the 64 hex characters without the `sha256:` prefix, so file names stay portable.

---

## 4. Environment

You can do all of Role 2 on your own Linux or macOS machine with Docker. Only the final integration needs the demo PC.

| Tool | Why | Check |
|---|---|---|
| Docker Engine with buildx | Build and push | `docker buildx version` |
| crane | Digests, manifests, configs, blobs | `crane version` |
| cosign (v2.6+ or v3.x) | Sign, attest, verify | `cosign version` |
| syft | CycloneDX SBOM | `syft version` |
| jq | Script checks | `jq --version` |
| Python 3.11 | Compiler | `python3.11 --version` |
| Python packages | `pyelftools`, `zstandard`, `packageurl-python`, `jsonschema`, `pytest` | `pip install -r requirements-role2.txt` |

**Environment variables:**

| Variable | Default | Meaning |
|---|---|---|
| `PROVBIND_RUN` | `./run` | The shared run folder |
| `PROVBIND_REGISTRY` | `localhost:5001` | Where images are pushed |
| `COSIGN_KEY` | `pipeline/keys/cosign.key` | Private key; never committed |
| `COSIGN_PASSWORD` | must be set (an empty string is fine) | Lets cosign run without prompts |
| `PROVBIND_OFFLINE` | unset | `1` signs and verifies without Rekor (Section 10); read by the build script and the compiler |
| `PROVBIND_STANDIN_REF` | unset | The stand-in's `ref@digest` from T2; integration tests skip without it |

Record the installed tool versions in `testbed/VERSIONS.md`.

---

## 5. Verified tool facts

These replace the VERIFY markers in the sprint handoff. Each was checked against the tool's documentation or source on 26 Sep 2026.

1. **cosign predicate types.** `cosign attest --type` accepts `slsaprovenance1` and `cyclonedx`, among others. `slsaprovenance1` sets the in-toto `predicateType` to `https://slsa.dev/provenance/v1`. ([cosign attest docs](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md))
2. **cosign v3 changed defaults.** Signing now defaults to the standardized Sigstore bundle format, and container signatures are stored as OCI 1.1 referring artifacts. Verification supports both old and new formats and detects which one it is given. ([cosign releases](https://github.com/sigstore/cosign/releases))
   - **Consequence:** the compiler must not depend on one exact JSON layout from `cosign verify`. See Task 3 for how to read the output defensively.
3. **No insecure-registry flags are needed for `localhost`.** go-containerregistry, which crane and cosign are built on, uses plain HTTP automatically for registry names starting with `localhost:`, loopback addresses and RFC 1918 addresses. ([registry.go](https://github.com/google/go-containerregistry/blob/main/pkg/name/registry.go))
4. **`docker build` attaches provenance by default.** Buildx creates a minimal provenance attestation unless told not to, and attestations are attached through an image index. `--provenance=false` (and `--sbom=false`) disables them. ([docker buildx build](https://docs.docker.com/reference/cli/docker/buildx/build/))
   - **Consequence:** the build script passes both flags, so the pushed digest is a single manifest. The compiler must still handle an index (Task 4).
   - The script also passes `--platform linux/amd64`, so a build on an Apple Silicon Mac still produces the image the demo PC runs. The compiler rejects any other platform with exit code 3.
5. **Whiteouts apply only to lower layers.** A whiteout never hides a file added in its own layer. An opaque marker is applied before the layer's own entries, however the tar orders them. ([OCI layer spec](https://github.com/opencontainers/image-spec/blob/main/layer.md))
   - **Consequence:** the union must be two-pass per layer (Task 5). Our old Section-Spec pseudocode got this wrong.
6. **syft's dependency edges are incomplete and keyed by bom-ref.**
   - syft writes CycloneDX `dependencies` only from package-to-package "dependency-of" relationships.
   - dpkg relationships are supported. Python relationships can miss some `Requires-Dist` entries, for example Flask listing 2 of its 4 dependencies ([syft #4401](https://github.com/anchore/syft/issues/4401)).
   - The `ref` and `dependsOn` values are bom-refs such as `pkg:pypi/flask@1.1.2?package-id=…`, not bare purls.
   - **Consequence:** map bom-ref → component first, key packages by the component's `purl` field, and treat missing edges as "unresolved", never as "depth 1" (Task 8).

---

## 6. Tasks, in order

Each task lists what to build, how to build it, and the tests that close it. Tests use `pytest`. Unit tests build their fixtures in code (small tar files, small JSON documents), so they run anywhere without Docker. Integration tests are marked `@pytest.mark.integration` and need Docker and the local registry.

### T1. Keys and the provenance generator (Day 1)

- **Keys.** Run `cosign generate-key-pair` inside `pipeline/keys/`. Commit `cosign.pub` only; `.gitignore` already lists `cosign.key`. Share the private key with teammates privately, never through the repo.
- **Provenance generator.** `pipeline/gen_provenance.py` is in the kit and already tested. Review it, run `python3 pipeline/gen_provenance.py --help`, and adjust the builder ID if the team agrees a different one.
  - It prints a **SLSA v1 predicate** (not a full in-toto statement; cosign wraps it).
  - cosign parses `slsaprovenance1` predicates into typed structs, so any field outside the SLSA v1 schema would be silently dropped. The generator uses the exact field names.
  - It records `buildDefinition.internalParameters.uncommittedChanges`, and warns when it is `true`, so a provenance never silently names a commit that differs from what was built. `internalParameters` is free-form, so cosign keeps it.

**Tests:** its output parses as JSON and has `buildDefinition.buildType`, `buildDefinition.resolvedDependencies[0].digest.gitCommit` and `runDetails.builder.id`.

### T2. Build and attest the stand-in image (Day 1)

Run `pipeline/build-and-attest.sh testbed/standin-app standin-app`. It prints the `ref@digest` on stdout and ends by verifying all three signatures with the public key. Fix the environment until it passes.

**Tests (integration):**

- `cosign verify --key pipeline/keys/cosign.pub <ref>` exits 0.
- `cosign verify-attestation --key pipeline/keys/cosign.pub --type cyclonedx <ref>` exits 0.
- The same with `--type slsaprovenance1` exits 0.
- `jq '.dependencies | length' run/attest/standin-app/sbom.json` is above 0.

The integration tests take the reference from `PROVBIND_STANDIN_REF` (the script's stdout) and never build or sign anything themselves.

### T3. Evidence module: `compiler/evidence.py` (Day 1–2)

The module fetches the verified evidence and runs the binding checks from the paper (Eqs. 10–18).

- **Signature (v_sig).** Run `cosign verify --key <pub> <ref>` and keep its stdout.
- **Attestations.** Run `cosign verify-attestation --key <pub> --type cyclonedx <ref>`, and the same with `--type slsaprovenance1`.
  - stdout has one JSON object per line.
  - If an object has a `payload` field, it is a DSSE envelope: base64-decode `payload` to get the in-toto statement.
  - If it already has `predicateType`, it is the statement itself.
  - Support both shapes (fact 2 in Section 5).
- **Binding (v_B and v_P).** Each statement's `subject[*].digest.sha256` must equal the image digest's hex, and its `predicateType` must be `https://cyclonedx.org/bom` or `https://slsa.dev/provenance/v1` respectively. If several attestations of one type exist, use the newest one that binds.
  - **Newest** means the latest predicate timestamp: `metadata.timestamp` for CycloneDX, `runDetails.metadata.finishedOn` for SLSA. On a tie or a missing timestamp, take the last line of cosign's output. cosign's own output order carries no time.
- **Rekor log index.** Search the `cosign verify` JSON *recursively* for the first integer under a key named `logIndex` or `log_index`. Accept a string of digits too, since protobuf's JSON encoding writes 64-bit integers as strings. If there is none, use `null`. Never fail on its absence.
- **Offline.** With `PROVBIND_OFFLINE=1`, every cosign command gets `--insecure-ignore-tlog=true`.
- **Signing identity.** From the provenance predicate, `builder_id = runDetails.builder.id`, and `source_commit` is the `digest.gitCommit` of the first `resolvedDependencies` entry that has one.

Any failure in v_sig, v_B or v_P raises `EvidenceError`. The CLI exits with **code 2** and a one-line reason, and **writes no envelope**.

**Tests:**

- Unit, with canned cosign output: both shapes decode; a wrong subject digest raises; a missing `logIndex` gives `None`.
- Integration: running it on the stand-in image returns an SBOM with components and a provenance with a commit.

### T4. Image fetch: `compiler/oci.py` (Day 1–2)

Use crane subcommands, not OCI-layout parsing:

1. `crane manifest <ref@digest>` gives the raw bytes. Check **v_M**: `sha256(raw bytes) == digest`.
2. If the manifest's `mediaType` is an index or manifest list, pick the entry with `platform.os == "linux"` and `platform.architecture == "amd64"`.
   - Skip entries whose annotations say `vnd.docker.reference.type: attestation-manifest`.
   - Fetch the chosen child manifest by digest, and check its v_M the same way.
3. `crane blob <repo>@<config.digest>` gives the config. Check **v_C**: `sha256(config bytes) == config.digest`.
4. For each layer, in manifest order, run `crane blob <repo>@<layer.digest>` into `run/cache/blobs/<hex>`. Verify its SHA-256 on download, and reuse a cached blob whose hash matches.
5. Return the ordered layers (`index`, `digest`, `mediaType`, path to the blob) and the parsed config (`Entrypoint`, `Cmd`, `Env`, `ExposedPorts`, `User`).

**Tests:**

- Unit: index selection skips attestation manifests; a hash mismatch raises.
- Integration: the stand-in image gives at least 4 layers and a config whose `Cmd` is `["python", "app.py"]`.

### T5. Layer union: `compiler/layers.py` (Day 2) ⚠ most important

Implement the two-pass union from Section 7.1.

- Read gzip layers with `tarfile`, zstd layers with `zstandard` (streaming), and uncompressed layers directly. Choose by `mediaType`, and fall back to magic bytes if the type is unknown.
- Normalise every tar name: strip a leading `./`, add a leading `/`, collapse `//`.
- Output three maps:
  - `files`: path → `(sha256, layer_index, mode)`, regular files only;
  - `links`: path → raw symlink target;
  - `dirs`: a set of directory paths, needed for opaque markers.

**Tests (unit, synthetic tars):**

| Test | Setup | Expected |
|---|---|---|
| Overwrite | L0 `/a/f` = "x"; L1 `/a/f` = "y" | `/a/f` has the hash of "y" and layer 1 |
| File whiteout | L0 `/a/f`; L1 `/a/.wh.f` | `/a/f` absent |
| Directory whiteout | L0 `/a/b/c`; L1 `/a/.wh.b` | `/a/b/c` absent |
| **Opaque after same-layer file** | L0 `/d/x`; L1 tar order `d/y`, then `d/.wh..wh..opq` | `/d/y` present, `/d/x` absent |
| Opaque before same-layer file | Same as above, marker first | Same result |
| Whiteout never hides its own layer | L1 has `/e/z` and `/e/.wh.z` | `/e/z` present |
| Hardlink | L0 `/usr/bin/a` regular, `/usr/bin/b` hardlink to it | `/usr/bin/b` has the same hash as `a` |
| Symlink | L0 `/bin` → `usr/bin` | `/bin` in `links`, not in `files` |
| Symlink replaces file | L0 `/x` file; L1 `/x` symlink | `/x` only in `links` |
| Symlink replaces directory | L0 `/x/a`; L1 `/x` → `/y` | `/x/a` absent |
| File replaces directory | L0 `/x/a`; L1 `/x` regular file | `/x/a` absent |
| Directory replaces symlink | L0 `/x` → `/y`; L1 directory `/x` with `/x/b` | `/x` not in `links`; `/x/b` present |
| Compression | the same layer as gzip, zstd and plain tar | Identical output |

### T6. Path resolution: `compiler/paths.py` (Day 2)

Implement `realpath(path, links)` from Section 7.2. It resolves symlinks at any position in the path, relative or absolute, and fails on a loop after 40 hops.

After the union, **canonicalise every file key** through `realpath` of its parent directory, so that any `/bin/foo` becomes `/usr/bin/foo` on merged-/usr images. Two keys that collide after canonicalisation keep the entry from the higher layer.

**Tests:**

| Input | Links | Expected |
|---|---|---|
| `/bin/ls` | `/bin` → `usr/bin` | `/usr/bin/ls` |
| `/usr/local/bin/python` | `python` → `python3`, `python3` → `python3.11` | `/usr/local/bin/python3.11` |
| `/opt/app/lib/x` | `/opt/app/lib` → `../shared` | `/opt/shared/x` |
| `/loop` | `/loop` → `/loop2`, `/loop2` → `/loop` | raises `SymlinkLoop` |
| `/bin/sh` | `/bin` → `usr/bin`, `/usr/bin/sh` → `dash` | `/usr/bin/dash` |

### T7. Execution and load closure: `compiler/closure.py` (Day 2)

Implement Section 7.3.

- The first executable is `Entrypoint[0]`, or `Cmd[0]` when there is no entrypoint. If `Entrypoint` is `["sh", "-c", …]`, include the shell only; parsing the command string is out of scope, so say so in a comment.
- Resolve it on the image's `PATH`, taken from the config `Env`.
- **Shebang lines:** `#!/usr/bin/env python3` adds `/usr/bin/env` and then resolves `python3` on `PATH`. `#!/bin/sh` adds the real path of `/bin/sh`.
- **ELF files (pyelftools):**
  - add the `PT_INTERP` path;
  - resolve each `DT_NEEDED` entry by searching, in order: `DT_RPATH` (only if there is no `DT_RUNPATH`), `LD_LIBRARY_PATH` from the config `Env`, `DT_RUNPATH`, the directories listed in `/etc/ld.so.conf` and its `include` globs, then `/lib`, `/usr/lib`, `/lib64`, `/usr/lib64`;
  - expand `$ORIGIN` to the directory of the file being examined.
- Every path added to the closure is a real path (use `paths.realpath`). A library that cannot be found is logged and skipped; it does not stop compilation.

**Tests:**

- Unit: shebang parsing, including `env` with flags such as `#!/usr/bin/env -S python3 -u`.
- Integration (stand-in image): the closure contains `/usr/local/bin/python3.11`, `/usr/local/lib/libpython3.11.so.1.0`, a `libc.so.6` and an `ld-linux-x86-64.so.2`, and does **not** contain `/usr/bin/ls` or `/usr/bin/dash`.

### T8. SBOM depth: `compiler/sbom.py` (Day 2)

Implement Section 7.4.

- Map each bom-ref to its component, and key packages by the component's `purl` field (use the bom-ref only if `purl` is missing).
- Add a synthetic application root at depth 0 with an edge to every component that has outgoing edges but no incoming ones. Then run a multi-source BFS, taking the minimum over paths.
- **A component that appears in no edge at all gets `depth: null` (unresolved).** Never default it to 1.
- Record `unresolved_fraction` = (components with a null depth) / (all components).

**Tests (synthetic CycloneDX):**

| Case | Expected |
|---|---|
| Chain A → B → C, with bom-refs carrying `?package-id=` | A 1, B 2, C 3 |
| Diamond A → B → C and A → C | C 2 (minimum) |
| D in no edge at all | D null |
| Two roots A1 → X and A2 → Y → X | X 2 |
| Cycle B → C → B under A | Terminates; B 2, C 3 |

### T9. Ownership: `compiler/owners.py` (Day 2)

Implement Section 7.5. Build `path → purl`:

- **dpkg:** read `/var/lib/dpkg/status` for name, version and architecture of installed packages. Then read `/var/lib/dpkg/info/<name>.list` and `<name>:<arch>.list`, which hold one absolute path per line and include directories.
  - **Every listed path goes through `realpath`**: merged-/usr images list `/bin/ls` while the file actually lives at `/usr/bin/ls`.
  - Only paths present in `files` are kept.
- **pip:** for each `*.dist-info/`, read `METADATA` (`Name`, `Version`) and `RECORD`, a CSV of `path,hash,size`. RECORD paths are relative to the directory that contains the dist-info folder, and may start with `../../` for scripts.
- **Matching to the SBOM:** parse purls with `packageurl-python`. Match deb packages on (name, version). Match pypi packages on (PEP 503-normalised name, version). **Ignore purl qualifiers** such as `?arch=amd64&distro=…`.
- A file claimed by no record gets `package: null`.
- A file whose record matches no SBOM component also gets `package: null`, and the compiler logs it. So every non-null `package` is a key of `packages` (Section 8).

**Tests:**

- Unit: a synthetic dpkg `.list` with `/bin/ls` on a merged-/usr link map maps `/usr/bin/ls` to the coreutils purl; a RECORD line `../../../bin/foo,,` resolves correctly; `Foo_Bar` normalises to `foo-bar`.
- Integration (stand-in image): the `requests` files are owned by `pkg:pypi/requests@…`, and `/usr/bin/ls` by a coreutils purl.

### T10. Capabilities: `compiler/caps.py` (Day 2)

Keep this simple; the demo never checks capabilities, but the contract requires the field.

- Apply `compiler/caps_allowlist.json` by package name.
- Add one rule: if any `ExposedPorts` entry is below 1024, add `CAP_NET_BIND_SERVICE`.
- Every entry gets `origin: "INFERRED"`.

**Tests:** the allowlist hits a package; the port rule fires for `80/tcp` and not for `8080/tcp`.

### T11. Envelope assembly and CLI: `compiler/compile.py` (Day 2)

```
python -m compiler.compile <ref@digest> --run $RUN [--key pipeline/keys/cosign.pub] [--registry-name localhost:5001]
```

- Pipeline: preflight → evidence → fetch → union → canonicalise → closure → SBOM → owners → caps → assemble.
  - **Preflight:** `crane manifest <ref>`, writing nothing. If it fails, exit 3, so an unreachable registry is never reported as failed evidence.
- `--registry-name HOST` fetches from `HOST` instead of the reference's own registry host, for example when the compiler runs on a different machine from the registry. crane and cosign both use it; `image.ref` is written exactly as given.
- Before writing, validate against `contracts/envelope.schema.json` with `jsonschema`.
- Write the file atomically.
- stdout: the envelope path. stderr: progress and timings per step.

| Exit code | Meaning |
|---|---|
| 0 | Envelope written |
| 1 | Unexpected error |
| 2 | Evidence failed verification or binding, or a v_M, v_C or blob hash mismatch; nothing written |
| 3 | Bad input (reference not by digest, registry unreachable or image missing, platform other than linux/amd64) |

**Tests:** a golden-file test on a small synthetic image built from the unit fixtures; the schema check rejects a missing field.

### T12. Integration (Day 3)

1. Run T2 and T11 on the stand-in image, and check the Section 1 "done when" list (the stand-in has no test package, so use `requests` in its place).
2. When Role 1's `testbed/demo-app/` arrives: build and attest it, compile it, and post `ref@digest` and the envelope path to the team.
3. Give Role 3 the real envelope; they replay their tests against it. Fix what fails, which is usually path canonicalisation.
4. Target compile time: under 60 s on the demo PC for the demo image. Report the real number; it goes on a slide.

---

## 7. Algorithms

### 7.1 Two-pass layer union

```python
def union(layers):                                   # layers in manifest order
    files, links, dirs = {}, {}, set()
    for i, layer in enumerate(layers):
        new_files, new_links, new_dirs = {}, {}, set()
        gone, opaque = set(), set()
        pending_hardlinks = []
        for e in iter_entries(layer):                # normalised names: "/a/b"
            d, base = dirname(e.name), basename(e.name)
            if base == ".wh..wh..opq":
                opaque.add(d)                        # hide lower-layer children of d
            elif base.startswith(".wh."):
                gone.add(join(d, base[4:]))          # hide that path and its subtree
            elif e.isdir():
                new_dirs.add(e.name)
            elif e.issym():
                new_links[e.name] = e.linkname
            elif e.islnk():
                pending_hardlinks.append((e.name, norm(e.linkname)))
            elif e.isreg():
                new_files[e.name] = (sha256_stream(e), i, oct_mode(e))
        # pass 1: this layer's deletions apply to LOWER layers only
        hidden = lambda p: any(p == g or p.startswith(g + "/") for g in gone) \
                        or any(p.startswith(o + "/") for o in opaque)
        files = {p: v for p, v in files.items() if not hidden(p)}
        links = {p: v for p, v in links.items() if not hidden(p)}
        dirs  = {p for p in dirs if not hidden(p)}
        # pass 2: add this layer's entries. Unless both are directories, a new entry replaces
        # the lower one at the same path, and a new non-directory also removes the lower
        # subtree under it (OCI "changeset over existing files").
        nondirs = set(new_files) | set(new_links) | {n for n, _ in pending_hardlinks}
        under = lambda p: any(p == n or p.startswith(n + "/") for n in nondirs)
        files = {p: v for p, v in files.items() if not under(p)}
        links = {p: v for p, v in links.items() if not under(p)}
        dirs  = {p for p in dirs if not under(p)}
        for p in new_dirs:
            files.pop(p, None); links.pop(p, None)
        files.update(new_files); links.update(new_links); dirs |= new_dirs
        for name, target in pending_hardlinks:       # target may be in this layer or lower
            src = new_files.get(target) or files.get(target)
            if src:
                files[name] = (src[0], i, src[2])
    return files, links, dirs
```

### 7.2 Symlink resolution

```python
def realpath(path, links, max_hops=40):
    parts, resolved, hops = split(path), "/", 0
    while parts:
        part = parts.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            resolved = parent(resolved)
            continue
        candidate = join(resolved, part)
        if candidate in links:
            hops += 1
            if hops > max_hops:
                raise SymlinkLoop(path)
            target = links[candidate]
            if target.startswith("/"):
                resolved = "/"
            parts = split(target) + parts          # a relative target resolves against `resolved`
        else:
            resolved = candidate
    return resolved
```

### 7.3 Closure worklist

```python
def closure(config, files, links):
    env = parse_env(config.Env)
    work, Q = [first_executable(config)], set()
    while work:
        name = work.pop()
        p = resolve_exe(name, env["PATH"], files, links)       # absolute, or searched on PATH
        if p is None or p in Q:
            continue
        Q.add(p)
        head = read_head(p, 256)
        if head.startswith(b"#!"):
            interp, args = parse_shebang(head)
            work.append(interp)
            if basename(interp) == "env" and args:
                work.append(first_non_flag(args))              # env -S python3 -u -> python3
        elif head.startswith(b"\x7fELF"):
            elf = parse_elf(p)                                 # pyelftools
            if elf.interp:
                work.append(elf.interp)
            for soname in elf.needed:
                lib = find_library(soname, elf, env, files, links)   # search order in T7
                if lib:
                    work.append(lib)
    return Q
```

### 7.4 Depth with a synthetic root

```python
def depths(bom):
    comp = {c["bom-ref"]: c for c in bom["components"]}
    edges = {d["ref"]: d.get("dependsOn", []) for d in bom.get("dependencies", [])}
    touched = set(edges) | {t for ts in edges.values() for t in ts}
    has_in = {t for ts in edges.values() for t in ts}
    roots = [r for r in edges if edges[r] and r not in has_in]
    depth, q = {}, deque()
    for r in roots:
        depth[r] = 1                                  # synthetic app root is depth 0
        q.append(r)
    while q:
        u = q.popleft()
        for v in edges.get(u, []):
            if v not in depth:
                depth[v] = depth[u] + 1
                q.append(v)
    out = {}
    for ref, c in comp.items():
        key = c.get("purl") or ref
        out[key] = {"depth": depth.get(ref) if ref in touched else None}
    return out
```

A cycle with no entry from a root (every member has an incoming edge) leaves its members with `None`. That is correct: nothing signed says how they are reached.

### 7.5 Ownership

```python
def owners(files, links, fs):                        # fs reads file bytes from the union
    owner = {}
    for pkg in dpkg_installed(fs):                   # name, version, arch from status
        for listed in dpkg_list(fs, pkg):
            real = realpath(listed, links)
            if real in files:
                owner[real] = ("deb", pkg.name, pkg.version)
    for dist in dist_info_dirs(files):
        name, version = read_metadata(fs, dist)
        site = dirname(dist)
        for rel in read_record(fs, dist):
            real = realpath(normpath(join(site, rel)), links)
            if real in files:
                owner[real] = ("pypi", pep503(name), version)
    return owner                                     # matched to SBOM purls in compile.py
```

---

## 8. The envelope contract

`contracts/envelope.schema.json` is the machine-checkable contract, and `contracts/envelope.sample.json` passes it. The sprint handoff's Section 4.1 remains the human-readable version. Rules that the schema cannot express:

- **Real paths only.** Every path in `files`, `closure` and `symlinks` values is a real absolute path. Role 3 compares them directly with Tetragon's paths.
- **`files` holds regular files only.** Symlinks live in `symlinks` as `link path → fully resolved real target` (or `null` if the link dangles). Directories are not listed.
- **`files[p].layer` is the index** of the layer that provided the effective version.
- **`files[p].mode` is `"0%03o" % (mode & 0o7777)`:** `"0755"` for a normal file, `"04755"` for a setuid one.
- **`packages` keys are the SBOM's `purl` strings, verbatim,** qualifiers included. Consumers treat them as opaque IDs.
- **Every non-null `files[p].package` is a key of `packages`.**
- **`depth: null` means unresolved;** `package: null` means no record claims the file, or the record matches no SBOM component.
- **`image.builder_id` must be a URI,** because SLSA v1 requires one. The generator uses `https://github.com/sf9-26/provbind/builders/local@v1`. The sprint handoff's sample value `sf9-26/local-build` was only illustrative; tell Roles 3 and 4 the real value.
- **Optional fields** are allowed, and readers ignore unknown fields. The compiler adds `verification` (the v_sig, v_M, v_C, v_B, v_P results) and `timings_ms`, which are useful on a slide.

---

## 9. Module layout

```
pipeline/
  build-and-attest.sh        given, verified flags (Section 5)
  gen_provenance.py          given, tested
  keys/cosign.pub            committed;  keys/cosign.key never committed
  tests/                     T1 unit test, T2 integration tests
compiler/
  __init__.py
  compile.py                 CLI and orchestration (T11)
  evidence.py                cosign verify and verify-attestation, binding checks (T3)
  oci.py                     crane manifest, config and blobs, v_M and v_C (T4)
  layers.py                  two-pass union (T5)
  paths.py                   realpath, key canonicalisation (T6)
  closure.py                 entrypoint closure (T7)
  sbom.py                    CycloneDX depth (T8)
  owners.py                  dpkg and pip ownership (T9)
  caps.py                    capabilities (T10)
  caps_allowlist.json        given, starter
  tests/                     unit and integration tests
contracts/
  envelope.schema.json       given
  envelope.sample.json       given
testbed/standin-app/         given: Dockerfile, app.py, requirements.txt
pytest.ini                   deselects integration tests unless -m integration is given
```

---

## 10. Pitfalls checklist

- [ ] The digest is always the one the image was **pushed** as, never a local image ID.
- [ ] Use manifest layer digests, never the config's `rootfs.diff_ids`.
- [ ] Handle an image index even though the script avoids creating one.
- [ ] Whiteouts: two passes per layer (T5 tests prove it).
- [ ] Canonicalise all keys through `realpath`, including dpkg `.list` entries (merged `/usr`).
- [ ] Read only verified evidence; exit code 2 on any binding failure.
- [ ] Never treat missing SBOM edges as depth 1.
- [ ] Ignore purl qualifiers when matching; keep them in the keys.
- [ ] Write envelopes atomically: a temp file, then rename.
- [ ] `sh -c "…"` entrypoints: the closure covers only the shell. Say so in the slide notes.
- [ ] Signing with public Rekor publishes the image reference and signature in a public log. That is fine for test images; never sign anything private this way. Offline, set `PROVBIND_OFFLINE=1`: the build script then signs with `--tlog-upload=false`, and the script and the compiler verify with `--insecure-ignore-tlog=true`. Tell the team, since the demo then skips transparency.

---

## 11. Coordination

| When | You give | To | You get |
|---|---|---|---|
| Day 1 kickoff | Agreement on Section 4.1 of the sprint handoff and this schema | Everyone | — |
| Day 1 evening | `cosign.pub` committed; private key shared privately | Role 4 | — |
| Day 1 end | — | — | `testbed/demo-app/` from Role 1 |
| Day 2 evening | One real envelope (stand-in image) for the mock integration | Roles 3, 4 | Bug reports |
| Day 3 noon | Demo image `ref@digest` and its envelope | Everyone | — |
| Day 4 | Slides: what is signed, what the envelope holds, one screenshot | Role 4 (slide merge) | — |

---

## 12. Resources

**Specifications**

- [OCI image layer spec: changesets and whiteouts](https://github.com/opencontainers/image-spec/blob/main/layer.md)
- [OCI image manifest spec](https://github.com/opencontainers/image-spec/blob/main/manifest.md) and [image index spec](https://github.com/opencontainers/image-spec/blob/main/image-index.md)
- [SLSA provenance v1](https://slsa.dev/spec/v1.0/provenance)
- [in-toto attestation framework](https://github.com/in-toto/attestation)
- [CycloneDX specification](https://cyclonedx.org/specification/overview/)
- [Package URL (purl) specification](https://github.com/package-url/purl-spec)
- [Python: recording installed projects (RECORD and METADATA)](https://packaging.python.org/en/latest/specifications/recording-installed-packages/)
- [PEP 503: name normalisation](https://peps.python.org/pep-0503/)
- [ld.so(8): library search order, `$ORIGIN`](https://man7.org/linux/man-pages/man8/ld.so.8.html)

**Tools**

- [cosign attest](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md) · [cosign releases and v3 notes](https://github.com/sigstore/cosign/releases)
- [crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane)
- [syft](https://github.com/anchore/syft)
- [docker buildx build: `--provenance`, `--sbom`](https://docs.docker.com/reference/cli/docker/buildx/build/)
- [pyelftools](https://github.com/eliben/pyelftools)
- [zstandard for Python](https://github.com/indygreg/python-zstandard)
- [packageurl-python](https://github.com/package-url/packageurl-python)

**Project context**

- *PROVBIND Sprint Handoff v1.0*: run folder, commands, contracts, schedule.
- *PROVBIND: Project Explanation and Review of Aj Ohm's Draft*, §4 (Phase 1) and §6 (Phase 3): the design behind this role.
- Aj Ohm's draft, Phase 1 (Eqs. 1–6) and Phase 3 (Eqs. 24–49): the notation the slides should use.

---

## 13. Open decisions for Korn

1. **The builder ID string.** It must be a URI; agree one with the team on Day 1.
2. **Where depth counts from.** The synthetic root puts top-level packages at depth 1, and depth 0 is reserved for the application. Aj Ohm's Eq. (29) measures distance from the SBOM's root components; confirm this reading.
3. **Application files owned by no package** (e.g. `/app/app.py`) score with `rho = 0.5` in Role 4's demo rules. An alternative is to treat them as depth 0. Decide with Role 4.

Decisions D1–D6 in `docs/ROLE2-HANDOFF-NOTES.md` were agreed on 26 September and are folded into this file. That file also lists implementation notes and notes for Roles 3 and 4.

---

## 14. Status

| Task | Status | Notes |
|---|---|---|
| T1 Keys and provenance | Partly done | Generator test green (`pipeline/tests/`); `uncommittedChanges` added. The key pair is still to generate: no `cosign.pub` yet |
| T2 Build and attest stand-in | Script ready, not run | Builds linux/amd64, supports `PROVBIND_OFFLINE`; fake-tool test green. Integration tests written; they need Docker and `PROVBIND_STANDIN_REF` |
| T3 Evidence | Unit done | `compiler/evidence.py`; DSSE, bare and bundle shapes, binding, newest by timestamp (D2), logIndex search (38 tests). Integration test needs cosign and the stand-in |
| T4 Image fetch | Unit done | `compiler/oci.py`; v_M, v_C, blob cache, index selection skipping attestation manifests, platform check (D6), `--registry-name` (D4) (29 tests). Integration test needs the stand-in |
| T5 Layer union | Done | `compiler/layers.py`; all T5 rows incl. the D1 rows green (36 tests); mutation-checked against single-pass whiteouts |
| T6 Path resolution | Done | `compiler/paths.py`; T6 table, canonical keys (higher layer wins), symlink targets incl. implicit dirs (20 tests) |
| T7 Closure | Not started | |
| T8 SBOM depth | Done | `compiler/sbom.py`; T8 table plus duplicates, OS component, nested and empty SBOMs (15 tests) |
| T9 Ownership | Not started | |
| T10 Capabilities | Done | `compiler/caps.py` (+ `compiler/purls.py` helpers); allowlist hit, 80/tcp vs 8080/tcp (12 tests) |
| T11 Envelope and CLI | Not started | |
| T12 Integration | Not started | |
