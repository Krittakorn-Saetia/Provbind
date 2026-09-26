# Role 2 Handoff: Review Notes

**PROVBIND sprint · Notes on `docs/ROLE2-HANDOFF.md` Draft v0.1 · 26 September 2026**

These notes come from reviewing the handoff against the kit as committed (`80e1972`). The handoff stays the spec, and these notes change nothing in it until Korn agrees. Fold each agreed item into the handoff (§6, §7 or §13) and mark it **Agreed** in the table in Section 2.

Nothing here requires a change to `contracts/`.

---

## 1. Checks already run

- `contracts/envelope.sample.json` validates against `contracts/envelope.schema.json` (JSON Schema 2020-12). Removing a required field makes validation fail, as T11 expects.
- `python3 pipeline/gen_provenance.py --context testbed/standin-app` prints the three fields T1 tests: `buildDefinition.buildType`, `buildDefinition.resolvedDependencies[0].digest.gitCommit` and `runDetails.builder.id`. The base-image digest also needs `crane` on `PATH`.
- A literal transcription of §7.1, §7.2 and §7.4 passes all 19 logic rows of the T5, T6 and T8 tables. T5's compression row tests the tar reader, not the algorithm. The transcription fails the three cases in D1.

---

## 2. Decisions needed

| # | Topic | Proposed default | Status |
|---|---|---|---|
| D1 | §7.1 misses three OCI replacement cases | Fix pass 2; add three T5 rows | Open |
| D2 | "Newest" attestation has no clock | Choose by the predicate's own timestamp | Open |
| D3 | Exit code 2 vs 3 | Registry preflight gives 3; any hash mismatch gives 2 | Open |
| D4 | `--registry-name` is undefined | Host to fetch from; `image.ref` unchanged | Open |
| D5 | File claimed by dpkg or pip, but no matching SBOM component | `package: null`, logged | Open |
| D6 | Gaps in the given build script and generator | Pin the platform; flag dirty trees; add an offline switch | Open |

### D1. The layer union misses three OCI replacement cases (§7.1)

The OCI layer spec ("Changeset over existing files") says: unless the new entry and the existing path are both directories, the existing path is removed, with its children if it is a directory, and the new entry is applied. §7.1 pass 2 removes a lower entry only at exactly the same path, and only for new files and symlinks. These cases go wrong:

| Test | Setup | Expected | §7.1 today |
|---|---|---|---|
| Symlink replaces directory | L0 `/x/a`; L1 `/x` → `/y` | `/x/a` absent | `/x/a` kept |
| File replaces directory | L0 `/x/a`; L1 `/x` regular file | `/x/a` absent | `/x/a` kept |
| Directory replaces symlink | L0 `/x` → `/y`; L1 directory `/x` with `/x/b` | `/x` not in `links` | `/x` stays a link |

T6 then makes the damage visible: canonicalisation moves each stale entry under the link target. In the first case the envelope gains a phantom `/y/a`. In the third it reports `/x/b` as `/y/b`.

BuildKit seldom writes such layers, because its diffs record real paths. The fix is still small:

- In pass 2, a new non-directory entry at `P` (file, symlink or hardlink) removes lower files, links and dirs at `P` and under `P + "/"`.
- A new directory at `P` removes a lower file or link at exactly `P`.

**Default:** make this change and add the three rows to the T5 tests. §7.1 says "follow exactly", so this needs Korn's agreement.

### D2. "Use the newest attestation that binds" has no clock (T3)

cosign prints the matching attestations one per line, in no documented time order, and a DSSE envelope carries no timestamp. Several attestations for one digest are normal. Rebuilding an unchanged context gives the same digest, and cosign adds a new attestation on every run unless told to replace it. The new provenance can name a different commit, for example after a commit that only touched docs.

**Default:** the newest attestation is the one with the latest CycloneDX `metadata.timestamp` (SBOM) or SLSA `runDetails.metadata.finishedOn` (provenance). On a tie or a missing timestamp, take the last line of output. An alternative to check is `cosign attest --replace` in the build script.

### D3. Exit code 2 or 3 (T11)

The pipeline runs evidence before fetch, so with an unreachable registry `cosign verify` fails first. That exits 2, but the exit-code table says an unreachable registry is 3. The table also gives no code for a v_M, v_C or blob-hash failure.

**Default:** run `crane manifest <ref>` first, writing nothing; if it fails, exit 3. A v_M, v_C or blob-hash mismatch exits 2, because the fetched content does not match the signed digest. Neither case writes anything.

### D4. What `--registry-name` means (T11)

The flag is in the T11 synopsis but never explained. It can be read two ways:

- (a) the registry host to fetch from, when that differs from the host in the reference (for example, when the compiler runs on a different machine from the registry);
- (b) the host to write into `image.ref`.

**Default:** (a), with `image.ref` written exactly as given, since the digest identifies the image. This needs confirmation.

### D5. A file claimed by dpkg or pip, but no matching SBOM component (T9)

T9 matches dpkg and pip records to SBOM purls, but says nothing about a record with no match, for example when syft missed a package or reports a different version.

**Default:** `package: null`, with the file and the record logged. Roles 3 and 4 then get a rule they can rely on: every non-null `files[p].package` is a key of `packages`. The alternative is to synthesise a purl and add it to `packages` with `depth: null`.

### D6. Gaps in the given build script and generator

- **Platform.** `docker build` has no `--platform` flag. On an Apple Silicon Mac the pushed image is linux/arm64. T4 checks the platform only inside an index, so the compiler accepts it; the first thing to fail would be the T7 integration test, which expects `ld-linux-x86-64.so.2`.
  - *Default:* add `--platform linux/amd64` to the build. The compiler checks the config's `os` and `architecture` and exits 3 on anything else.
- **Uncommitted changes.** `gen_provenance.py` records `git rev-parse HEAD` even when the context has uncommitted changes, so the provenance can name a commit that is not what was built.
  - *Default:* warn, and record the uncommitted state in `buildDefinition.internalParameters`. That field is free-form, so cosign keeps it.
- **Multi-stage Dockerfiles.** `first_from` records the first `FROM`, but in a multi-stage build the runtime base is the final stage's.
  - *Default:* leave it until Role 1's Dockerfile arrives, and fix it only if that Dockerfile is multi-stage.
- **Offline signing.** §10 describes signing without Rekor, but nothing implements it. The flags are `--tlog-upload=false` for signing and `--insecure-ignore-tlog=true` for verifying. The build script's sign, attest and verify steps need them, and so does the compiler's evidence step.
  - *Default:* one environment variable, for example `PROVBIND_OFFLINE=1`, read by both. The envelope then has `rekor_log_index: null`. Tell the team, since the demo then skips transparency.

---

## 3. Implementation notes (no spec change)

These cover cases the handoff doesn't address and keep within what it asks for.

1. **Mode strings for setuid files.** Debian slim ships setuid binaries (`su`, `passwd`, `mount`). `"%04o"` turns mode `04755` into `"4755"`, which the schema's `^0[0-7]{3,4}$` rejects, so compilation would fail on the real image but not in the unit tests. Write `"0%03o" % (mode & 0o7777)`, and include one setuid file in the unit fixtures.
2. **Symlink keys and values.** Canonicalise each link key's parent, as T6 does for file keys; the sample has `/usr/bin/sh`, not `/bin/sh`. The value is the link's full real path.
   - The value is `null` (dangling) only when the target is neither a file nor a directory. Directories include the implicit parents of files, because layers do not always carry explicit directory entries.
   - A link loop gives `null` and a log line, not a crash. A file under a looping parent is dropped and logged.
3. **Reading file contents after the union.** §7.3 (`read_head`, `parse_elf`) and §7.5 (`fs`) read file bytes, but T5 returns only `(sha256, layer_index, mode)`. Plan:
   - The union also records which layer and tar member provides each file. A hardlink points at its target's member.
   - Each layer is decompressed once into a temporary directory outside `$PROVBIND_RUN`, and members are read by offset.
   - The directory is deleted on exit, so the run folder keeps its layout.
4. **Test commands.** Nothing deselects integration tests, so `pytest -q` runs them too. A root `pytest.ini` with `addopts = -m "not integration"` makes the `CLAUDE.md` commands mean what they say; `pytest -q -m integration` overrides it. `compiler/__init__.py` (listed in §9) is needed for `python -m compiler.compile` and for the tests' imports.
5. **T1 test.** The handoff calls `gen_provenance.py` "already tested", but no test is committed. T1 adds one.
6. **Rekor log index.** Accept an integer or a string of digits under `logIndex` or `log_index`. Protobuf's JSON encoding writes 64-bit integers as strings, and cosign v3's bundle format may use it.
7. **Media types.** Depending on Docker's image store, `docker push` writes Docker v2 media types (`application/vnd.docker.distribution.manifest.v2+json`, `application/vnd.docker.image.rootfs.diff.tar.gzip`) or OCI ones. Handle both.
   - When the type is unknown, check the magic bytes: gzip `1f 8b`, zstd `28 b5 2f fd`.
   - An older manifest may omit `mediaType`. A `manifests` key means an index; a `layers` key means an image manifest.
8. **Tar names.** Besides T5's three rules, strip a trailing `/`, resolve `.` and `..` lexically, and skip the root entry.
9. **Closure inputs.**
   - Also parse the config's `WorkingDir`, for relative entrypoints such as `./start.sh`.
   - If `Env` has no `PATH`, use the runtime default `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`.
   - In `env` shebangs, skip `NAME=value` tokens as well as flags.
10. **SBOM edge cases.** Merge duplicate purls, keeping the minimum non-null depth. Count only package components: syft's `operating-system` component, if present, would otherwise land in `packages` with `depth: null` and inflate `unresolved_fraction`. With no components at all, `unresolved_fraction` is 0.
11. **Golden test and atomic write (T11).**
    - Keep envelope assembly a pure function of the evidence and the fetched image, so the golden test needs neither cosign nor crane.
    - Fix `compiled_at` and drop `timings_ms` before comparing.
    - Give the temp file a name that doesn't end in `.json` (for example `.<hex>.json.tmp`), so readers that glob `envelopes/*.json` never see it.

---

## 4. Notes for Roles 3 and 4

The sample envelope does not show these. The first real envelope, due Day 2 evening, will.

1. **Depth.** syft emits dependency edges between Debian packages, and the Debian graph never connects to the PyPI graph. Under the synthetic root (§7.4), every Debian package that depends on something and that nothing depends on becomes a root at depth 1.
   - Expect many OS packages at depth 1, like `requests`, probably including coreutils (`/usr/bin/ls`) and dash. Expect libc6 at depth 2.
   - The sample's values (libc6 at 3; coreutils and dash `null`) are illustrative only. Calibrate scoring on the real envelope.
   - This affects open decision 2 (§13).
2. **The interpreter has no owner.** The official `python` images build Python from source into `/usr/local`, so no dpkg or pip record claims `/usr/local/bin/python3.11` or `/usr/local/lib/libpython3.11.so.1.0`. Both get `package: null`, as in the sample.
   - Under Role 4's demo rule (unowned files score `rho = 0.5`), the interpreter scores the same as `/app/app.py`.
   - syft's binary cataloger probably lists them as `pkg:generic/python@3.11.x` with their paths, which could become a third ownership source in T9.
   - This affects open decision 3.
3. **Package references.** If D5's default is agreed, every non-null `files[p].package` is a key of `packages`.
4. **Builder ID.** The generator and the schema's `$id` use `https://github.com/sf9-26/provbind/…`, but the team repo is `github.com/Krittakorn-Saetia/Provbind`. They work as identifiers, since `builder_id` only has to be a URI, but choose the value on purpose (open decision 1) and tell Roles 3 and 4 the final one.
