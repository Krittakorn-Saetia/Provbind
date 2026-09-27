# Ω_I: ML-A features (version 1)

This is the definition of the feature extractor in Aj Ohm's draft, Eq. (32):

    z_I = Ω_I(𝒞_cfg, 𝒫*_I, 𝒬_I, C_I)

The draft names the four inputs but not the features. Test Plan §4.3 proposed the list below, and `ml/features.py` implements it. MLA-02 checks that every feature the code produces is listed here, and that everything listed here exists in the code.

- **Shape.** A vector of floats in the order of the tables below. Its length is fixed for a given package vocabulary: 46 features plus one per vocabulary entry, so 146 with the full vocabulary of 100.
- **Determinism.** The same inputs always give the same vector. Nothing depends on the clock, on randomness, or on the order of dictionaries, sets or lists.
- **Missing values** are NaN (`null` in JSON), and LightGBM treats them as missing.

## Configuration (𝒞_cfg: the image config)

| Feature | Meaning | Values |
|---|---|---|
| `cfg.runs_as_root` | `User` is empty, `root` or uid `0` (a named user is assumed not to be root) | 0 or 1 |
| `cfg.user_set` | `User` is set | 0 or 1 |
| `cfg.exposed_ports` | Number of `ExposedPorts` entries | count |
| `cfg.port_below_1024` | Any exposed port below 1024 | 0 or 1 |
| `cfg.env_vars` | Number of `Env` entries | count |

## Packages (𝒫*_I: the envelope's `packages`)

All packages in the envelope, the SBOM's full package set. The draft calls 𝒫*_I the "package closure" but does not define reachability further.

| Feature | Meaning | Values |
|---|---|---|
| `pkg.count.apk` | Packages whose purl type is `apk` | count |
| `pkg.count.cargo` | … `cargo` | count |
| `pkg.count.composer` | … `composer` | count |
| `pkg.count.deb` | … `deb` | count |
| `pkg.count.gem` | … `gem` | count |
| `pkg.count.generic` | … `generic` (e.g. syft's binary cataloger) | count |
| `pkg.count.golang` | … `golang` | count |
| `pkg.count.maven` | … `maven` | count |
| `pkg.count.npm` | … `npm` | count |
| `pkg.count.nuget` | … `nuget` | count |
| `pkg.count.pypi` | … `pypi` | count |
| `pkg.count.rpm` | … `rpm` | count |
| `pkg.count.other` | Any other type, or a key that is not a purl | count |
| `pkg.has.<type>/<name>` | The image has this package, for each entry of the vocabulary | 0 or 1 |

**Vocabulary.** The `pkg.has.*` features are one per entry of a vocabulary of 100 package ids. An id is `<purl type>/<name>`, for example `pypi/requests` or `deb/libc6`: no version, qualifiers or namespace, and pypi names are PEP 503-normalised. `build_vocabulary` picks the ids that appear in the most training images, breaking ties by name, and the vocabulary is stored with the model so that inference builds the same vector.

## Closure (𝒬_I: the envelope's `closure`)

| Feature | Meaning | Values |
|---|---|---|
| `clo.size` | Number of executables and libraries in the closure | count |
| `clo.interp.python` | A closure file is a Python interpreter or libpython | 0 or 1 |
| `clo.interp.node` | … a Node.js binary or libnode | 0 or 1 |
| `clo.interp.java` | … `java` or `libjvm.so` | 0 or 1 |
| `clo.interp.shell` | … a shell: `sh`, `bash`, `dash`, `ash`, `zsh`, `ksh`, `mksh` or `busybox` | 0 or 1 |
| `clo.static` | The closure is non-empty and has no dynamic loader (`ld-linux*` or `ld-musl*`) | 0 or 1 |

## ELF imports across the closure's binaries (𝒬_I, read from the image)

Each feature is 1 if any ELF file in the closure imports the function, meaning it has an undefined dynamic symbol of that name. The compiler reads the symbols from the image with `closure_imports()`. An envelope alone does not contain them, so without that input all nineteen are NaN.

| Feature | Meaning | Values |
|---|---|---|
| `imp.socket` | imports `socket` | 0, 1 or NaN |
| `imp.bind` | imports `bind` | 0, 1 or NaN |
| `imp.listen` | imports `listen` | 0, 1 or NaN |
| `imp.connect` | imports `connect` | 0, 1 or NaN |
| `imp.setuid` | imports `setuid` | 0, 1 or NaN |
| `imp.setgid` | imports `setgid` | 0, 1 or NaN |
| `imp.setgroups` | imports `setgroups` | 0, 1 or NaN |
| `imp.chown` | imports `chown` | 0, 1 or NaN |
| `imp.fchown` | imports `fchown` | 0, 1 or NaN |
| `imp.chmod` | imports `chmod` | 0, 1 or NaN |
| `imp.mount` | imports `mount` | 0, 1 or NaN |
| `imp.umount2` | imports `umount2` | 0, 1 or NaN |
| `imp.ptrace` | imports `ptrace` | 0, 1 or NaN |
| `imp.capset` | imports `capset` | 0, 1 or NaN |
| `imp.prctl` | imports `prctl` | 0, 1 or NaN |
| `imp.chroot` | imports `chroot` | 0, 1 or NaN |
| `imp.setns` | imports `setns` | 0, 1 or NaN |
| `imp.unshare` | imports `unshare` | 0, 1 or NaN |
| `imp.sethostname` | imports `sethostname` | 0, 1 or NaN |

## Deployment (C_I: the pod's securityContext)

Envelopes are compiled per image, not per pod. When no pod is known, the default pod is assumed: not privileged, and nothing added or dropped. The profiling corpus records each pod's securityContext.

| Feature | Meaning | Values |
|---|---|---|
| `dep.privileged` | The container is privileged | 0 or 1 |
| `dep.caps_added` | Capabilities it has beyond the runtime's 14 defaults | count |
| `dep.caps_dropped` | Runtime defaults it does not have (`drop: [ALL]` counts all 14) | count |

The effective set is computed the way containerd builds it from a securityContext (`ml/alg1.py`, `effective_set`).
