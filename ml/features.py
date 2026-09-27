"""Ω_I, the ML-A feature extractor (Aj Ohm's draft, Eq. 32; Test Plan §4.3).

    z_I = Ω_I(𝒞_cfg, 𝒫*_I, 𝒬_I, C_I)

z_I is a named vector of floats whose length is fixed for a given package vocabulary.
ml/features.md lists every feature; that list is the definition of Ω_I the paper lacks. The
same inputs always give the same vector (MLA-02): no clock, no randomness, and no dependence
on dict, set or list order.

Inputs besides the envelope:
- the image config (User, ExposedPorts, Env);
- `imports`: the dynamic symbols each closure binary imports, which only the image's files can
  tell; closure_imports() reads them during compilation. Without them the imp.* features are
  NaN, which LightGBM treats as missing;
- `deployment`: the pod's securityContext. The compiler works per image, so without it the
  default pod is assumed: not privileged, nothing added or dropped.
"""
from __future__ import annotations

import logging
import math
import posixpath
import re
from collections import Counter
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Mapping, Protocol, Sequence

from elftools.elf.elffile import ELFFile

from compiler import purls

from .alg1 import RUNTIME_DEFAULT_CAPS, effective_set

log = logging.getLogger("provbind.ml.features")

FEATURES_VERSION = 1
VOCABULARY_SIZE = 100
ECOSYSTEMS = ("apk", "cargo", "composer", "deb", "gem", "generic", "golang", "maven", "npm", "nuget", "pypi", "rpm")
WATCHED_SYMBOLS = ("socket", "bind", "listen", "connect", "setuid", "setgid", "setgroups", "chown", "fchown",
                   "chmod", "mount", "umount2", "ptrace", "capset", "prctl", "chroot", "setns", "unshare",
                   "sethostname")
_INTERPRETERS = (
    ("python", re.compile(r"^(python\d*(\.\d+)*|libpython\d[\d.]*\.so(\.[\d.]+)?)$")),
    ("node", re.compile(r"^(node|nodejs|libnode\.so(\.[\d.]+)?)$")),
    ("java", re.compile(r"^(java|libjvm\.so)$")),
    ("shell", re.compile(r"^(sh|bash|dash|ash|zsh|ksh|mksh|busybox)$")),
)
_LOADER = re.compile(r"^ld-(linux|musl)[^/]*\.so")

CONFIG_FEATURES = ("cfg.runs_as_root", "cfg.user_set", "cfg.exposed_ports", "cfg.port_below_1024", "cfg.env_vars")
CLOSURE_FEATURES = ("clo.size",) + tuple(f"clo.interp.{name}" for name, _ in _INTERPRETERS) + ("clo.static",)
DEPLOYMENT_FEATURES = ("dep.privileged", "dep.caps_added", "dep.caps_dropped")


class ImageFS(Protocol):
    def read(self, path: str, n: int | None = None) -> bytes | None: ...
    def open(self, path: str) -> BinaryIO | None: ...


@dataclass(frozen=True)
class FeatureVector:
    names: tuple[str, ...]
    values: tuple[float, ...]

    def as_dict(self) -> dict[str, float]:
        return dict(zip(self.names, self.values))

    def to_json(self) -> dict[str, float | None]:
        """For JSON files: NaN (missing) becomes null."""
        return {n: (None if math.isnan(v) else v) for n, v in zip(self.names, self.values)}


def feature_names(vocabulary: Sequence[str] = ()) -> tuple[str, ...]:
    """The features, in vector order, for a package vocabulary (see build_vocabulary)."""
    names = (CONFIG_FEATURES
             + tuple(f"pkg.count.{e}" for e in ECOSYSTEMS) + ("pkg.count.other",)
             + tuple(f"pkg.has.{v}" for v in vocabulary)
             + CLOSURE_FEATURES
             + tuple(f"imp.{s}" for s in WATCHED_SYMBOLS)
             + DEPLOYMENT_FEATURES)
    if len(set(names)) != len(names):
        raise ValueError("the vocabulary repeats a package")
    return names


def package_id(purl: str) -> str | None:
    """"type/name" of a package, e.g. "pypi/requests" or "deb/libc6": no version, qualifiers or
    namespace, so the same package matches across versions and distributions."""
    p = purls.parse(purl)
    return None if p is None else f"{p.type}/{purls.name_of(p)}"


def package_ids(envelope: Mapping) -> set[str]:
    return {i for i in (package_id(p) for p in envelope.get("packages") or {}) if i is not None}


def build_vocabulary(envelopes: Iterable[Mapping], k: int = VOCABULARY_SIZE) -> list[str]:
    """The k package ids in the most envelopes (ties broken by name), from the training corpus.
    The vocabulary is stored with the model, so inference uses the same features."""
    df = Counter()
    for env in envelopes:
        df.update(package_ids(env))
    return [name for name, _ in sorted(df.items(), key=lambda kv: (-kv[1], kv[0]))[:k]]


def _config_fields(config) -> tuple[str, dict, list]:
    """(User, ExposedPorts, Env) from an oci.ImageConfig, an OCI config document, or its
    inner `config` object."""
    if hasattr(config, "exposed_ports"):
        return config.user or "", dict(config.exposed_ports or {}), list(config.env or ())
    c = config.get("config", config) if isinstance(config, Mapping) else {}
    return c.get("User") or "", dict(c.get("ExposedPorts") or {}), list(c.get("Env") or ())


def runs_as_root(user: str) -> bool:
    """An empty User runs as root, as do "root" and uid 0; a named user is assumed not root."""
    name = user.strip().split(":", 1)[0]
    return name in ("", "root", "0")


def _ports(exposed: Mapping) -> list[int]:
    ports = []
    for spec in exposed:
        try:
            ports.append(int(str(spec).split("/", 1)[0]))
        except ValueError:
            continue
    return ports


def extract(envelope: Mapping, config, *, imports: Mapping[str, Iterable[str]] | None = None,
            deployment: Mapping | None = None, vocabulary: Sequence[str] = ()) -> FeatureVector:
    """z_I for one image. `deployment` takes securityContext-style keys: privileged, add, drop."""
    v: dict[str, float] = {}

    user, exposed, env = _config_fields(config)                                   # 𝒞_cfg
    ports = _ports(exposed)
    v["cfg.runs_as_root"] = float(runs_as_root(user))
    v["cfg.user_set"] = float(bool(user.strip()))
    v["cfg.exposed_ports"] = float(len(exposed))
    v["cfg.port_below_1024"] = float(any(p < 1024 for p in ports))
    v["cfg.env_vars"] = float(len(env))

    counts = Counter()                                                            # 𝒫*_I
    for purl in envelope.get("packages") or {}:
        p = purls.parse(purl)
        counts[p.type if p is not None and p.type in ECOSYSTEMS else "other"] += 1
    for eco in ECOSYSTEMS + ("other",):
        v[f"pkg.count.{eco}"] = float(counts[eco])
    ids = package_ids(envelope)
    for name in vocabulary:
        v[f"pkg.has.{name}"] = float(name in ids)

    closure = set(envelope.get("closure") or ())                                  # 𝒬_I
    basenames = {posixpath.basename(p) for p in closure}
    v["clo.size"] = float(len(closure))
    for label, rx in _INTERPRETERS:
        v[f"clo.interp.{label}"] = float(any(rx.match(b) for b in basenames))
    v["clo.static"] = float(bool(closure) and not any(_LOADER.match(b) for b in basenames))

    if imports is None:
        for sym in WATCHED_SYMBOLS:
            v[f"imp.{sym}"] = math.nan
    else:
        imported = {s for path, syms in imports.items() if path in closure for s in syms}
        for sym in WATCHED_SYMBOLS:
            v[f"imp.{sym}"] = float(sym in imported)

    dep = deployment or {}                                                        # C_I
    privileged = bool(dep.get("privileged", False))
    effective = effective_set(dep.get("add", ()), dep.get("drop", ()), privileged)
    v["dep.privileged"] = float(privileged)
    v["dep.caps_added"] = float(len(effective - RUNTIME_DEFAULT_CAPS))
    v["dep.caps_dropped"] = float(len(RUNTIME_DEFAULT_CAPS - effective))

    names = feature_names(vocabulary)
    return FeatureVector(names, tuple(v[n] for n in names))


def _undefined_dynamic_symbols(f: BinaryIO) -> set[str]:
    elf = ELFFile(f)
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is not None:
        symbols = dynsym.iter_symbols()
    else:                                              # stripped: read DT_SYMTAB via the dynamic segment
        symbols = next((seg.iter_symbols() for seg in elf.iter_segments() if seg["p_type"] == "PT_DYNAMIC"), ())
    return {s.name for s in symbols if s.name and s["st_shndx"] == "SHN_UNDEF"}


def closure_imports(fs: ImageFS, closure: Iterable[str],
                    symbols: Sequence[str] = WATCHED_SYMBOLS) -> dict[str, tuple[str, ...]]:
    """For each ELF file in the closure, the watched symbols it imports: its undefined dynamic
    symbols. Read from the image during compilation; a file that cannot be parsed is logged and
    left out."""
    watched = set(symbols)
    out: dict[str, tuple[str, ...]] = {}
    for path in sorted(set(closure)):
        if (fs.read(path, 4) or b"") != b"\x7fELF":
            continue
        try:
            with fs.open(path) as f:
                out[path] = tuple(sorted(_undefined_dynamic_symbols(f) & watched))
        except Exception as e:                         # a broken ELF must not stop compilation
            log.warning("features: cannot read the dynamic symbols of %s (%s); left out", path, e)
    return out
