"""Phase 4 Step 2 (Eq. 52): envelopes and bindings from the run folder, one cached envelope per digest.

bindings.json (Role 4, Sprint Handoff §4.2) maps a container ID to its image digest. It also
says whether the image's evidence verified, which paths are mounts, and whether the envelope is
ready. envelopes/<hex>.json (Role 2, §4.1) is the image's compiled envelope.

The store reads both and reloads them when they change. It keeps one prepared envelope per
digest in memory, counted by the verified containers bound to it: the envelope is loaded when
its first container appears and evicted when its last one goes (Explanation §7, Step 2). A
200-replica deployment therefore holds one envelope per node.

An envelope is ready when its file exists, parses, and names the digest it is filed under. The
compiler writes it atomically, so a file that exists is complete. `envelope_ready` in
bindings.json is informational here: the file is the evidence.
"""
from __future__ import annotations

import json
import logging
import os
import posixpath
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from compiler.indices import Indices, build as build_indices
from compiler.paths import SymlinkLoop, realpath

log = logging.getLogger("provbind.node.store")

ORIGINS = ("AUTHENTICATED", "INFERRED", "CONFIGURED")


def bare_id(container_id: str) -> str:
    """containerd://4b1c… -> 4b1c…; Tetragon and Kubernetes both prefix the runtime."""
    return container_id.split("://", 1)[-1]


def hex_of(digest: str) -> str:
    return digest.split(":", 1)[-1]


@dataclass
class Envelope:
    """One envelope, prepared for the per-event checks (Eq. 37): J_I, the closure as a set, the
    symlinks for canonical paths, and the capabilities with their origins."""
    digest: str
    doc: dict
    j: Indices
    closure: frozenset
    links: dict
    caps: dict                      # CAP_X -> origin
    cap_origin: str                 # the origin of "this capability is not needed" (D_cap)
    source: str = ""
    stamp: tuple = ()
    extra: dict = field(default_factory=dict)       # per-envelope state other stages attach

    @classmethod
    def prepare(cls, doc: Mapping, source: str = "", stamp: tuple = ()) -> Envelope:
        """Raises ValueError for an envelope the verifier cannot use."""
        for key in ("image", "files", "symlinks", "closure", "capabilities", "layers", "packages"):
            if key not in doc:
                raise ValueError(f"envelope has no {key!r}")
        digest = doc["image"].get("digest") if isinstance(doc["image"], dict) else None
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise ValueError("envelope has no image digest")
        caps = {}
        for c in doc["capabilities"]:
            if isinstance(c, dict) and isinstance(c.get("cap"), str):
                caps[c["cap"]] = c.get("origin") if c.get("origin") in ORIGINS else "INFERRED"
        origins = set(caps.values())
        if not caps or "INFERRED" in origins:
            cap_origin = "INFERRED"             # the set, or its absence, came from inference
        elif "CONFIGURED" in origins:
            cap_origin = "CONFIGURED"
        else:
            cap_origin = "AUTHENTICATED"
        return cls(digest=digest, doc=dict(doc), j=build_indices(doc), closure=frozenset(doc["closure"]),
                   links=dict(doc["symlinks"]), caps=caps, cap_origin=cap_origin, source=source, stamp=stamp)

    def canonical(self, path: str | None) -> str | None:
        """The path with the image's symlinks resolved, or None if they loop."""
        if not path or not path.startswith("/"):
            return path
        try:
            return realpath(path, self.links)
        except SymlinkLoop:
            return None

    def lookup(self, path: str | None) -> tuple[str | None, tuple | None]:
        """(the declared path, its J_path record) for a runtime path, or (None, None).

        Tetragon reports real paths, so the path is looked up as it is first. Only if that
        misses is it resolved through the image's symlinks, which covers a kernel or a
        Tetragon version that reports the name it was called by (/bin/sh for /usr/bin/dash).
        """
        if not path:
            return None, None
        rec = self.j.path.get(path)
        if rec is not None:
            return path, rec
        real = self.canonical(path)
        if real and real != path:
            rec = self.j.path.get(real)
            if rec is not None:
                return real, rec
        return None, None

    def context(self, key: str | None) -> dict:
        """§4.4 context for a declared path (from `lookup`), or for one in no layer."""
        if key is None:
            return {"declared": False, "package": None, "depth": None, "layer": None}
        pkg = self.j.pkg.get(key)
        return {"declared": True, "package": pkg, "depth": self.j.depth.get(pkg) if pkg else None,
                "layer": self.j.path[key][1]}


@dataclass
class Binding:
    """One container's entry in bindings.json (§4.2)."""
    container_id: str
    image_digest: str | None
    verified: bool
    mounts: tuple
    envelope_ready: bool
    namespace: str = ""
    pod: str = ""
    container: str = ""
    run_as_root: bool | None = None
    privileged: bool | None = None

    @classmethod
    def parse(cls, container_id: str, entry: Mapping) -> Binding:
        mounts = entry.get("mounts") if isinstance(entry.get("mounts"), list) else []
        return cls(container_id=container_id,
                   image_digest=entry.get("image_digest") if isinstance(entry.get("image_digest"), str) else None,
                   verified=entry.get("verified") is True,
                   mounts=tuple(m for m in mounts if isinstance(m, str) and m.startswith("/")),
                   envelope_ready=entry.get("envelope_ready") is True,
                   namespace=str(entry.get("namespace") or ""), pod=str(entry.get("pod") or ""),
                   container=str(entry.get("container") or ""),
                   run_as_root=entry.get("run_as_root") if isinstance(entry.get("run_as_root"), bool) else None,
                   privileged=entry.get("privileged") if isinstance(entry.get("privileged"), bool) else None)


def under(path: str, mounts) -> bool:
    """Is `path` a mount point or inside one? A mount at / covers everything."""
    for m in mounts:
        m = m.rstrip("/") or "/"
        if m == "/" or path == m or path.startswith(m + "/"):
            return True
    return False


class Store:
    """Bindings and envelopes, reloaded on change; one envelope per digest, counted by the
    verified containers bound to it (Eq. 52).

    `run_dir` reads `bindings.json` and `envelopes/` from a run folder. `Store.static(...)` takes
    them as objects, for replay and tests; it behaves the same but never reloads.
    """

    def __init__(self, run_dir: str | os.PathLike | None):
        self.run_dir = Path(run_dir) if run_dir is not None else None
        self.bindings: dict[str, Binding] = {}
        self._bare: dict[str, str] = {}              # bare container ID -> bindings key
        self.cache: dict[str, Envelope] = {}          # digest -> prepared envelope
        self.refs: Counter = Counter()                # digest -> verified containers bound to it
        self.ever_bound: set[str] = set()             # bare IDs of every container ever bound
        self.stats: Counter = Counter()
        self._bindings_stamp: tuple | None = None
        self._failed: dict[str, tuple] = {}            # digest -> stamp of the file that failed
        self._mounts: dict[tuple, tuple] = {}          # (container, digest) -> canonical mounts
        self._static_envelopes: dict[str, Mapping] | None = None

    @classmethod
    def static(cls, envelopes, bindings: Mapping) -> Store:
        """A store over given envelope documents and a bindings.json object."""
        s = cls(None)
        s._static_envelopes = {e["image"]["digest"]: e for e in envelopes}
        s.set_bindings(bindings)
        return s

    def provide(self, doc: Mapping) -> None:
        """A static store's equivalent of the compiler writing envelopes/<hex>.json."""
        if self._static_envelopes is None:
            raise TypeError("provide() is for static stores; write the file instead")
        self._static_envelopes[doc["image"]["digest"]] = doc

    # bindings -----------------------------------------------------------------------------------
    def set_bindings(self, doc: Mapping) -> None:
        """Take a bindings.json object: count references per digest, evict what lost its last
        container, and load what gained its first."""
        bindings = {cid: Binding.parse(cid, entry) for cid, entry in doc.items()
                    if isinstance(cid, str) and isinstance(entry, Mapping)}
        self.bindings = bindings
        self._bare = {bare_id(cid): cid for cid in bindings}
        self.ever_bound.update(self._bare)
        refs = Counter(b.image_digest for b in bindings.values() if b.verified and b.image_digest)
        for digest in list(self.cache):
            if not refs[digest]:
                del self.cache[digest]
                self.stats["evictions"] += 1
                log.info("evicted envelope %s: no container is bound to it", digest)
        self.refs = refs
        self._mounts = {k: v for k, v in self._mounts.items() if k[0] in bindings}
        for digest in refs:
            self._ensure(digest)

    def _read_bindings(self) -> bool:
        """Reload bindings.json if it changed. True if it did."""
        path = self.run_dir / "bindings.json"
        try:
            st = path.stat()
        except FileNotFoundError:
            if self._bindings_stamp != ():
                self._bindings_stamp = ()
                self.set_bindings({})
                return True
            return False
        stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
        if stamp == self._bindings_stamp:
            return False
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                raise ValueError("not a JSON object")
        except (OSError, ValueError) as e:
            self.stats["bad_bindings"] += 1
            log.error("bindings.json unreadable, keeping the previous bindings: %s", e)
            return False
        self._bindings_stamp = stamp
        self.stats["bindings_loads"] += 1
        self.set_bindings(doc)
        return True

    def refresh(self) -> bool:
        """Reload what changed and retry envelopes that were not ready. True if anything changed."""
        if self._static_envelopes is not None:
            return False
        changed = self._read_bindings()
        for digest in list(self.refs):
            before = self.cache.get(digest)
            self._ensure(digest)
            changed |= self.cache.get(digest) is not before
        return changed

    def binding(self, container_id: str) -> Binding | None:
        """The container's binding: by its full ID, by the ID without the runtime prefix, or by
        a unique prefix of 12 or more characters (Tetragon's short `docker` field)."""
        b = self.bindings.get(container_id)
        if b is not None:
            return b
        bare = bare_id(container_id)
        key = self._bare.get(bare)
        if key is None and len(bare) >= 12:
            keys = [k for b2, k in self._bare.items() if b2.startswith(bare)]
            key = keys[0] if len(keys) == 1 else None
        return self.bindings.get(key) if key else None

    def was_bound(self, container_id: str) -> bool:
        """Was this container ever in bindings.json? Its events after unbinding are not failures."""
        bare = bare_id(container_id)
        return bare in self.ever_bound or (len(bare) >= 12 and any(b.startswith(bare) for b in self.ever_bound))

    # envelopes ----------------------------------------------------------------------------------
    def envelope(self, digest: str | None) -> Envelope | None:
        """The prepared envelope for a digest bound to a verified container, or None if not ready."""
        if not digest:
            return None
        env = self.cache.get(digest)
        if env is not None:
            self.stats["hits"] += 1
            return env
        self.stats["misses"] += 1
        return self._ensure(digest) if self.refs[digest] else None

    def _ensure(self, digest: str) -> Envelope | None:
        """Load the digest's envelope if its file is new or changed."""
        if self._static_envelopes is not None:
            if digest not in self.cache and digest in self._static_envelopes:
                self._install(digest, self._static_envelopes[digest], "static", ())
            return self.cache.get(digest)
        path = self._path(digest)
        try:
            st = path.stat() if path is not None else None
        except FileNotFoundError:                        # replaced between the two calls
            st = None
        if st is None:
            return self.cache.get(digest)
        stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
        cached = self.cache.get(digest)
        if (cached is not None and cached.stamp == stamp) or self._failed.get(digest) == stamp:
            return cached
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            self._install(digest, doc, str(path), stamp)
        except (OSError, ValueError, KeyError, TypeError) as e:
            self._failed[digest] = stamp
            self.stats["bad_envelopes"] += 1
            log.error("envelope %s unusable, events stay buffered: %s", path, e)
        return self.cache.get(digest)

    def _path(self, digest: str) -> Path | None:
        """envelopes/<hex>.json as the compiler writes it; envelopes/<digest>.json as §3.2 names it."""
        for name in (f"{hex_of(digest)}.json", f"{digest}.json"):
            p = self.run_dir / "envelopes" / name
            if p.is_file():
                return p
        return None

    def _install(self, digest: str, doc: Mapping, source: str, stamp: tuple) -> None:
        env = Envelope.prepare(doc, source, stamp)
        if env.digest != digest:
            raise ValueError(f"filed under {digest} but names {env.digest}")
        replaced = digest in self.cache
        self.cache[digest] = env
        self._failed.pop(digest, None)
        self._mounts = {k: v for k, v in self._mounts.items() if k[1] != digest}
        self.stats["reloads" if replaced else "loads"] += 1
        log.info("%s envelope %s (%d files, closure %d)", "reloaded" if replaced else "loaded", digest,
                 len(env.j.path), len(env.closure))

    # mounts -------------------------------------------------------------------------------------
    def mounts(self, binding: Binding, env: Envelope) -> tuple:
        """The binding's mounts as given and as real paths in the image. A pod spec names
        /var/run/secrets/…, which on Debian is /run/secrets/… once /var/run -> /run resolves."""
        key = (binding.container_id, env.digest)
        cached = self._mounts.get(key)
        if cached is None:
            out = []
            for m in binding.mounts:
                for p in (posixpath.normpath(m), env.canonical(posixpath.normpath(m))):
                    if p and p not in out:
                        out.append(p)
            cached = self._mounts[key] = tuple(out)
        return cached
