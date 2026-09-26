"""T5: the two-pass layer union (handoff Section 7.1).

Layers apply in manifest order. Within a layer, whiteouts and opaque markers hide only
lower-layer entries (pass 1). Then the layer's own entries go in (pass 2): unless both
are directories, a new entry replaces the lower one at the same path, and a new
non-directory also removes the lower subtree under it (OCI "changeset over existing
files").

Each layer is decompressed once into a temporary directory outside the run folder, so
later steps (closure, owners) can read file bytes without decompressing again.
"""
from __future__ import annotations

import dataclasses
import gzip
import hashlib
import logging
import os
import posixpath
import shutil
import tarfile
import tempfile
from dataclasses import dataclass
from typing import BinaryIO, Iterable, NamedTuple

import zstandard

log = logging.getLogger("provbind.layers")

GZIP_TYPES = {
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
}
ZSTD_TYPES = {
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
}
TAR_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.nondistributable.v1.tar",
}
GZIP_MAGIC = b"\x1f\x8b"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

WHITEOUT = ".wh."
OPAQUE = ".wh..wh..opq"
CHUNK = 1 << 20


class LayerError(Exception):
    """A layer blob could not be decompressed or read as a tar."""


@dataclass(frozen=True)
class LayerBlob:
    """One layer as fetched by oci.py, in manifest order."""
    index: int
    digest: str
    media_type: str | None
    path: str


class FileEntry(NamedTuple):
    """A regular file. The first three fields are the handoff's (sha256, layer_index, mode);
    the rest locate its bytes, which for a hardlink are its target's."""
    sha256: str
    layer: int
    mode: str
    size: int
    src_layer: int
    offset: int


def mode_string(mode: int) -> str:
    """"0755", or "04755" for a setuid file: the schema's ^0[0-7]{3,4}$."""
    return "0%03o" % (mode & 0o7777)


def normalise(name: str) -> str | None:
    """A tar member name as an absolute path, or None for the root itself.

    Strips "./", adds a leading "/", collapses "//", drops a trailing "/" and resolves
    "." and ".." lexically.
    """
    path = posixpath.normpath("/" + name)
    if path.startswith("//"):          # normpath keeps exactly two leading slashes (POSIX)
        path = "/" + path.lstrip("/")
    return None if path == "/" else path


def compression(media_type: str | None, path: str) -> str:
    """"gzip", "zstd" or "tar": by media type, or by magic bytes if the type is unknown."""
    if media_type in GZIP_TYPES:
        return "gzip"
    if media_type in ZSTD_TYPES:
        return "zstd"
    if media_type in TAR_TYPES:
        return "tar"
    with open(path, "rb") as f:
        head = f.read(4)
    if head.startswith(GZIP_MAGIC):
        return "gzip"
    if head.startswith(ZSTD_MAGIC):
        return "zstd"
    return "tar"


class LayerStore:
    """Uncompressed copies of the layers, for reading file bytes after the union."""

    def __init__(self, workdir: str | None = None):
        self._owned = workdir is None
        self.dir = workdir or tempfile.mkdtemp(prefix="provbind-layers-")
        self._tars: dict[int, tarfile.TarFile] = {}
        self._members: dict[tuple[int, int], tarfile.TarInfo] = {}

    def open_layer(self, layer: LayerBlob) -> tarfile.TarFile | None:
        """Decompress one layer and open it; None for an empty blob."""
        path = os.path.join(self.dir, f"{layer.index}.tar")
        kind = compression(layer.media_type, layer.path)
        try:
            with open(layer.path, "rb") as src, open(path, "wb") as dst:
                if kind == "gzip":
                    with gzip.GzipFile(fileobj=src) as z:
                        shutil.copyfileobj(z, dst, CHUNK)
                elif kind == "zstd":
                    reader = zstandard.ZstdDecompressor().stream_reader(
                        src, read_across_frames=True, closefd=False)
                    with reader:
                        shutil.copyfileobj(reader, dst, CHUNK)
                else:
                    shutil.copyfileobj(src, dst, CHUNK)
            if os.path.getsize(path) == 0:
                return None
            tf = tarfile.open(path, mode="r:")
        except (OSError, EOFError, zstandard.ZstdError, tarfile.TarError) as e:
            raise LayerError(f"layer {layer.index} ({layer.digest}): not a {kind} tar: {e}") from e
        self._tars[layer.index] = tf
        return tf

    def add_file(self, layer_index: int, tf: tarfile.TarFile, member: tarfile.TarInfo) -> FileEntry:
        """Hash a regular file and remember where its bytes are."""
        h = hashlib.sha256()
        f = tf.extractfile(member)
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
        self._members[(layer_index, member.offset_data)] = member
        return FileEntry(h.hexdigest(), layer_index, mode_string(member.mode), member.size,
                         layer_index, member.offset_data)

    def open(self, entry: FileEntry) -> BinaryIO:
        """A seekable reader over the file's bytes."""
        member = self._members[(entry.src_layer, entry.offset)]
        return self._tars[entry.src_layer].extractfile(member)

    def read(self, entry: FileEntry, n: int | None = None) -> bytes:
        with self.open(entry) as f:
            return f.read() if n is None else f.read(n)

    def close(self) -> None:
        for tf in self._tars.values():
            tf.close()
        self._tars.clear()
        if self._owned:
            shutil.rmtree(self.dir, ignore_errors=True)


@dataclass
class Union:
    """The union of an image's layers: the handoff's files, links and dirs maps, plus the
    layer that provided each link and read access to file bytes."""
    files: dict[str, FileEntry]
    links: dict[str, str]
    dirs: set[str]
    link_layers: dict[str, int]
    store: LayerStore

    def replace(self, **changes) -> "Union":
        """The same union with some maps swapped (e.g. canonical keys); shares the store."""
        return dataclasses.replace(self, **changes)

    def open(self, path: str) -> BinaryIO | None:
        entry = self.files.get(path)
        return None if entry is None else self.store.open(entry)

    def read(self, path: str, n: int | None = None) -> bytes | None:
        entry = self.files.get(path)
        return None if entry is None else self.store.read(entry, n)

    def close(self) -> None:
        self.store.close()

    def __enter__(self) -> "Union":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _has_ancestor_in(path: str, paths: set[str]) -> bool:
    while path != "/":
        path = posixpath.dirname(path)
        if path in paths:
            return True
    return False


def union(layers: Iterable[LayerBlob], workdir: str | None = None) -> Union:
    """Apply the layers in order. The caller closes the result (it is a context manager)."""
    store = LayerStore(workdir)
    try:
        return _union(layers, store)
    except BaseException:
        store.close()
        raise


def _union(layers: Iterable[LayerBlob], store: LayerStore) -> Union:
    files: dict[str, FileEntry] = {}
    links: dict[str, str] = {}
    link_layers: dict[str, int] = {}
    dirs: set[str] = set()

    for layer in layers:
        i = layer.index
        # Later entries for the same path win, as they would when the tar is extracted.
        entries: dict[str, tuple[str, object]] = {}
        gone: set[str] = set()
        opaque: set[str] = set()
        tf = store.open_layer(layer)
        try:
            for m in tf or ():
                name = normalise(m.name)
                if name is None:
                    continue
                d, base = posixpath.split(name)
                if base == OPAQUE:
                    opaque.add(d)                        # hides lower-layer children of d
                elif base.startswith(WHITEOUT):
                    gone.add(posixpath.join(d, base[len(WHITEOUT):]))  # that path and its subtree
                elif m.isdir():
                    entries[name] = ("dir", None)
                elif m.issym():
                    entries[name] = ("sym", m.linkname)
                elif m.islnk():
                    entries[name] = ("hard", normalise(m.linkname))
                elif m.isreg():
                    entries[name] = ("reg", store.add_file(i, tf, m))
                else:
                    entries[name] = ("other", None)      # device or fifo: replaces, not listed
        except tarfile.TarError as e:
            raise LayerError(f"layer {i} ({layer.digest}): bad tar: {e}") from e

        # Pass 1: this layer's deletions apply to lower layers only.
        if gone or opaque:
            def hidden(p: str) -> bool:
                return p in gone or _has_ancestor_in(p, gone) or _has_ancestor_in(p, opaque)
            files = {p: v for p, v in files.items() if not hidden(p)}
            links = {p: v for p, v in links.items() if not hidden(p)}
            link_layers = {p: v for p, v in link_layers.items() if p in links}
            dirs = {p for p in dirs if not hidden(p)}

        # Pass 2: a new non-directory replaces the lower entry and its subtree; a new
        # directory replaces a lower file or link at the same path.
        nondirs = {p for p, (kind, _) in entries.items() if kind != "dir"}
        if nondirs:
            def cut(p: str) -> bool:
                return p in nondirs or _has_ancestor_in(p, nondirs)
            files = {p: v for p, v in files.items() if not cut(p)}
            links = {p: v for p, v in links.items() if not cut(p)}
            link_layers = {p: v for p, v in link_layers.items() if p in links}
            dirs = {p for p in dirs if not cut(p)}
        for p, (kind, value) in entries.items():
            if kind == "dir":
                files.pop(p, None)
                links.pop(p, None)
                link_layers.pop(p, None)
                dirs.add(p)
            elif kind == "reg":
                files[p] = value
            elif kind == "sym":
                links[p] = value
                link_layers[p] = i
        # Hardlinks last: the target may be in this layer or a lower one.
        for p, (kind, target) in entries.items():
            if kind != "hard":
                continue
            if target in files:
                files[p] = files[target]._replace(layer=i)
            elif target in links:
                links[p] = links[target]
                link_layers[p] = i
            else:
                log.warning("layer %d: hardlink %s -> %s: target not found; skipped", i, p, target)

    return Union(files, links, dirs, link_layers, store)
