"""T6: symlink resolution (handoff Section 7.2) and canonical keys.

Every path in the envelope is a real path, because Role 3 compares them directly with
the kernel's paths as Tetragon reports them. realpath resolves symlinks at any position
in a path; canonicalise moves every union key under the real path of its parent, so
/bin/ls becomes /usr/bin/ls on a merged-/usr image.
"""
from __future__ import annotations

import logging
import posixpath
from collections import deque
from itertools import chain
from typing import Iterable, Mapping, NamedTuple

log = logging.getLogger("provbind.paths")

MAX_HOPS = 40


class SymlinkLoop(Exception):
    """More than MAX_HOPS symlinks while resolving one path (the kernel's ELOOP)."""


def realpath(path: str, links: Mapping[str, str], max_hops: int = MAX_HOPS) -> str:
    """Resolve every symlink in an absolute path against the union's links (Section 7.2).

    A relative target resolves against the directory holding the link, and ".." applies to
    the resolved path, as in the kernel.
    """
    parts, resolved, hops = deque(path.split("/")), "/", 0
    while parts:
        part = parts.popleft()
        if part in ("", "."):
            continue
        if part == "..":
            resolved = posixpath.dirname(resolved)
            continue
        candidate = posixpath.join(resolved, part)
        if candidate in links:
            hops += 1
            if hops > max_hops:
                raise SymlinkLoop(path)
            target = links[candidate]
            if target.startswith("/"):
                resolved = "/"
            parts.extendleft(reversed(target.split("/")))
        else:
            resolved = candidate
    return resolved


class Canonical(NamedTuple):
    files: dict
    links: dict[str, str]
    link_layers: dict[str, int]
    dirs: set[str]


def canonical_key(path: str, links: Mapping[str, str]) -> str | None:
    """`path` with its directory replaced by that directory's real path; None on a loop."""
    parent, base = posixpath.split(path)
    try:
        return posixpath.join(realpath(parent, links), base)
    except SymlinkLoop:
        log.warning("dropped %s: its directory is a symlink loop", path)
        return None


def canonicalise(files: Mapping, links: Mapping[str, str], dirs: Iterable[str],
                 link_layers: Mapping[str, int]) -> Canonical:
    """Canonical keys for the union's maps (T6).

    When two keys land on the same path, the entry from the higher layer wins, whether it
    is a file or a link; on a tie, the key that was already canonical wins. Link keys are
    resolved first, and files and dirs then resolve against the canonical links, which is
    the map realpath walks: its candidates are always real paths.
    """
    best: dict[str, tuple] = {}                  # path -> (rank, kind, value, layer)

    def offer(path, layer, already_canonical, kind, value):
        rank = (layer, already_canonical)
        if path not in best or rank > best[path][0]:
            best[path] = (rank, kind, value, layer)

    for p, target in links.items():
        q = canonical_key(p, links)
        if q is not None:
            offer(q, link_layers.get(p, 0), p == q, "link", target)
    canon_links = {q: v for q, (_, kind, v, _) in best.items() if kind == "link"}
    for p, entry in files.items():
        q = canonical_key(p, canon_links)
        if q is not None:
            offer(q, entry.layer, p == q, "file", entry)

    out_files = {q: v for q, (_, kind, v, _) in best.items() if kind == "file"}
    out_links = {q: v for q, (_, kind, v, _) in best.items() if kind == "link"}
    out_layers = {q: layer for q, (_, kind, _, layer) in best.items() if kind == "link"}
    out_dirs = set()
    for d in dirs:
        q = canonical_key(d, out_links)
        if q is not None and q not in out_files and q not in out_links:
            out_dirs.add(q)
    return Canonical(out_files, out_links, out_layers, out_dirs)


def all_dirs(files: Iterable[str], links: Iterable[str], dirs: Iterable[str]) -> set[str]:
    """Explicit directories plus every parent of a file, link or directory, since a layer
    need not list parent directories."""
    dirs = set(dirs)
    out = {"/"}
    for p in chain(dirs, files, links):
        parent = posixpath.dirname(p)
        while parent not in out:
            out.add(parent)
            parent = posixpath.dirname(parent)
    return out | dirs


def resolve_links(links: Mapping[str, str], files: Mapping, dirs: Iterable[str]) -> dict[str, str | None]:
    """The envelope's `symlinks`: each link's fully resolved real target, or None if the
    target is neither a file nor a directory, or the link loops."""
    known_dirs = all_dirs(files, links, dirs)
    out: dict[str, str | None] = {}
    for p in links:
        try:
            target = realpath(p, links)
        except SymlinkLoop:
            log.warning("symlink %s loops; recorded as dangling", p)
            out[p] = None
            continue
        out[p] = target if target in files or target in known_dirs else None
    return out
