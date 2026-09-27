"""Eq. (37): the runtime indices J_I = (J_path, J_hash, J_layer, J_pkg, J_depth) of one envelope.

    J_path:  path -> (sha256, layer index)    is this file declared, and is its content unchanged?
    J_hash:  sha256 -> frozenset of paths     relocated binary: declared content at another path
    J_layer: path -> layer digest             layer attribution without a graph query
    J_pkg:   path -> package purl, or None    the owning package, Φ (Eq. 30)
    J_depth: package purl -> δ, or None       dependency depth (Eq. 29); None is unresolved

Each is a plain dict with O(1) lookups, which is what the node reads per event. They are built
from the envelope alone, so a node can rebuild them from the envelope it reads; nothing new is
written to the run folder. PH3-09 checks that they agree with the envelope.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class Indices:
    path: dict[str, tuple[str, int]]
    hash: dict[str, frozenset[str]]
    layer: dict[str, str]
    pkg: dict[str, str | None]
    depth: dict[str, int | None]


def build(envelope: Mapping) -> Indices:
    """J_I for one envelope. Raises ValueError when a file names a layer the envelope lacks."""
    layer_digest = {entry["index"]: entry["digest"] for entry in envelope["layers"]}
    path: dict[str, tuple[str, int]] = {}
    by_hash: dict[str, set[str]] = {}
    layer: dict[str, str] = {}
    pkg: dict[str, str | None] = {}
    for p, f in envelope["files"].items():
        if f["layer"] not in layer_digest:
            raise ValueError(f"{p}: layer {f['layer']} is not in the envelope's layers")
        path[p] = (f["sha256"], f["layer"])
        by_hash.setdefault(f["sha256"], set()).add(p)
        layer[p] = layer_digest[f["layer"]]
        pkg[p] = f.get("package")
    depth = {purl: info.get("depth") for purl, info in envelope["packages"].items()}
    return Indices(path, {h: frozenset(ps) for h, ps in by_hash.items()}, layer, pkg, depth)
