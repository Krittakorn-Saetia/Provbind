"""T8: package depth from the CycloneDX SBOM (handoff Section 7.4).

A synthetic application root sits at depth 0 with an edge to every component that has
outgoing edges but no incoming ones; a multi-source BFS then gives each component its
shortest distance. A component in no edge gets depth None (unresolved), never 1: syft's
edges are incomplete (handoff Section 5, fact 6), so a missing edge says nothing about
where a package sits. Edges use bom-refs; packages are keyed by the component's purl.

A component without a purl is not a package here. On the stand-in these are syft's Windows
PE launchers inside pip and setuptools (cli-64.exe, gui-32.exe, ...; syft:package:type
"binary", no purl, in no edge): no file can be matched to them, no reader can name them,
and keyed by their bom-refs they only made unresolved_fraction and ML-A's pkg.count.other
look worse (19.7% unresolved on the stand-in instead of 9.7%).
"""
from __future__ import annotations

import logging
from collections import deque
from typing import Iterable, Iterator

log = logging.getLogger("provbind.sbom")

# CycloneDX types that are packages. The others (operating-system, file, container, ...)
# are not, and counting them would only inflate unresolved_fraction.
PACKAGE_TYPES = {"library", "application", "framework"}


def _walk(components: Iterable[dict] | None) -> Iterator[dict]:
    for c in components or ():
        yield c
        yield from _walk(c.get("components"))


def package_components(bom: dict) -> list[dict]:
    """The package components, nested ones included, in document order: a package type and
    a purl. Components of a package type without a purl are logged and left out."""
    typed = [c for c in _walk(bom.get("components")) if c.get("type", "library") in PACKAGE_TYPES]
    packages = [c for c in typed if c.get("purl")]
    if len(packages) < len(typed):
        names = sorted({str(c.get("name")) for c in typed if not c.get("purl")})
        log.info("%d SBOM components have no purl and are left out of packages: %s",
                 len(typed) - len(packages), ", ".join(names[:10]) + (", ..." if len(names) > 10 else ""))
    return packages


def depths(bom: dict) -> tuple[dict[str, dict], float]:
    """(packages, unresolved_fraction) for the envelope.

    packages maps each package's purl to {"depth": ...}; components without a purl are left
    out (package_components). Components that share a purl keep the smallest non-null depth.
    unresolved_fraction is the share of packages entries with a null depth, or 0 when there
    are none.
    """
    edges: dict[str, list[str]] = {}
    for d in bom.get("dependencies") or ():
        if d.get("ref"):
            edges.setdefault(d["ref"], []).extend(d.get("dependsOn") or ())
    has_in = {t for targets in edges.values() for t in targets}
    roots = [r for r in edges if edges[r] and r not in has_in]

    depth: dict[str, int] = {}
    queue = deque()
    for r in roots:
        depth[r] = 1                     # the synthetic application root is depth 0
        queue.append(r)
    while queue:
        u = queue.popleft()
        for v in edges.get(u, ()):
            if v not in depth:
                depth[v] = depth[u] + 1
                queue.append(v)

    # A component in no edge, or in a cycle that no root reaches, stays None: nothing
    # signed says how it is reached.
    packages: dict[str, dict] = {}
    for c in package_components(bom):
        ref, key = c.get("bom-ref"), c["purl"]
        d = depth.get(ref) if ref else None
        prev = packages.get(key)
        if prev is None or (d is not None and (prev["depth"] is None or d < prev["depth"])):
            packages[key] = {"depth": d}

    unresolved = sum(1 for v in packages.values() if v["depth"] is None)
    return packages, (unresolved / len(packages) if packages else 0.0)
