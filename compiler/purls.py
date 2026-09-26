"""Package URL helpers shared by ownership (T9) and capabilities (T10).

Envelope keys keep the SBOM's purl strings verbatim; these helpers are only for matching,
which ignores version qualifiers such as ?arch=amd64&distro=debian-12.
"""
from __future__ import annotations

import re

from packageurl import PackageURL


def pep503(name: str) -> str:
    """PEP 503 normalised project name: Foo_Bar.baz -> foo-bar-baz."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse(purl: str) -> PackageURL | None:
    try:
        return PackageURL.from_string(purl)
    except ValueError:
        return None


def name_of(p: PackageURL) -> str:
    """The package name as matching compares it: PEP 503 for pypi, verbatim otherwise."""
    return pep503(p.name) if p.type == "pypi" else p.name


def identity(purl: str) -> tuple[str, str | None, str] | None:
    """(type, namespace, name) without version, qualifiers or subpath; None if unparsable."""
    p = parse(purl)
    return None if p is None else (p.type, p.namespace, name_of(p))
