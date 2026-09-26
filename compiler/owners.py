"""T9: file ownership (handoff Section 7.5): which package's record claims each file.

dpkg: /var/lib/dpkg/status names the installed packages, and /var/lib/dpkg/info/<name>.list
or <name>:<arch>.list lists their paths, directories included. pip: every *.dist-info
directory has METADATA (Name, Version) and RECORD (path,hash,size, relative to the
directory that holds the dist-info). Every listed path goes through realpath, because
merged-/usr images list /bin/ls while the file lives at /usr/bin/ls.

Records are then matched to SBOM purls, ignoring qualifiers. A file whose record matches
no SBOM component gets package None and is logged (decision D5), so every non-null
package in the envelope is a key of `packages`.
"""
from __future__ import annotations

import csv
import io
import logging
import posixpath
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Mapping

from . import purls
from .paths import SymlinkLoop, realpath

log = logging.getLogger("provbind.owners")

DPKG_STATUS = "/var/lib/dpkg/status"
DPKG_INFO = "/var/lib/dpkg/info"

Reader = Callable[[str], "bytes | None"]      # real path -> bytes, or None if no such file


@dataclass(frozen=True)
class Record:
    kind: str                 # "deb" or "pypi"
    name: str                 # dpkg Package, or the PEP 503-normalised project name
    version: str
    arch: str = ""            # dpkg Architecture; only breaks ties between purls


def _text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _stanzas(text: str) -> Iterator[dict[str, str]]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if fields:
                yield fields
                fields = {}
        elif line[0] not in " \t":            # skip continuation lines of multi-line fields
            key, sep, value = line.partition(":")
            if sep:
                fields[key.strip().lower()] = value.strip()
    if fields:
        yield fields


def dpkg_installed(status: str) -> list[tuple[str, str, str]]:
    """(name, version, architecture) of each package whose Status ends in "installed"."""
    out = []
    for s in _stanzas(status):
        state = s.get("status", "").split()
        if len(state) == 3 and state[2] == "installed" and s.get("package") and s.get("version"):
            out.append((s["package"], s["version"], s.get("architecture", "")))
    return out


def read_metadata(text: str) -> tuple[str, str] | None:
    """(Name, Version) from a METADATA file's headers, which end at the first blank line."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            break
        key, sep, value = line.partition(":")
        if sep and line[0] not in " \t":
            fields.setdefault(key.strip().lower(), value.strip())
    name, version = fields.get("name"), fields.get("version")
    return (name, version) if name and version else None


def read_record(text: str) -> list[str]:
    """The path column of a RECORD file (CSV, so quoted paths with commas work)."""
    return [row[0] for row in csv.reader(io.StringIO(text)) if row and row[0]]


def dist_info_dirs(paths: Iterable[str]) -> list[str]:
    """Every *.dist-info directory that holds a METADATA or RECORD file."""
    out = set()
    for p in paths:
        d, base = posixpath.split(p)
        if base in ("METADATA", "RECORD") and d.endswith(".dist-info"):
            out.add(d)
    return sorted(out)


def owners(files: Mapping[str, object], links: Mapping[str, str], read: Reader) -> dict[str, Record]:
    """path -> the record that claims it, for paths present in `files`. pip records are
    applied after dpkg, so pip wins when both claim a file."""
    owner: dict[str, Record] = {}

    def real(path: str) -> str | None:
        try:
            return realpath(path, links)
        except SymlinkLoop:
            log.warning("listed path %s is a symlink loop; ignored", path)
            return None

    def read_path(path: str) -> bytes | None:
        r = real(path)
        return None if r is None else read(r)

    def claim(path: str, record: Record) -> None:
        r = real(path)
        if r is not None and r in files:
            owner[r] = record

    status = read_path(DPKG_STATUS)
    for name, version, arch in dpkg_installed(_text(status)) if status is not None else ():
        record = Record("deb", name, version, arch)
        for list_file in (f"{DPKG_INFO}/{name}.list", f"{DPKG_INFO}/{name}:{arch}.list"):
            data = read_path(list_file)
            for line in _text(data).splitlines() if data is not None else ():
                if line.strip():
                    claim(line.strip(), record)

    for dist in dist_info_dirs(files):
        meta = read(posixpath.join(dist, "METADATA"))
        parsed = read_metadata(_text(meta)) if meta is not None else None
        rows = read(posixpath.join(dist, "RECORD"))
        if parsed is None or rows is None:
            log.warning("%s has no readable METADATA Name/Version or RECORD; ignored", dist)
            continue
        record = Record("pypi", purls.pep503(parsed[0]), parsed[1])
        site = posixpath.dirname(dist)
        for rel in read_record(_text(rows)):
            claim(posixpath.normpath(posixpath.join(site, rel)), record)
    return owner


def _index(package_purls: Iterable[str]) -> dict[tuple[str, str, str], list]:
    index: dict[tuple[str, str, str], list] = {}
    for purl in sorted(package_purls):
        p = purls.parse(purl)
        if p is not None and p.type in ("deb", "pypi") and p.version:
            index.setdefault((p.type, purls.name_of(p), p.version), []).append((purl, p))
    return index


def _lookup(index: Mapping, record: Record) -> str | None:
    candidates = index.get((record.kind, record.name, record.version))
    if not candidates and record.kind == "deb" and ":" in record.version:
        # dpkg always writes a non-zero epoch; accept an SBOM version written without it.
        candidates = index.get(("deb", record.name, record.version.split(":", 1)[1]))
    if not candidates:
        return None
    for purl, p in candidates:                       # ties: prefer the matching arch
        if record.arch and (p.qualifiers or {}).get("arch") == record.arch:
            return purl
    return candidates[0][0]


def match(owner: Mapping[str, Record], package_purls: Iterable[str]) -> dict[str, str | None]:
    """path -> the SBOM purl of the package that claims it, or None when no component
    matches (decision D5). deb matches on (name, version), pypi on (PEP 503 name,
    version); purl qualifiers are ignored."""
    index = _index(package_purls)
    out: dict[str, str | None] = {}
    unmatched: dict[Record, int] = {}
    for path, record in owner.items():
        out[path] = _lookup(index, record)
        if out[path] is None:
            unmatched[record] = unmatched.get(record, 0) + 1
    for record, n in sorted(unmatched.items(), key=lambda kv: (kv[0].kind, kv[0].name)):
        log.warning("no SBOM component for %s %s %s; its %d file(s) get package null",
                    record.kind, record.name, record.version, n)
    return out
