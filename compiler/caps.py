"""T10: capabilities, kept simple on purpose: the demo never checks them, but the
contract requires the field. Every entry is INFERRED."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterable, Mapping

from . import purls

log = logging.getLogger("provbind.caps")

ALLOWLIST = Path(__file__).with_name("caps_allowlist.json")
NET_BIND_SERVICE = "CAP_NET_BIND_SERVICE"


def load_allowlist(path: str | Path = ALLOWLIST) -> dict[tuple, list[str]]:
    """Package identity -> capabilities, from caps_allowlist.json ("_" keys are comments)."""
    out: dict[tuple, list[str]] = {}
    for key, caps in json.loads(Path(path).read_text(encoding="utf-8")).items():
        if key.startswith("_"):
            continue
        ident = purls.identity(key)
        if ident is None:
            log.warning("caps allowlist: %r is not a purl; ignored", key)
            continue
        out[ident] = list(caps)
    return out


def privileged_ports(exposed_ports: Iterable[str] | None) -> list[int]:
    """Ports below 1024 among the config's ExposedPorts keys, such as "80/tcp"."""
    ports = []
    for spec in exposed_ports or ():
        try:
            port = int(str(spec).split("/", 1)[0])
        except ValueError:
            log.warning("ExposedPorts entry %r is not a port; ignored", spec)
            continue
        if port < 1024:
            ports.append(port)
    return ports


def capabilities(package_purls: Iterable[str], exposed_ports: Iterable[str] | None,
                 allowlist: Mapping[tuple, list[str]] | None = None) -> list[dict]:
    """The envelope's `capabilities`, sorted by name, one entry per capability."""
    allow = load_allowlist() if allowlist is None else allowlist
    caps: set[str] = set()
    for purl in package_purls:
        caps.update(allow.get(purls.identity(purl), ()))
    if privileged_ports(exposed_ports):
        caps.add(NET_BIND_SERVICE)
    return [{"cap": c, "origin": "INFERRED"} for c in sorted(caps)]
