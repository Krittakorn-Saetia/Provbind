"""Phase 4 Step 3 (Eqs. 53-56): the deterministic verifier and its decision order (M12).

Every event gets exactly one outcome: conforming, or one detection in the shape of Sprint
Handoff §4.4. The rules below are tried in order, and the first match wins.

    exec, load  declared path?
                  yes  runtime hash known and different        D_hash / modified           strong
                       not reachable from the entrypoint       D_exec|D_load / outside_closure  weak (C2)
                       otherwise                               conforming
                  no   runtime hash known, declared elsewhere  D_hash / relocated          strong
                       otherwise                               D_exec|D_load / undeclared  strong
    write       under one of the container's mounts            conforming (M10)
                declared path                                  D_write / declared_file
                otherwise: a new file                          conforming
    cap         denied: nothing was used                       conforming
                in the envelope's capabilities                 conforming
                otherwise                                      D_cap / not_in_envelope
    connect     no egress allow list given (M8)                conforming
                allowed                                        conforming
                otherwise                                      D_net / not_allowed
    exit                                                       conforming

The hash tests run only when a runtime hash is known; that guard is the fix for C3. Without a
hash (path-only mode, the default), a file in no layer is D_exec / undeclared, and its detail
says the relocation check could not run (PH4-09).

Two rules keep D_load from drowning the node (PH4-11):
- A mapping of the process's own executable is skipped: its exec was judged already.
- A declared library outside the closure is reported only when the process that maps it is in
  the closure, and only once per container and library. A process outside the closure (sh, ls)
  was reported when it started, and the libraries it needs add nothing.
  Such a mapping is SUPPRESSED, not conforming: it is not written again, and it never enters
  an ML-B window.

A library in no layer is always reported.
"""
from __future__ import annotations

import ipaddress
import json
from collections import Counter
from pathlib import Path

from .normalize import Event
from .store import Binding, Envelope, under

WEAK = {("D_exec", "outside_closure"), ("D_load", "outside_closure")}
PATH_ONLY = "; path-only: no runtime hash, so relocation was not checked"


class _Suppressed:
    """A repeat of a weak detection already reported: not written again, but not conforming
    either, so ML-B's gate keeps it out of the windows (Algorithm 2, lines 2-4)."""

    def __repr__(self):
        return "SUPPRESSED"


SUPPRESSED = _Suppressed()

# §4.4 detection fields, in the contract's order
FIELDS = ("id", "time", "container_id", "namespace", "pod", "container", "image_digest", "pid", "ppid",
          "exe", "parent_exe", "class", "subclass", "clause", "origin", "context")


def detection(ev: Event, binding: Binding | None, klass: str, subclass: str, clause: tuple, origin: str,
              context: dict) -> dict:
    """A §4.4 record; `id` is set when it is written."""
    kind, path, detail = clause
    return {"id": None, "time": ev.time, "container_id": ev.container_id, "namespace": ev.namespace,
            "pod": ev.pod, "container": ev.container,
            "image_digest": binding.image_digest if binding is not None else None,
            "pid": ev.pid, "ppid": ev.ppid, "exe": ev.exe, "parent_exe": ev.parent_exe,
            "class": klass, "subclass": subclass, "clause": {"kind": kind, "path": path, "detail": detail},
            "origin": origin, "context": context}


UNKNOWN_CONTEXT = {"declared": None, "package": None, "depth": None, "layer": None}


def binding_failure(ev: Event, binding: Binding | None, subclass: str, detail: str) -> dict:
    """Eq. 51: an event that cannot be bound to an admitted, verified image. Nothing is known about
    its file, so `declared` is null rather than false."""
    return detection(ev, binding, "binding", subclass, ("binding", ev.exe, detail), "AUTHENTICATED",
                     dict(UNKNOWN_CONTEXT))


def is_weak(det: dict) -> bool:
    """Weak classes are observations, capped at Low by the scorer (Sprint Handoff §8, C2)."""
    return (det["class"], det["subclass"]) in WEAK


class Egress:
    """An operator's egress allow list for D_net. The envelope has no egress set yet (M8), so
    D_net checks this list, and its detections carry origin CONFIGURED.

    Entries: "10.96.0.0/12" (any port), "10.96.0.10/32:53", "127.0.0.1:8080", "*:443" (any
    address), "[::1]:8080".
    """

    def __init__(self, entries):
        self.rules = [self._parse(e) for e in entries]

    @classmethod
    def load(cls, path) -> Egress:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = doc.get("allow") if isinstance(doc, dict) else doc
        if not isinstance(entries, list):
            raise ValueError(f"{path}: expected {{\"allow\": [...]}}")
        return cls(entries)

    @staticmethod
    def _parse(entry: str):
        if not isinstance(entry, str) or not entry.strip():
            raise ValueError(f"bad egress entry: {entry!r}")
        entry = entry.strip()
        port = None
        if entry.startswith("["):                                   # [v6]:port
            addr, _, rest = entry[1:].partition("]")
            if rest:
                port = int(rest.lstrip(":"))
        elif entry.count(":") == 1:                                 # v4:port or *:port
            addr, p = entry.split(":")
            port = int(p)
        else:
            addr = entry
        net = None if addr in ("*", "") else ipaddress.ip_network(addr, strict=False)
        return net, port

    def allows(self, daddr: str | None, dport: int | None) -> bool:
        try:
            ip = ipaddress.ip_address(daddr) if daddr else None
        except ValueError:
            ip = None
        for net, port in self.rules:
            if port is not None and port != dport:
                continue
            if net is None or (ip is not None and ip.version == net.version and ip in net):
                return True
        return False


class Verifier:
    """The decision order above. `stats` counts outcomes by class and subclass."""

    def __init__(self, egress: Egress | None = None):
        self.egress = egress
        self.stats: Counter = Counter()
        self._weak_loads: set[tuple] = set()

    def verify(self, ev: Event, env: Envelope, binding: Binding, mounts=()):
        """A detection, None (conforming), or SUPPRESSED (a weak repeat, neither)."""
        det = self._decide(ev, env, binding, mounts)
        if det is None:
            self.stats["conforming"] += 1
        elif det is SUPPRESSED:
            self.stats["suppressed"] += 1
        else:
            self.stats[f"{det['class']}/{det['subclass']}"] += 1
        return det

    def _decide(self, ev: Event, env: Envelope, binding: Binding, mounts) -> dict | None:
        kind = ev.kind
        if kind in ("exec", "load"):
            return self._exec_or_load(ev, env, binding)
        if kind == "write":
            if ev.path is None or under(ev.path, mounts):
                return None
            key, rec = env.lookup(ev.path)
            if rec is None:
                return None                                        # a new file conforms
            return detection(ev, binding, "D_write", "declared_file",
                             ("file_set", key, f"write to a file declared in layer {rec[1]}; not under a mount"),
                             "AUTHENTICATED", env.context(key))
        if kind == "cap":
            if ev.granted is False or ev.cap is None or ev.cap in env.caps:
                return None
            key, _ = env.lookup(ev.exe)
            known = ", ".join(sorted(env.caps)) or "none"
            unknown = "" if ev.granted else " (return value unknown, treated as used)"
            return detection(ev, binding, "D_cap", "not_in_envelope",
                             ("capabilities", ev.exe, f"{ev.cap} used{unknown}; the envelope's capabilities: {known}"),
                             env.cap_origin, env.context(key))
        if kind == "connect":
            if self.egress is None or self.egress.allows(ev.daddr, ev.dport):
                return None
            key, _ = env.lookup(ev.exe)
            return detection(ev, binding, "D_net", "not_allowed",
                             ("egress", ev.exe, f"{ev.daddr}:{ev.dport}/{ev.protocol or 'tcp'} is not in the egress allow list"),
                             "CONFIGURED", env.context(key))
        return None                                                # exit, and anything newer

    def _exec_or_load(self, ev: Event, env: Envelope, binding: Binding) -> dict | None:
        is_exec = ev.kind == "exec"
        path = ev.exe if is_exec else ev.path
        if not is_exec and path == ev.exe:
            return None                                            # the executable's own mapping
        klass = "D_exec" if is_exec else "D_load"
        key, rec = env.lookup(path)
        if rec is not None:                                        # declared
            if ev.hash is not None and ev.hash != rec[0]:
                return detection(ev, binding, "D_hash", "modified",
                                 ("file_hash", key, f"runtime sha256 {ev.hash[:12]}… differs from the declared "
                                                    f"{rec[0][:12]}… (layer {rec[1]})"),
                                 "AUTHENTICATED", env.context(key))
            if key in env.closure:
                return None
            if not is_exec:
                loader, _ = env.lookup(ev.exe)
                if loader not in env.closure or (ev.container_id, key) in self._weak_loads:
                    return SUPPRESSED                              # judged at its exec, or reported already
                self._weak_loads.add((ev.container_id, key))
            return detection(ev, binding, klass, "outside_closure",
                             ("closure", key, f"declared in layer {rec[1]}, but not reachable from the entrypoint"),
                             "AUTHENTICATED", env.context(key))
        if ev.hash is not None and ev.hash in env.j.hash:
            origin = sorted(env.j.hash[ev.hash])
            more = f" and {len(origin) - 1} more" if len(origin) > 1 else ""
            return detection(ev, binding, "D_hash", "relocated",
                             ("file_hash", path, f"in no layer, but its content is the declared {origin[0]}{more}"),
                             "AUTHENTICATED", env.context(None))
        detail = "path is in no layer of the attested image" + ("" if ev.hash is not None else PATH_ONLY)
        return detection(ev, binding, klass, "undeclared", ("file_set", path, detail), "AUTHENTICATED",
                         env.context(None))
