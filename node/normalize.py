"""Phase 4 Step 1 (Eq. 50): Tetragon's JSON export -> PROVBIND events (Sprint Handoff §4.3).

Each Tetragon line holds one event: process_exec, process_exit or process_kprobe. It carries the
process, its parent and the pod they run in. `Normalizer` turns it into an `Event` with an
absolute path and integer pids. It drops everything outside the monitored namespaces as early as
it can, and counts every drop by reason.

Kinds, and the hook each comes from (the policies are in node/tetragon/):

  exec     built-in process_exec                                        D_exec, D_hash
  exit     built-in process_exit                                        ML-B: a process ends
  write    security_file_permission with MAY_WRITE; security_path_truncate  D_write
           and security_file_truncate (a truncation changes a file too)
  load     security_mmap_file with PROT_EXEC                            D_load, D_hash
  cap      cap_capable; granted when it returned 0                      D_cap, ML-B
  connect  tcp_connect                                                  D_net, ML-B

events.jsonl carries only the field names of §4.3. The cap and connect kinds need fields the
contract does not have (the capability, the destination), so they are verified in memory and
not written there until the team agrees on those fields (node/ROLE3_STATUS.md, question Q1).

Paths are kept exactly as Tetragon reports them, which is the kernel's real path. A path that
cannot be verified is never tidied up: " (deleted)" is not stripped, because a file can be
named that way on purpose, and a relative exec path is joined to the process's cwd only.
"""
from __future__ import annotations

import calendar
import datetime as dt
import json
import posixpath
import re
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Iterator

MAY_WRITE = 0x02          # security_file_permission's mask argument
PROT_EXEC = 0x04          # security_mmap_file's prot argument

# linux/capability.h; Tetragon sends the name too, this covers events that carry only the number
CAPABILITIES = (
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
    "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK",
    "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG",
    "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
)

# The kernel functions the policies hook, and the kind each becomes. test_policies.py checks
# that every `call` in node/tetragon/*.yaml is listed here.
# The container runtime's own setup step. runc (1.2+) and crun re-execute themselves from a sealed
# memfd, so `kubectl exec` shows up in the pod as an exec of /proc/self/fd/N with the argument
# "init", started by the host's runc. Seen on the demo VM (containerd, kind): it scored as a
# CRITICAL D_exec/undeclared inside benign-1. Only that exact shape is dropped; a process in the
# container that runs a memfd (fileless malware) has a container parent and is still verified.
RUNTIME_INIT_EXE = re.compile(r"^/proc/self/fd/[0-9]+$")
RUNTIME_PARENTS = frozenset({"runc", "crun"})

KPROBE_KINDS = {
    "security_file_permission": "write",
    "security_path_truncate": "write",
    "security_file_truncate": "write",
    "security_mmap_file": "load",
    "cap_capable": "cap",
    "tcp_connect": "connect",
}

# The §4.3 fields each kind writes to events.jsonl, in the contract's order. cap and connect
# have no entry: their payload has no contract field yet.
BASE_FIELDS = ("time", "kind", "container_id", "namespace", "pod", "container",
               "pid", "ppid", "exe", "parent_exe")
RECORD_FIELDS = {
    "exec": BASE_FIELDS + ("hash",),
    "write": BASE_FIELDS + ("path",),
    "load": BASE_FIELDS + ("path", "hash"),
    "exit": BASE_FIELDS,
}
KINDS = ("exec", "exit", "write", "load", "cap", "connect")

_TIME = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def parse_time(value) -> int | None:
    """UTC ISO 8601 (Tetragon gives nanoseconds) -> integer nanoseconds since the epoch."""
    m = _TIME.match(value) if isinstance(value, str) else None
    if not m:
        return None
    y, mo, d, h, mi, s, frac, tz = m.groups()
    try:
        dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s))      # rejects 2026-13-40
    except ValueError:
        return None
    secs = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(s), 0, 0, 0))
    if tz != "Z":
        offset = int(tz[1:3]) * 3600 + int(tz[4:6]) * 60
        secs -= offset if tz[0] == "+" else -offset
    return secs * 1_000_000_000 + int((frac or "").ljust(9, "0"))


def format_time(ns: int) -> str:
    """Integer nanoseconds -> UTC ISO 8601 with Z and at least millisecond precision."""
    secs, rest = divmod(ns, 1_000_000_000)
    frac = f"{rest:09d}".rstrip("0").ljust(3, "0")
    return dt.datetime.fromtimestamp(secs, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{frac}Z"


def normalise_hash(value) -> str | None:
    """A runtime hash as the envelope writes sha256: 64 lower-case hex digits, no prefix."""
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    if value.startswith("sha256:"):
        value = value[len("sha256:"):]
    return value if _HEX64.match(value) else None


@dataclass(slots=True)
class Event:
    """One normalised event. Only the §4.3 fields reach events.jsonl (see `record`)."""
    time: str                       # UTC ISO 8601, as the source gave it
    t: int                          # the same instant in nanoseconds, for ordering and windows
    kind: str
    container_id: str
    namespace: str
    pod: str
    container: str
    pid: int | None
    ppid: int | None
    exe: str | None
    parent_exe: str | None
    path: str | None = None         # write, load: the file
    hash: str | None = None         # exec, load: runtime sha256; None means path-only
    cap: str | None = None          # cap: the capability checked      (in memory only)
    granted: bool | None = None     # cap: True if cap_capable returned 0 (in memory only)
    daddr: str | None = None        # connect: destination address       (in memory only)
    dport: int | None = None        # connect: destination port          (in memory only)
    protocol: str | None = None     # connect: tcp                       (in memory only)

    def record(self) -> dict | None:
        """The events.jsonl line: §4.3 field names only. None for cap and connect (see Q1)."""
        fields = RECORD_FIELDS.get(self.kind)
        return None if fields is None else {f: getattr(self, f) for f in fields}

    @classmethod
    def from_record(cls, rec: dict) -> Event | None:
        """An events.jsonl line back to an Event, for replay. None if it is not a usable event."""
        if not isinstance(rec, dict) or rec.get("kind") not in KINDS:
            return None
        t = parse_time(rec.get("time"))
        if t is None or not isinstance(rec.get("container_id"), str):
            return None
        return cls(time=rec["time"], t=t, kind=rec["kind"], container_id=rec["container_id"],
                   namespace=_str(rec.get("namespace")), pod=_str(rec.get("pod")),
                   container=_str(rec.get("container")), pid=_int(rec.get("pid")),
                   ppid=_int(rec.get("ppid")), exe=_opt_str(rec.get("exe")),
                   parent_exe=_opt_str(rec.get("parent_exe")), path=_opt_str(rec.get("path")),
                   hash=normalise_hash(rec.get("hash")), cap=_opt_str(rec.get("cap")),
                   granted=rec.get("granted") if isinstance(rec.get("granted"), bool) else None,
                   daddr=_opt_str(rec.get("daddr")), dport=_int(rec.get("dport")),
                   protocol=_opt_str(rec.get("protocol")))


def _int(value) -> int | None:
    """Tetragon's JSON gives 64-bit numbers as strings (protobuf JSON mapping)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _str(value) -> str:
    return value if isinstance(value, str) else ""


def _opt_str(value) -> str | None:
    return value if isinstance(value, str) and value else None


def _find(args, key: str):
    """The first kprobe argument of one type. Arguments are found by type, not position, so a
    policy's `nop` arguments may be left out of the output or not."""
    for a in args if isinstance(args, list) else ():
        if isinstance(a, dict) and key in a:
            return a[key]
    return None


def _file_path(args) -> str | None:
    for key in ("file_arg", "path_arg"):
        f = _find(args, key)
        if isinstance(f, dict) and isinstance(f.get("path"), str):
            return f["path"]
    return None


def _return_int(kp: dict) -> int | None:
    ret = kp.get("return")
    return _int(ret.get("int_arg")) if isinstance(ret, dict) else None


class Normalizer:
    """Tetragon JSON lines -> Events. `stats` counts each kind kept and each reason dropped."""

    def __init__(self, namespaces: Iterable[str] | None = ("demo",)):
        self.namespaces = None if namespaces is None else frozenset(namespaces)
        self.stats: Counter = Counter()
        self._capsets_seen = False          # a process.cap was seen: a missing one means "holds nothing"

    def __call__(self, line) -> Event | None:
        if isinstance(line, (str, bytes)):
            try:
                obj = json.loads(line)
            except ValueError:
                return self._drop("bad_json")
        else:
            obj = line
        if not isinstance(obj, dict):
            return self._drop("bad_json")
        if "kind" in obj:                                   # already normalised (events.jsonl)
            ev = Event.from_record(obj)
            if ev is None:
                return self._drop("bad_record")
            if self.namespaces is not None and ev.namespace not in self.namespaces:
                return self._drop("other_namespace")
            return self._keep(ev)
        for key, handler in (("process_exec", self._exec), ("process_kprobe", self._kprobe),
                             ("process_exit", self._exit)):
            if key in obj:
                body = obj[key]
                if not isinstance(body, dict):
                    return self._drop("bad_json")
                return handler(obj, body)
        return self._drop("other_event")

    def _drop(self, reason: str) -> None:
        self.stats["drop:" + reason] += 1
        return None

    def _keep(self, ev: Event) -> Event:
        self.stats["kind:" + ev.kind] += 1
        return ev

    def _base(self, obj: dict, body: dict, kind: str) -> Event | None:
        """The fields every kind shares, or None (after counting why) if the event is unusable."""
        proc, parent = body.get("process"), body.get("parent")
        if not isinstance(proc, dict):
            return self._drop("no_process")
        pod = proc.get("pod")
        if not isinstance(pod, dict) or not isinstance(pod.get("namespace"), str):
            return self._drop("no_pod")                     # a host process, or not yet mapped
        if self.namespaces is not None and pod["namespace"] not in self.namespaces:
            return self._drop("other_namespace")
        container = pod.get("container") if isinstance(pod.get("container"), dict) else {}
        cid = _opt_str(container.get("id")) or _opt_str(proc.get("docker"))
        if cid is None:
            return self._drop("no_container")
        t = parse_time(obj.get("time"))
        time = obj.get("time")
        if t is None:                                        # fall back to the process start
            t, time = parse_time(proc.get("start_time")), proc.get("start_time")
            if t is None:
                return self._drop("no_time")
        parent = parent if isinstance(parent, dict) else {}
        if _is_runtime_init(proc, parent):
            return self._drop("runtime_init")
        return Event(time=time, t=t, kind=kind, container_id=cid, namespace=pod["namespace"],
                     pod=_str(pod.get("name")), container=_str(container.get("name")),
                     pid=_int(proc.get("pid")), ppid=_int(parent.get("pid")),
                     exe=_exe(proc), parent_exe=_exe(parent))

    def _exec(self, obj: dict, body: dict) -> Event | None:
        ev = self._base(obj, body, "exec")
        return None if ev is None else self._keep(ev)

    def _exit(self, obj: dict, body: dict) -> Event | None:
        ev = self._base(obj, body, "exit")
        return None if ev is None else self._keep(ev)

    def _kprobe(self, obj: dict, body: dict) -> Event | None:
        kind = KPROBE_KINDS.get(body.get("function_name"))
        if kind is None:
            return self._drop("other_function")
        args, ret = body.get("args"), _return_int(body)
        if kind in ("write", "load"):
            path = _file_path(args)
            if not path or not path.startswith("/"):
                return self._drop("not_a_file")             # pipe:[…], socket:[…], anonymous map
            if ret not in (None, 0):
                return self._drop("denied")                 # the LSM refused it: nothing changed
            if body["function_name"] == "security_file_permission":
                mask = _int(_find(args, "int_arg"))
                if mask is None or not mask & MAY_WRITE:
                    return self._drop("not_a_write")
            if kind == "load":
                prot = _int(_find(args, "uint_arg"))
                prot = _int(_find(args, "int_arg")) if prot is None else prot
                if prot is None or not prot & PROT_EXEC:
                    return self._drop("not_executable")
            ev = self._base(obj, body, kind)
            if ev is None:
                return None
            ev.path = path
            return self._keep(ev)
        if kind == "cap":
            c = _find(args, "capability_arg")
            if not isinstance(c, dict):
                return self._drop("no_capability")
            name, value = _opt_str(c.get("name")), _int(c.get("value"))
            # The number is canonical: Tetragon 1.7 names value 1 "DAC_OVERRIDE", without the CAP_
            # prefix every other name (and the envelope) has.
            if value is not None and 0 <= value < len(CAPABILITIES):
                name = CAPABILITIES[value]
            elif name is not None and not name.startswith("CAP_"):
                name = "CAP_" + name
            if name is None:
                return self._drop("no_capability")
            ev = self._base(obj, body, kind)
            if ev is None:
                return None
            granted = None if ret is None else ret == 0
            proc = body.get("process")
            if isinstance(proc, dict) and isinstance(proc.get("cap"), dict):
                self._capsets_seen = True                   # enableProcessCred is on in this stream
            own = own_capabilities(proc, assume_empty=self._capsets_seen)
            if granted and own is not None and name not in own:
                # A 0 for a capability the process does not hold (enableProcessCred's process.cap):
                # the check was made with other credentials (on the demo VM, overlayfs acting with
                # the mounter's), so it is not this process using the capability.
                granted = False
                self.stats["cap:not_held"] += 1
            ev.cap, ev.granted = name, granted
            return self._keep(ev)
        sock = _find(args, "sock_arg")                          # connect
        if not isinstance(sock, dict) or not _opt_str(sock.get("daddr")):
            return self._drop("no_destination")
        ev = self._base(obj, body, kind)
        if ev is None:
            return None
        ev.daddr, ev.dport = sock["daddr"], _int(sock.get("dport"))
        proto = _opt_str(sock.get("protocol")) or "IPPROTO_TCP"
        ev.protocol = proto.lower().removeprefix("ipproto_")
        return self._keep(ev)


def own_capabilities(proc, assume_empty: bool = False) -> frozenset[str] | None:
    """The process's own effective capabilities (process.cap.effective, sent with Tetragon's
    enableProcessCred) as CAP_* names, or None when the event does not carry them.

    Tetragon's JSON leaves out empty lists, so a process holding nothing (a workload that switched
    to a non-root user: postgres, mysql, grafana... on the demo VM) has no `effective`, or no `cap`
    at all. A `cap` without `effective` is therefore the empty set; a missing `cap` is the empty set
    when `assume_empty` (the caller has seen capability sets in the same stream), else unknown."""
    capset = proc.get("cap") if isinstance(proc, dict) else None
    if not isinstance(capset, dict):
        return frozenset() if assume_empty and isinstance(proc, dict) else None
    eff = capset.get("effective")
    if not isinstance(eff, list):
        return frozenset()
    out = set()
    for name in eff:
        if isinstance(name, str) and name:
            name = name.strip().upper()
            out.add(name if name.startswith("CAP_") else "CAP_" + name)   # Tetragon: "DAC_OVERRIDE"
    return frozenset(out)


def is_runtime_init(proc: dict, parent: dict) -> bool:
    """Public name for the runtime-init test, shared with the profiling labels (testbed/profiling)."""
    return _is_runtime_init(proc if isinstance(proc, dict) else {}, parent if isinstance(parent, dict) else {})


def _is_runtime_init(proc: dict, parent: dict) -> bool:
    """runc's or crun's init step (see RUNTIME_INIT_EXE): memfd path, argument "init", runtime parent."""
    binary, parent_bin = _opt_str(proc.get("binary")), _opt_str(parent.get("binary"))
    return (binary is not None and RUNTIME_INIT_EXE.match(binary) is not None
            and (_opt_str(proc.get("arguments")) or "").strip() == "init"
            and parent_bin is not None and posixpath.basename(parent_bin) in RUNTIME_PARENTS)


def _exe(proc: dict) -> str | None:
    """process.binary; a relative path is joined to the process's cwd, never guessed further."""
    binary = _opt_str(proc.get("binary"))
    if binary is None or binary.startswith("/"):
        return binary
    cwd = _opt_str(proc.get("cwd"))
    return posixpath.normpath(posixpath.join(cwd, binary)) if cwd and cwd.startswith("/") else binary


def iter_events(lines: Iterable, normalizer: Normalizer | None = None) -> Iterator[Event]:
    """Every usable event in a stream of Tetragon JSON or events.jsonl lines, in order."""
    normalizer = normalizer or Normalizer()
    for line in lines:
        if isinstance(line, (str, bytes)) and not line.strip():
            continue
        ev = normalizer(line)
        if ev is not None:
            yield ev
