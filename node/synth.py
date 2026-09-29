"""Synthetic Tetragon events, for tests only. Nothing made from them is a project result.

The shapes follow Tetragon's JSON export: process_exec, process_exit and process_kprobe with
typed arguments (file_arg, int_arg, uint_arg, capability_arg, sock_arg) and a return value. The
cloud has no Tetragon, so they were written from the documentation. Check them against a real
recording (node/testdata/raw.jsonl on the demo PC) before trusting any number made from them.

A `Session` builds one stream with a clock: every event advances it by `step_ms`, and `sleep`
jumps ahead.

    s = Session()
    app = s.proc("/usr/local/bin/python3.11", pid=4402)
    s.exec(app)
    x9 = s.proc("/tmp/.x9", parent=app)
    s.exec(x9); s.write(x9, "/etc/passwd")
    lines = s.lines()
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field

from .normalize import CAPABILITIES, format_time, parse_time

DIGEST = "sha256:6105d6cc76af400325e94d588ce511be5bfdbb73b437dc51eca43917d7a43e3d"   # contracts sample
DEMO_CID = "containerd://" + "4b1c" * 16
DEMO_POD = "demo-app-7d9f"
NODE = "kind-control-plane"


@dataclass
class Proc:
    binary: str
    pid: int
    parent: Proc | None = None
    namespace: str = "demo"
    pod: str | None = DEMO_POD
    container: str = "app"
    container_id: str = DEMO_CID
    cwd: str = "/"
    uid: int = 0
    start_time: str = ""
    arguments: str = ""
    extra: dict = field(default_factory=dict)

    def json(self) -> dict:
        """Tetragon's process object."""
        exec_id = base64.b64encode(f"{NODE}:{self.pid}:{self.binary}".encode()).decode()
        doc = {"exec_id": exec_id, "pid": self.pid, "uid": self.uid, "cwd": self.cwd,
               "binary": self.binary, "arguments": self.arguments, "flags": "execve clone",
               "start_time": self.start_time, "auid": 4294967295, "tid": self.pid}
        if self.pod is not None:
            doc["pod"] = {
                "namespace": self.namespace, "name": self.pod,
                "container": {"id": self.container_id, "name": self.container,
                              "image": {"id": f"localhost:5001/demo-app@{DIGEST}",
                                        "name": f"localhost:5001/demo-app@{DIGEST}"},
                              "start_time": self.start_time, "pid": 1},
                "pod_labels": {"app": self.pod.rsplit("-", 1)[0]},
                "workload": self.pod.rsplit("-", 1)[0], "workload_kind": "Deployment"}
            doc["docker"] = self.container_id.split("://", 1)[-1][:31]
        if self.parent is not None:
            doc["parent_exec_id"] = base64.b64encode(
                f"{NODE}:{self.parent.pid}:{self.parent.binary}".encode()).decode()
        doc.update(self.extra)
        return doc


class Session:
    """One synthetic Tetragon stream with its own clock."""

    def __init__(self, start: str = "2026-09-28T10:00:00Z", step_ms: int = 10):
        self.now = parse_time(start)
        self.step = step_ms * 1_000_000
        self.events: list[dict] = []
        self._next_pid = 4400

    # the clock -----------------------------------------------------------------------------
    def sleep(self, seconds: float) -> None:
        self.now += int(seconds * 1_000_000_000)

    def time(self) -> str:
        return format_time(self.now)

    def _stamp(self) -> str:
        t = format_time(self.now)
        self.now += self.step
        return t

    # processes -----------------------------------------------------------------------------
    def proc(self, binary: str, pid: int | None = None, parent: Proc | None = None, **kw) -> Proc:
        if pid is None:
            self._next_pid += 1
            pid = self._next_pid
        if parent is not None and parent.pod is not None:   # a child inherits its parent's pod,
            for k in ("namespace", "pod", "container", "container_id"):   # not a host process's
                kw.setdefault(k, getattr(parent, k))
        return Proc(binary=binary, pid=pid, parent=parent, start_time=self.time(), **kw)

    def _emit(self, key: str, proc: Proc, body: dict) -> dict:
        doc = {key: {"process": proc.json(), **body}, "node_name": NODE, "time": self._stamp()}
        if proc.parent is not None:
            doc[key]["parent"] = proc.parent.json()
        self.events.append(doc)
        return doc

    def exec(self, proc: Proc) -> dict:
        proc.start_time = self.time()
        return self._emit("process_exec", proc, {})

    def exit(self, proc: Proc, status: int = 0) -> dict:
        return self._emit("process_exit", proc, {"signal": "", "status": status})

    def _kprobe(self, proc: Proc, function: str, args: list, ret: int | None, policy: str) -> dict:
        body = {"function_name": function, "args": args, "action": "KPROBE_ACTION_POST",
                "policy_name": policy}
        if ret is not None:
            body["return"] = {"int_arg": ret}
            body["return_action"] = "KPROBE_ACTION_POST"
        return self._emit("process_kprobe", proc, body)

    # kprobes, as the policies in node/tetragon/ define them ---------------------------------
    def write(self, proc: Proc, path: str, mask: int = 0x02, ret: int | None = 0) -> dict:
        args = [{"file_arg": {"path": path, "permission": "-rw-r--r--"}}, {"int_arg": mask}]
        return self._kprobe(proc, "security_file_permission", args, ret, "provbind-write")

    def truncate(self, proc: Proc, path: str, via_file: bool = True, ret: int | None = 0) -> dict:
        if via_file:
            return self._kprobe(proc, "security_file_truncate", [{"file_arg": {"path": path}}], ret,
                                "provbind-truncate")
        return self._kprobe(proc, "security_path_truncate", [{"path_arg": {"path": path}}], ret,
                            "provbind-truncate")

    def mmap(self, proc: Proc, path: str, prot: int = 0x05, ret: int | None = 0) -> dict:
        args = [{"file_arg": {"path": path, "permission": "-rwxr-xr-x"}}, {"uint_arg": prot}]
        return self._kprobe(proc, "security_mmap_file", args, ret, "provbind-load")

    def cap(self, proc: Proc, cap: str, granted: bool | None = True) -> dict:
        args = [{"user_ns_arg": {"level": 0, "uid": 0, "gid": 0,
                                 "ns": {"inum": 4026531837, "is_host": True}}},
                {"capability_arg": {"value": CAPABILITIES.index(cap), "name": cap}}]
        return self._kprobe(proc, "cap_capable", args, None if granted is None else (0 if granted else -1),
                            "provbind-cap")

    def connect(self, proc: Proc, daddr: str, dport: int, saddr: str = "10.244.0.12",
                sport: int = 43210) -> dict:
        args = [{"sock_arg": {"family": "AF_INET", "type": "SOCK_STREAM", "protocol": "IPPROTO_TCP",
                              "saddr": saddr, "daddr": daddr, "sport": sport, "dport": dport,
                              "cookie": "18446635827187264768", "state": "TCP_SYN_SENT"}}]
        return self._kprobe(proc, "tcp_connect", args, None, "provbind-connect")

    # output ---------------------------------------------------------------------------------
    def lines(self) -> list[str]:
        return [json.dumps(e, separators=(",", ":")) for e in self.events]
