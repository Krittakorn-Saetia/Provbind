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
import copy
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .normalize import CAPABILITIES, format_time, parse_time

SAMPLE = Path(__file__).resolve().parents[1] / "contracts" / "envelope.sample.json"
DIGEST = "sha256:6105d6cc76af400325e94d588ce511be5bfdbb73b437dc51eca43917d7a43e3d"   # contracts sample
DEMO_CID = "containerd://" + "4b1c" * 16
DEMO_POD = "demo-app-7d9f"
ROGUE_CID = "containerd://" + "9d2e" * 16          # in no binding: attack-9
UNSIGNED_CID = "containerd://" + "7a5f" * 16       # bound, evidence did not verify
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
        self._pids: set[int] = set()

    # the clock -----------------------------------------------------------------------------
    def sleep(self, seconds: float) -> None:
        self.now += round(seconds * 1_000_000) * 1000               # whole microseconds

    def time(self) -> str:
        return format_time(self.now)

    def _stamp(self) -> str:
        t = format_time(self.now)
        self.now += self.step
        return t

    # processes -----------------------------------------------------------------------------
    def proc(self, binary: str, pid: int | None = None, parent: Proc | None = None, **kw) -> Proc:
        if pid is None:                                    # never reuse a pid given explicitly
            self._next_pid += 1
            while self._next_pid in self._pids:
                self._next_pid += 1
            pid = self._next_pid
        self._pids.add(pid)
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


# the scenario library (Test Plan §7), synthetic --------------------------------------------------

def fake_sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def demo_envelope() -> dict:
    """contracts/envelope.sample.json plus the declared files the synthetic scenarios touch."""
    env = json.loads(SAMPLE.read_text(encoding="utf-8"))
    coreutils = "pkg:deb/debian/coreutils@9.1-1?arch=amd64&distro=debian-12"
    libc = "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12"
    selinux = "pkg:deb/debian/libselinux1@3.4-1+b6?arch=amd64&distro=debian-12"
    extra = {
        "/usr/bin/cat": (0, coreutils, "0755"),
        "/usr/lib/x86_64-linux-gnu/libselinux.so.1": (0, selinux, "0644"),
        "/usr/lib/x86_64-linux-gnu/libnss_dns.so.2": (0, libc, "0644"),
        "/usr/local/lib/python3.11/lib-dynload/_ssl.cpython-311-x86_64-linux-gnu.so": (2, None, "0755"),
        "/etc/hosts": (0, None, "0644"),
        "/app/data/seed.json": (5, None, "0644"),
    }
    for path, (layer, pkg, mode) in extra.items():
        env["files"][path] = {"sha256": fake_sha(path), "layer": layer, "package": pkg, "mode": mode}
    env["packages"][selinux] = {"depth": None}
    return env


def demo_bindings() -> dict:
    """bindings.json (§4.2) for the demo pod, plus one container whose evidence did not verify."""
    return {
        DEMO_CID: {"namespace": "demo", "pod": DEMO_POD, "container": "app", "image_digest": DIGEST,
                   "verified": True, "run_as_root": True, "privileged": False,
                   "mounts": ["/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/dev/termination-log",
                              "/var/run/secrets/kubernetes.io/serviceaccount", "/app/data"],
                   "envelope_ready": True},
        UNSIGNED_CID: {"namespace": "demo", "pod": "unsigned-6f2a", "container": "app",
                       "image_digest": "sha256:" + "ee" * 32, "verified": False, "run_as_root": True,
                       "privileged": False, "mounts": [], "envelope_ready": False},
    }


EGRESS = ["10.96.0.0/12", "10.244.0.0/16", "127.0.0.0/8"]      # cluster services, pods, loopback


@dataclass
class Library:
    lines: list
    ground_truth: list                  # rows of §4.7 as dicts
    envelope: dict
    bindings: dict
    hashes: dict                        # (container_id, pid) -> the executed file's sha256
    egress: list


def library(attack2_files: int = 300) -> Library:
    """One synthetic session: the app starts, then each scenario runs in its own window.

    Expected outcomes, with the runtime hashes of `hashes` (and path-only in brackets):
      benign-1  sh and ls: D_exec / outside_closure twice (weak); nothing else
      attack-1  /tmp/.x9: D_exec / undeclared; /etc/passwd: D_write
      ph4-14    /tmp/new.txt written: nothing
      attack-2  300 new files under /tmp/.cache: nothing deterministic
      attack-3  /tmp/.l with ls's content: D_hash / relocated   [D_exec / undeclared]
      attack-4  /usr/bin/ls overwritten, then run: D_write, then D_hash / modified   [D_exec / outside_closure]
      attack-5  python3 with LD_PRELOAD=/tmp/libx.so: D_load / undeclared
      attack-6  os.chown to uid 4242: D_cap (INFERRED)
      attack-7  a connection to 203.0.113.9:4444: D_net
      benign-3  a DNS lookup maps libnss_dns: D_load / outside_closure (weak); the DNS connection is allowed
      benign-4  writes to /app/data (a mount) and /etc/hosts: nothing
      attack-9  a container in no binding: binding / unknown_container; one that did not verify: binding / unverified
    """
    env = demo_envelope()
    declared = {p: f["sha256"] for p, f in env["files"].items()}
    s = Session(start="2026-09-28T10:00:00Z")
    rows, hashes = [], {}

    def run(pid_proc: Proc, sha: str | None = None):
        s.exec(pid_proc)
        real = sha if sha is not None else declared.get(pid_proc.binary, fake_sha("new " + pid_proc.binary))
        hashes[(pid_proc.container_id, pid_proc.pid)] = real

    def scenario(name: str, label: str, body, pod_prefix: str = "demo-app"):
        s.sleep(5)
        start = s.time()
        s.sleep(0.5)
        body()
        s.sleep(0.5)
        rows.append({"scenario": name, "label": label, "namespace": "demo", "pod_prefix": pod_prefix,
                     "start": start, "end": s.time(), "expected": ""})

    shim = s.proc("/usr/local/bin/containerd-shim-runc-v2", pid=4100, pod=None)
    runc = s.proc("/usr/local/sbin/runc", pid=4150, pod=None)
    app = s.proc("/usr/local/bin/python3.11", pid=4402, parent=shim, arguments="app.py")
    run(app)
    s.mmap(app, "/usr/local/bin/python3.11")
    s.mmap(app, "/usr/local/lib/libpython3.11.so.1.0")
    s.mmap(app, "/usr/lib/x86_64-linux-gnu/libc.so.6")

    def benign_1():
        sh = s.proc("/usr/bin/dash", parent=runc, pod=DEMO_POD, container_id=DEMO_CID)
        run(sh)
        ls = s.proc("/usr/bin/ls", parent=sh)
        run(ls)
        s.mmap(ls, "/usr/lib/x86_64-linux-gnu/libselinux.so.1")     # ls is outside the closure: not judged
        s.mmap(ls, "/usr/lib/x86_64-linux-gnu/libc.so.6")
        s.exit(ls)
        s.exit(sh)

    def attack_1():
        s.write(app, "/tmp/.x9")
        x9 = s.proc("/tmp/.x9", pid=4471, parent=app)
        run(x9)
        s.write(x9, "/etc/passwd")

    def ph4_14():
        s.write(app, "/tmp/new.txt")

    def attack_2():
        step = 20.0 / max(attack2_files, 1)
        for i in range(attack2_files):
            s.write(app, f"/tmp/.cache/f{i:03d}")
            s.sleep(step)

    def attack_3():
        s.write(app, "/tmp/.l")
        relocated = s.proc("/tmp/.l", parent=app)
        run(relocated, sha=declared["/usr/bin/ls"])

    def attack_4():
        s.write(app, "/usr/bin/ls")
        ls = s.proc("/usr/bin/ls", parent=app)
        run(ls, sha=declared["/usr/bin/cat"])

    def attack_5():
        s.write(app, "/tmp/libx.so")
        child = s.proc("/usr/local/bin/python3.11", parent=app, arguments="-c pass")
        run(child)
        s.mmap(child, "/tmp/libx.so")
        s.mmap(child, "/usr/lib/x86_64-linux-gnu/libc.so.6")
        s.exit(child)

    def attack_6():
        s.cap(app, "CAP_CHOWN", granted=True)

    def attack_7():
        s.connect(app, "203.0.113.9", 4444)

    def benign_3():
        s.mmap(app, "/usr/lib/x86_64-linux-gnu/libnss_dns.so.2")
        s.connect(app, "10.96.0.10", 53)

    def benign_4():
        s.write(app, "/app/data/seed.json")
        s.write(app, "/etc/hosts")

    def attack_9():
        rogue = s.proc("/usr/bin/sleep", pod="rogue-5c7d", container_id=ROGUE_CID, parent=runc)
        run(rogue)
        s.write(rogue, "/tmp/rogue")
        unsigned = s.proc("/usr/bin/sleep", pod="unsigned-6f2a", container_id=UNSIGNED_CID, parent=runc)
        run(unsigned)

    for name, label, body, prefix in (
            ("benign-1", "benign", benign_1, "demo-app"), ("attack-1", "malicious", attack_1, "demo-app"),
            ("ph4-14", "benign", ph4_14, "demo-app"), ("attack-2", "malicious", attack_2, "demo-app"),
            ("attack-3", "malicious", attack_3, "demo-app"), ("attack-4", "malicious", attack_4, "demo-app"),
            ("attack-5", "malicious", attack_5, "demo-app"), ("attack-6", "malicious", attack_6, "demo-app"),
            ("attack-7", "malicious", attack_7, "demo-app"), ("benign-3", "benign", benign_3, "demo-app"),
            ("benign-4", "benign", benign_4, "demo-app"), ("attack-9", "malicious", attack_9, "")):
        scenario(name, label, body, prefix)
    s.sleep(40)                                                  # past the binding grace period
    s.exit(app)
    return Library(lines=s.lines(), ground_truth=rows, envelope=env, bindings=demo_bindings(),
                   hashes=hashes, egress=list(EGRESS))


def library_copy(lib: Library) -> Library:
    return copy.deepcopy(lib)
