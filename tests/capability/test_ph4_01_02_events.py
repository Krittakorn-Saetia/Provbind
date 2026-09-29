"""PH4-01, PH4-02a and PH4-02b: Tetragon's events reach PROVBIND with every field (Test Plan §3.5).

- PH4-01 (P0): exec events carry the real path, pid, ppid and container (Eq. 50).
- PH4-02a (P0): exec, write and capability events arrive; the event rate per kind is recorded (M11).
- PH4-02b (P1): executable-mmap and connect events arrive; the event rate per kind is recorded (M11).

Evidence, first found wins:
1. PROVBIND_RECORDING: Tetragon's JSON export recorded on the demo PC, e.g.
   `kubectl logs -n kube-system ds/tetragon -c export-stdout -f | tee rec.jsonl | python -m node.run`.
   Every kind the test needs must appear in namespace demo.
2. run/results/<ID>/capture.jsonl with triggers.json: what the live test below captured around its
   own kubectl exec triggers. Each trigger must show up.
3. Otherwise a synthetic stream (node/synth.py). The checks run on it, and the result is not_run.

"Real path" needs the image's symlinks: PROVBIND_ENVELOPE, or the envelopes that
$PROVBIND_RUN/bindings.json points to. Without one, PH4-01 cannot pass and stays not_run.

The live tests are marked integration (demo PC only). They trigger each event in a demo pod
(PROVBIND_DEMO_POD, or the first running pod named PROVBIND_DEMO_POD_PREFIX*, default demo-app)
and capture Tetragon's export for that window. They save the capture, then record the result
from it, so later runs of the unit tests re-read the same capture instead of resetting it.
Each test also runs the normaliser and policy unit tests (node/tests/).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

import pytest

from compiler.paths import realpath
from node.normalize import Normalizer
from node.synth import DEMO_CID, Session

ROOT = Path(__file__).resolve().parents[2]
RUN = Path(os.environ.get("PROVBIND_RUN", "./run"))
SAMPLE_ENVELOPE = ROOT / "contracts" / "envelope.sample.json"
UNIT_SUITES = ("node/tests/test_normalize.py", "node/tests/test_policies.py")
KINDS = {"PH4-02a": ("exec", "write", "cap"), "PH4-02b": ("load", "connect")}
POLICY_OF = {"exec": "values.yaml", "write": "write.yaml", "cap": "cap.yaml", "load": "load.yaml",
             "connect": "connect.yaml"}
_CID = re.compile(r"^[a-z0-9-]+://[0-9a-f]{64}$")


def run_suite(test_id: str, suites) -> dict:
    """Run unit-test files in a fresh pytest process: counts, output and the JUnit XML path."""
    junit = RUN / "results" / test_id / "junit.xml"
    junit.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-m", "not integration", "-p", "no:cacheprovider",
                           f"--junitxml={junit.resolve()}", *suites], cwd=ROOT, capture_output=True, text=True,
                          timeout=900)
    root = ET.parse(junit).getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    counts = {k: int(suite.get(k, 0)) for k in ("tests", "failures", "errors", "skipped")}
    passed = counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"]
    return {"ok": proc.returncode == 0 and passed > 0 and counts["failures"] == counts["errors"] == 0,
            "metrics": {"passed": passed, "failed": counts["failures"] + counts["errors"],
                        "skipped": counts["skipped"]},
            "output": proc.stdout[-3000:] + proc.stderr[-1000:], "junit": str(junit)}


# evidence -------------------------------------------------------------------------------------

def synthetic_stream() -> list[str]:
    """One demo pod doing each kind once, as the policies in node/tetragon/ report it."""
    s = Session()
    shim = s.proc("/usr/local/bin/containerd-shim-runc-v2", pid=4100, pod=None)
    app = s.proc("/usr/local/bin/python3.11", pid=4402, parent=shim)
    s.exec(app)
    s.mmap(app, "/usr/local/lib/libpython3.11.so.1.0")
    sh = s.proc("/usr/bin/dash", parent=app)
    s.exec(sh)
    s.write(sh, "/tmp/.provbind-trigger")
    chown = s.proc("/usr/bin/chown", parent=sh)
    s.exec(chown)
    s.cap(chown, "CAP_CHOWN")
    s.connect(app, "127.0.0.1", 8080)
    s.exit(chown)
    return s.lines()


def evidence(test_id: str) -> dict:
    """The event stream to judge, where it came from, and the triggers if it is a live capture."""
    rec = os.environ.get("PROVBIND_RECORDING")
    if rec:
        return {"lines": Path(rec).read_text(encoding="utf-8").splitlines(), "source": rec, "real": True,
                "triggers": None, "artifacts": [rec]}
    capture = RUN / "results" / test_id / "capture.jsonl"
    triggers = capture.with_name("triggers.json")
    if capture.exists() and triggers.exists():
        return {"lines": capture.read_text(encoding="utf-8").splitlines(), "source": str(capture), "real": True,
                "triggers": json.loads(triggers.read_text(encoding="utf-8")),
                "artifacts": [str(capture), str(triggers)]}
    return {"lines": synthetic_stream(), "source": "synthetic stream (node/synth.py)", "real": False,
            "triggers": None, "artifacts": []}


def symlinks_for():
    """container_id -> the image's symlinks, from PROVBIND_ENVELOPE or the run folder; None if unknown."""
    one = os.environ.get("PROVBIND_ENVELOPE")
    if one:
        links = json.loads(Path(one).read_text(encoding="utf-8"))["symlinks"]
        return lambda cid: links
    bindings_path = RUN / "bindings.json"
    if not bindings_path.exists():
        return None
    by_cid = {}
    for cid, b in json.loads(bindings_path.read_text(encoding="utf-8")).items():
        digest = (b or {}).get("image_digest") or ""
        env = RUN / "envelopes" / f"{digest.split(':', 1)[-1]}.json"
        if env.exists():
            by_cid[cid] = json.loads(env.read_text(encoding="utf-8"))["symlinks"]
    return by_cid.get if by_cid else None


def normalise(lines):
    n = Normalizer(namespaces=("demo",))
    events = [e for e in map(n, (line for line in lines if line.strip())) if e is not None]
    return events, n.stats


def rates(events) -> dict:
    """Events per kind, and per second over the stream's span (at least one second)."""
    counts = Counter(e.kind for e in events)
    span = max((events[-1].t - events[0].t) / 1e9, 1.0) if events else 1.0
    return {k: {"count": counts[k], "per_s": round(counts[k] / span, 3)} for k in sorted(counts)}


def exec_problems(events, links_of) -> tuple[Counter, dict, int]:
    """Every missing or wrong PH4-01 field: counts by problem, up to three example exe paths for
    each, and how many exe paths were checked for realness."""
    problems, examples, checked = Counter(), {}, 0

    def note(problem, e):
        problems[problem] += 1
        seen = examples.setdefault(problem, [])
        if len(seen) < 3 and e.exe not in seen:
            seen.append(e.exe)

    for e in events:
        if e.kind != "exec":
            continue
        for f in ("pod", "container", "exe"):
            if not getattr(e, f):
                note(f"no {f}", e)
        if not _CID.match(e.container_id or ""):
            note("container_id is not <runtime>://<64 hex>", e)
        if not isinstance(e.pid, int) or e.pid <= 0:
            note("no pid", e)
        if not isinstance(e.ppid, int) or e.ppid < 0:
            note("no ppid", e)
        if e.exe and not e.exe.startswith("/"):
            note("exe is not absolute", e)
        links = links_of(e.container_id) if links_of else None
        if links is not None and e.exe and e.exe.startswith("/"):
            checked += 1
            if realpath(e.exe, links) != e.exe:
                note("exe is not a real path", e)
    return problems, examples, checked


def status_for(ok: bool, real: bool, complete: bool = True) -> str:
    if not ok:
        return "fail"
    return "pass" if real and complete else "not_run"


# PH4-01 ---------------------------------------------------------------------------------------

def judge_ph4_01(ev: dict, links_of) -> dict:
    events, stats = normalise(ev["lines"])
    trig = ev["triggers"]
    if trig:
        events = [e for e in events if e.pod == trig["pod"] and e.kind == "exec" and (e.exe or "").endswith(trig["exec"])]
    execs = [e for e in events if e.kind == "exec"]
    problems, examples, checked = exec_problems(execs, links_of)
    ok = bool(execs) and not problems
    notes = f"{ev['source']}: {len(execs)} exec events in namespace demo"
    if problems:
        notes += "; problems: " + ", ".join(f"{k} ({v}, e.g. {', '.join(map(str, examples[k]))})"
                                           for k, v in sorted(problems.items()))
    if not execs:
        notes += "; no exec event" + (f" for {trig['exec']} in {trig['pod']}" if trig else "")
    if links_of is None:
        notes += "; no envelope, so real paths were not checked (set PROVBIND_ENVELOPE)"
    if not ev["real"]:
        notes += "; synthetic, so not a project result: set PROVBIND_RECORDING or run the live test"
    return {"status": status_for(ok, ev["real"], complete=links_of is not None and checked > 0), "notes": notes,
            "metrics": {"exec_events": len(execs), "real_paths_checked": checked,
                        "problems": dict(problems), "dropped": {k[5:]: v for k, v in stats.items()
                                                                if k.startswith("drop:")}}}


def test_ph4_01_exec_events_carry_every_field(record_result):
    kit = run_suite("PH4-01", UNIT_SUITES)
    ev = evidence("PH4-01")
    links_of = symlinks_for()
    if not ev["real"] and links_of is None:
        sample_links = json.loads(SAMPLE_ENVELOPE.read_text(encoding="utf-8"))["symlinks"]
        links_of = {DEMO_CID: sample_links}.get
    r = judge_ph4_01(ev, links_of)
    status = r["status"] if kit["ok"] else "fail"
    notes = r["notes"] + f"; unit tests: {kit['metrics']['passed']} passed, {kit['metrics']['failed']} failed"
    record_result("PH4-01", status, metrics={**r["metrics"], "unit_tests": kit["metrics"]}, notes=notes,
                  artifacts=ev["artifacts"] + [kit["junit"]])
    assert kit["ok"], kit["output"]
    assert status != "fail", notes


# PH4-02a and PH4-02b --------------------------------------------------------------------------

def judge_ph4_02(test_id: str, ev: dict) -> dict:
    events, stats = normalise(ev["lines"])
    need = KINDS[test_id]
    trig = ev["triggers"]
    per_kind = rates(events)
    if trig:
        hits = {k: sum(1 for e in events if e.pod == trig["pod"] and _is_trigger(e, k, trig[k])) for k in need}
    else:
        hits = {k: per_kind.get(k, {}).get("count", 0) for k in need}
    missing = [k for k in need if not hits[k]]
    ok = not missing
    notes = f"{ev['source']}: " + ", ".join(f"{k} {hits[k]}" for k in need)
    notes += " (events matching each trigger)" if trig else " (events in namespace demo)"
    if missing:
        notes += "; nothing arrived for: " + ", ".join(missing) + " (is " + ", ".join(
            sorted({f"node/tetragon/{POLICY_OF[k]}" for k in missing if k in POLICY_OF})) + " applied?)"
    if stats.get("drop:other_namespace"):
        notes += f"; {stats['drop:other_namespace']} events from other namespaces reached the stream"
    if not ev["real"]:
        notes += "; synthetic, so not a project result: set PROVBIND_RECORDING or run the live test"
    return {"status": status_for(ok, ev["real"]), "notes": notes,
            "metrics": {"events": hits, "rate_per_kind": {k: v for k, v in per_kind.items()},
                        "dropped": {k[5:]: v for k, v in stats.items() if k.startswith("drop:")}}}


def _is_trigger(e, kind: str, want) -> bool:
    if e.kind != kind:
        return False
    if kind == "exec":
        return (e.exe or "").endswith(want)
    if kind == "write":
        return e.path == want
    if kind == "load":
        return want in (e.path or "")
    if kind == "cap":
        return e.cap == want and e.granted is True
    return e.daddr == want["daddr"] and e.dport == want["dport"]


@pytest.mark.parametrize("test_id", sorted(KINDS))
def test_ph4_02_events_of_each_kind_arrive(test_id, record_result):
    kit = run_suite(test_id, UNIT_SUITES)
    ev = evidence(test_id)
    r = judge_ph4_02(test_id, ev)
    status = r["status"] if kit["ok"] else "fail"
    notes = r["notes"] + f"; unit tests: {kit['metrics']['passed']} passed, {kit['metrics']['failed']} failed"
    record_result(test_id, status, metrics={**r["metrics"], "unit_tests": kit["metrics"]}, notes=notes,
                  artifacts=ev["artifacts"] + [kit["junit"]])
    assert kit["ok"], kit["output"]
    assert status != "fail", notes


# live tests (demo PC) --------------------------------------------------------------------------

def _kubectl(*args, timeout=60, check=True) -> subprocess.CompletedProcess:
    proc = subprocess.run(["kubectl", *args], capture_output=True, text=True, timeout=timeout)
    if check and proc.returncode:
        pytest.skip(f"kubectl {' '.join(args[:3])} failed: {proc.stderr.strip()[-300:]}")
    return proc


def _demo_pod() -> str:
    if shutil.which("kubectl") is None:
        pytest.skip("kubectl is not on PATH")
    if os.environ.get("PROVBIND_DEMO_POD"):
        return os.environ["PROVBIND_DEMO_POD"]
    prefix = os.environ.get("PROVBIND_DEMO_POD_PREFIX", "demo-app")
    names = _kubectl("get", "pods", "-n", "demo", "--field-selector=status.phase=Running",
                     "-o", "jsonpath={.items[*].metadata.name}").stdout.split()
    pods = [n for n in names if n.startswith(prefix)]
    if not pods:
        pytest.skip(f"no running pod named {prefix}* in namespace demo")
    return pods[0]


def _exec_in(pod: str, *command: str) -> str:
    """Run the trigger in the pod. A trigger that fails still produces events, so it is noted, not skipped."""
    container = os.environ.get("PROVBIND_DEMO_CONTAINER")
    proc = _kubectl("exec", "-n", "demo", pod, *(["-c", container] if container else []), "--", *command,
                    check=False)
    return "" if proc.returncode == 0 else f"; the trigger exited {proc.returncode}: {proc.stderr.strip()[-200:]}"


def _capture(test_id: str, since: dt.datetime, triggers: dict, settle: float = 3.0) -> dict:
    """Tetragon's export since `since`, saved with the triggers as this test's evidence."""
    time.sleep(settle)                                     # let Tetragon export the events
    ns = os.environ.get("PROVBIND_TETRAGON_NAMESPACE", "kube-system")
    selector = os.environ.get("PROVBIND_TETRAGON_SELECTOR", "app.kubernetes.io/name=tetragon")
    container = os.environ.get("PROVBIND_TETRAGON_CONTAINER", "export-stdout")
    out = _kubectl("logs", "-n", ns, "-l", selector, "-c", container, "--tail=-1", "--max-log-requests=20",
                   "--since-time=" + since.strftime("%Y-%m-%dT%H:%M:%SZ"), timeout=120).stdout
    folder = RUN / "results" / test_id
    folder.mkdir(parents=True, exist_ok=True)
    capture, saved = folder / "capture.jsonl", folder / "triggers.json"
    capture.write_text(out, encoding="utf-8")
    saved.write_text(json.dumps(triggers, indent=2), encoding="utf-8")
    return {"lines": out.splitlines(), "source": str(capture), "real": True, "triggers": triggers,
            "artifacts": [str(capture), str(saved)]}


def _since() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=2)


@pytest.mark.integration
def test_ph4_01_live(record_result):
    pod, since = _demo_pod(), _since()
    exited = _exec_in(pod, "ls", "/")
    ev = _capture("PH4-01", since, {"pod": pod, "exec": "/ls"})
    r = judge_ph4_01(ev, symlinks_for())
    record_result("PH4-01", r["status"], metrics=r["metrics"], notes="live: " + r["notes"] + exited,
                  artifacts=ev["artifacts"])
    assert r["status"] != "fail", r["notes"]


@pytest.mark.integration
def test_ph4_02a_live(record_result):
    pod, since = _demo_pod(), _since()
    target = f"/tmp/.provbind-ph4-02a-{int(time.time())}"             # new each run: no truncation
    exited = _exec_in(pod, "sh", "-c", f"echo provbind > {target} && chown 4242 {target} && rm -f {target}")
    ev = _capture("PH4-02a", since, {"pod": pod, "exec": "/chown", "write": target, "cap": "CAP_CHOWN"})
    r = judge_ph4_02("PH4-02a", ev)
    record_result("PH4-02a", r["status"], metrics=r["metrics"], notes="live: " + r["notes"] + exited,
                  artifacts=ev["artifacts"])
    assert r["status"] != "fail", r["notes"]


@pytest.mark.integration
def test_ph4_02b_live(record_result):
    pod, since = _demo_pod(), _since()
    port = int(os.environ.get("PROVBIND_DEMO_PORT", "8080"))
    exited = _exec_in(pod, "python3", "-c",
                      f"import socket; socket.create_connection(('127.0.0.1', {port}), 2).close()")
    ev = _capture("PH4-02b", since, {"pod": pod, "load": "libc.so", "connect": {"daddr": "127.0.0.1", "dport": port}})
    r = judge_ph4_02("PH4-02b", ev)
    record_result("PH4-02b", r["status"], metrics=r["metrics"], notes="live: " + r["notes"] + exited,
                  artifacts=ev["artifacts"])
    assert r["status"] != "fail", r["notes"]
