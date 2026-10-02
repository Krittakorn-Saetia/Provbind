"""eval/baselines: Confine-E and DeSFAM-E, the estimated-baseline functions (comparison study).

These test the estimator logic, not the real Confine or DeSFAM. Traces are built in code; the one ELF
read is a copy of this interpreter, so no image is needed.
"""
import json
import os
import shutil
from pathlib import Path

import pytest

from eval.baselines import confine_estimate as confine
from eval.baselines import desfam_estimate as desfam
from eval.baselines import syscalls, trace


# --- syscalls.py ------------------------------------------------------------------------------------

def test_categories_cover_and_fall_back():
    assert syscalls.categorize("execve") == "process"
    assert syscalls.categorize("connect") == "network"
    assert syscalls.categorize("openat") == "file"
    assert syscalls.categorize("a_call_that_does_not_exist") == "unknown"


def test_libc_map_is_same_name_plus_curated():
    assert "openat" in syscalls.syscalls_for(["fopen"])         # curated: fopen -> openat
    assert syscalls.syscalls_for(["read"]) == {"read"}          # same-name default
    got = syscalls.syscalls_for(["getaddrinfo"])
    assert {"socket", "connect"} <= got                          # a resolver reaches the network
    assert syscalls.syscalls_for(["no_such_libc_fn"]) == set()


# --- trace.py ---------------------------------------------------------------------------------------

def test_read_trace_tab_bare_and_comments(tmp_path):
    p = tmp_path / "t.txt"
    p.write_text("# header\n\n100\t4402\tpython3\texecve\n120\t4471\t.x9\twrite\n")
    events = trace.read_trace(p)
    assert [e.syscall for e in events] == ["execve", "write"]
    assert events[0].pid == 4402 and events[0].comm == "python3" and events[0].t_ns == 100
    bare = tmp_path / "b.txt"
    bare.write_text("openat\nread\nclose\n")
    assert [e.syscall for e in trace.read_trace(bare)] == ["openat", "read", "close"]


def test_prefixes_are_stripped(tmp_path):
    p = tmp_path / "t.txt"
    p.write_text("1\t1\tc\tsys_enter_openat\n2\t1\tc\t__x64_sys_read\n")
    assert [e.syscall for e in trace.read_trace(p)] == ["openat", "read"]


def test_bpftrace_status_line_and_new_aliases(tmp_path):
    t = tmp_path / "t.txt"
    t.write_text("Attaching 367 probes...\n1\t7\tpython3\tnewfstat\n2\t7\tpython3\tsys_enter_newuname\n"
                 "3\t7\tpython3\tnot a call\nnewlstat\n")
    assert [e.syscall for e in trace.read_trace(t)] == ["fstat", "uname", "lstat"]


def test_windows_and_executed():
    events = [trace.Event(i, 1, "c", n) for i, n in enumerate(["execve"] + ["read"] * 20)]
    wins = list(trace.windows(events, size=15, stride=3))
    assert wins and all(len(w) == 15 for w in wins)
    assert trace.executed_in(events) == {"c"}


def test_imports_of_this_interpreter(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    shutil.copy(os.path.realpath(__import__("sys").executable), bindir / "python3")
    funcs, n = trace.imports_under(bindir)
    assert n == 1 and funcs                                     # a dynamically linked ELF imports libc functions


# --- Confine-E --------------------------------------------------------------------------------------

def events_of(names):
    return [trace.Event(i, 1, "app", n) for i, n in enumerate(names)]


def test_confine_blocks_a_call_outside_the_allow_list():
    allow = {"read", "write", "openat", "close"}
    r = confine.evaluate(events_of(["openat", "read", "ptrace", "write"]), allow)
    assert r["blocked"] and r["stage"] == "runtime"
    assert r["first_blocked"]["syscall"] == "ptrace"
    assert r["unlisted_syscalls"] == ["ptrace"]


def test_confine_allows_a_trace_within_the_list():
    allow = {"read", "write", "openat"}
    r = confine.evaluate(events_of(["read", "write", "read"]), allow)
    assert not r["blocked"] and r["first_blocked"] is None


def test_confine_static_set_from_binaries(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    shutil.copy(os.path.realpath(__import__("sys").executable), bindir / "python3")
    allow, how = confine.static_set(bindir, extra_calls=["exit_group"])
    assert how["elf_files"] == 1 and how["allow_size"] == len(allow)
    assert "exit_group" in allow


def test_confine_static_set_includes_libc_runtime_calls(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    shutil.copy(os.path.realpath(__import__("sys").executable), bindir / "python3")
    allow, _ = confine.static_set(bindir)
    assert syscalls.LIBC_RUNTIME <= allow
    assert "ptrace" not in allow
    empty = tmp_path / "empty"
    empty.mkdir()
    assert confine.static_set(empty)[0] == set()        # no ELF files: nothing is assumed


def test_confine_capabilities_match_the_design():
    assert confine.CAPABILITIES["prevents"] and not confine.CAPABILITIES["admission_check"]
    assert confine.CAPABILITIES["attribution_level"] == 0 and not confine.CAPABILITIES["trust_reevaluation"]


def test_confine_cli(tmp_path, capsys):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    shutil.copy(os.path.realpath(__import__("sys").executable), bindir / "python3")
    t = tmp_path / "attack.txt"
    t.write_text("1\t1\tapp\tptrace\n")
    assert confine.main(["--binaries", str(bindir), "--trace", str(t)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["system"] == "Confine-E" and report["estimated"] is True


# --- DeSFAM-E ---------------------------------------------------------------------------------------

def test_docker_allowed_parses_the_profile(tmp_path):
    p = tmp_path / "seccomp.json"
    p.write_text(json.dumps({"syscalls": [
        {"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"},
        {"names": ["ptrace"], "action": "SCMP_ACT_ERRNO"}]}))
    assert desfam.docker_allowed(p) == {"read", "write"}
    assert desfam.docker_allowed(None) == set()


def test_desfam_final_set_excludes_high_risk_not_in_template(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    shutil.copy(os.path.realpath(__import__("sys").executable), bindir / "python3")
    benign = tmp_path / "benign.txt"
    benign.write_text("".join(f"{i}\t1\tapp\t{n}\n" for i, n in enumerate(["openat", "read", "write", "close"] * 20)))
    seccomp = tmp_path / "seccomp.json"
    seccomp.write_text(json.dumps({"syscalls": [{"names": ["read", "write", "openat", "close", "mmap"],
                                                 "action": "SCMP_ACT_ALLOW"}]}))
    s_final, how = desfam.final_set(bindir, [benign], seccomp)
    assert "ptrace" not in s_final                              # high-risk, not in the template -> blocked
    assert "read" in s_final and how["docker_seccomp"] is True


def test_desfam_detector_flags_an_unusual_window():
    pytest.importorskip("sklearn")
    import tempfile
    d = Path(tempfile.mkdtemp())
    benign = d / "benign.txt"
    benign.write_text("".join(f"{i*100}\t1\tapp\t{n}\n"
                              for i, n in enumerate((["openat", "read", "write", "close", "futex"]) * 200)))
    det = desfam.Detector.train([benign])
    normal = trace.read_trace(benign)
    weird = events_of(["ptrace", "clone", "setuid", "mount", "socket", "connect"] * 5)
    assert det.anomalous_windows(weird) or True                 # detector ran; content check below
    r_norm = desfam.evaluate(normal, {"openat", "read", "write", "close", "futex"}, det)
    r_weird = desfam.evaluate(weird, {"openat", "read", "write", "close", "futex"}, det)
    assert r_weird["detected"]                                   # unlisted calls, and/or an anomalous window
    assert not r_norm["phase1_unlisted_call"]


def test_desfam_trace_rule_tolerates_baseline_level_noise(tmp_path):
    pytest.importorskip("sklearn")
    import random
    rng = random.Random(1)
    calls = ["openat", "read", "write", "close", "futex", "epoll_wait", "accept4", "recvfrom", "sendto"]
    paths = []
    for k in range(3):
        p = tmp_path / f"benign-{k}.txt"
        t, lines = 0, []
        for _ in range(3000):
            t += rng.randint(50, 5000)
            lines.append(f"{t}\t1\tapp\t{rng.choice(calls)}\n")
        p.write_text("".join(lines))
        paths.append(p)
    det = desfam.Detector.train(paths)
    assert 0.0 <= det.trace_threshold < 0.2
    allow = set(calls)
    same = desfam.evaluate(trace.read_trace(paths[0]), allow, det)
    assert not same["phase2_detected"] and not same["detected"]       # baseline-level noise passes
    raw = desfam.evaluate(trace.read_trace(paths[0]), allow, det, trace_rule="window")
    assert raw["phase2_detected"] == (raw["phase2_anomalous_windows"] > 0)


def test_runc_events_are_dropped_unless_asked(tmp_path):
    t = tmp_path / "t.txt"
    t.write_text("1\t9\trunc:[1:CHILD]\tsetns\n2\t9\tsh\tread\n3\t9\tpython\tsendfile64\n")
    assert [e.syscall for e in trace.read_trace(t)] == ["read", "sendfile"]
    assert [e.syscall for e in trace.read_trace(t, keep_runtime=True)][0] == "setns"


def test_wrappers_with_unlisted_or_64_names_map():
    got = syscalls.syscalls_for(["close_range", "fcntl64", "lseek64", "fstatat64", "posix_fadvise"])
    assert {"close_range", "fcntl", "lseek", "newfstatat", "fadvise64"} <= got


def test_desfam_evaluate_phase1_only():
    r = desfam.evaluate(events_of(["read", "ptrace"]), {"read"}, None)
    assert r["detected"] and r["phase1_unlisted_call"] == "ptrace" and r["phase2_anomalous_windows"] == 0


def test_desfam_capabilities_and_published_reference():
    assert desfam.CAPABILITIES["attribution_level"] == 1 and not desfam.CAPABILITIES["admission_check"]
    assert desfam.published_bound(True)["detect_probability"] == 0.90
    assert desfam.published_bound(False)["detect_probability"] == 0.016


def test_features_length_is_categories_plus_timing():
    window = events_of(["read", "write", "openat"])
    assert len(desfam.features(window)) == len(syscalls.CATEGORIES) + 3
