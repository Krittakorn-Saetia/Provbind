"""PH4-03, 05 to 18: deterministic verification, judged per scenario (Test Plan §3.5 and §7).

Evidence, first found wins:
1. **Demo PC.** PROVBIND_RECORDING is Tetragon's JSON export, or an events.jsonl, recorded while
   Role 1's scenario scripts ran. It is replayed with:
   - the run folder's bindings.json and envelopes/ ($PROVBIND_RUN);
   - ground_truth.csv (PROVBIND_GROUND_TRUTH, default $PROVBIND_RUN/ground_truth.csv), whose
     rows give each scenario's pod prefix and time window;
   - the egress allow list for D_net (PROVBIND_EGRESS, optional).
   A test whose scenario has no row records not_run.
2. **Otherwise** node/synth.py's library stands in: every §7 scenario once, synthetic. The checks
   run and must hold, but the result is not_run.

Each test records one result. P0 here: PH4-05, PH4-06, PH4-12, PH4-14. PH4-17 is in
test_ph4_17_records.py, and PH4-04 needs a live scale test (integration).
"""
from __future__ import annotations

import functools
import os
from collections import Counter
from pathlib import Path

import pytest

from node.scenarios import recorded_evidence, synthetic_evidence
from node.verify import Verifier, is_weak

RUN = Path(os.environ.get("PROVBIND_RUN", "./run"))


@functools.lru_cache(maxsize=1)
def evidence():
    rec = os.environ.get("PROVBIND_RECORDING")
    if rec:
        return recorded_evidence(rec, RUN, os.environ.get("PROVBIND_GROUND_TRUTH"), os.environ.get("PROVBIND_EGRESS"))
    return synthetic_evidence()


def triple(d):
    return d["class"], d["subclass"], d["clause"]["path"]


def judge(record_result, test_id, scenario, check, *, blocked=None):
    """Run `check(rows)` on the scenario's rows; record pass/fail on real evidence, not_run otherwise.

    check(evidence, rows) -> (ok, metrics, notes). `blocked(evidence)` may return a reason that
    makes the result blocked instead (a missing input, not a failure of the capability).
    """
    ev = evidence()
    rows = ev.scenario(scenario) if scenario else ev.rows
    if not rows:
        record_result(test_id, "not_run", notes=f"{ev.source}: no {scenario} row in the ground truth",
                      artifacts=ev.artifacts)
        return
    ok, metrics, notes = check(ev, rows)
    reason = blocked(ev) if blocked and ev.real else None
    if reason:
        status = "blocked"
        notes = f"{reason}; {notes}"
    elif not ev.real:
        status = "not_run" if ok else "fail"
        notes += "; synthetic library, so not a project result: set PROVBIND_RECORDING on the demo PC"
    else:
        status = "pass" if ok else "fail"
    metrics = {"runs": len(rows), **metrics}
    record_result(test_id, status, metrics=metrics, notes=f"{ev.source}: {notes}", artifacts=ev.artifacts)
    assert status != "fail", notes


def per_row(ev, rows, replay=None):
    replay = replay or ev.main
    return [replay.within(r) for r in rows]


# PH4-05 and PH4-12 (P0): attack-1 ---------------------------------------------------------------

def test_ph4_05_undeclared_exec(record_result):
    """D_exec / undeclared for /tmp/.x9 in every attack-1 run."""
    def check(ev, rows):
        found = [sum(1 for d in dets if triple(d)[:2] == ("D_exec", "undeclared") and
                     (d["clause"]["path"] or "").endswith("/.x9")) for _, dets in per_row(ev, rows)]
        return all(found), {"undeclared_x9_per_run": found}, f"D_exec / undeclared for /tmp/.x9 in runs: {found}"
    judge(record_result, "PH4-05", "attack-1", check)


def test_ph4_12_write_to_declared_file(record_result):
    """D_write on /etc/passwd in every attack-1 run."""
    def check(ev, rows):
        found = [sum(1 for d in dets if triple(d) == ("D_write", "declared_file", "/etc/passwd"))
                 for _, dets in per_row(ev, rows)]
        return all(found), {"d_write_passwd_per_run": found}, f"D_write on /etc/passwd in runs: {found}"
    judge(record_result, "PH4-12", "attack-1", check)


# PH4-06 (P0): Eq. (55) as written against the split class ----------------------------------------

def test_ph4_06_strict_against_split_closure_rule(record_result):
    """Benign scenarios under both rules. Eq. (55) as written makes every exec or load outside the
    closure a contradiction; the split class keeps a declared file outside it weak (capped at Low).
    A false positive is a benign scenario with a detection above Low."""
    def check(ev, rows):
        rules = {"strict_eq55": Counter(), "split": Counter()}
        per_scenario = {"strict_eq55": 0, "split": 0}
        verified = 0
        for r in rows:
            events, dets = ev.main.within(r)
            verified += sum(1 for e in events if e.kind in ("exec", "load"))
            strong = {"strict_eq55": [d for d in dets if d["class"] != "binding"],
                      "split": [d for d in dets if not is_weak(d) and d["class"] != "binding"]}
            for rule, found in strong.items():
                rules[rule]["detections"] += len(dets)
                rules[rule]["above_low"] += len(found)
                per_scenario[rule] += bool(found)
        metrics = {rule: {"detections": c["detections"], "above_low": c["above_low"],
                          "fp_rate_scenarios": round(per_scenario[rule] / len(rows), 4),
                          "fp_rate_exec_load_events": round(c["above_low"] / verified, 4) if verified else None}
                   for rule, c in rules.items()}
        metrics["exec_and_load_events"] = verified
        notes = (f"{len(rows)} benign runs, {verified} exec/load events: strict Eq. 55 puts "
                 f"{rules['strict_eq55']['above_low']} detections above Low, the split class "
                 f"{rules['split']['above_low']}")
        return verified > 0, metrics, notes
    ev = evidence()
    benign = [r for r in ev.rows if r.label == "benign"]
    if not benign:
        record_result("PH4-06", "not_run", notes=f"{ev.source}: no benign row in the ground truth",
                      artifacts=ev.artifacts)
        return
    ok, metrics, notes = check(ev, benign)
    status = ("pass" if ok else "fail") if ev.real else ("not_run" if ok else "fail")
    if not ev.real:
        notes += "; synthetic library, so not a project result: set PROVBIND_RECORDING on the demo PC"
    elif not ok:
        notes += "; no exec or load event in any benign run, so nothing was measured"
    record_result("PH4-06", status, metrics={"runs": len(benign), **metrics}, notes=f"{ev.source}: {notes}",
                  artifacts=ev.artifacts)
    assert status != "fail", notes


# PH4-13 and PH4-14: writes -------------------------------------------------------------------------

def test_ph4_13_writes_under_mounts(record_result):
    """benign-4: nothing under the mount rule; the count under the draft's rule (no exclusion)."""
    def check(ev, rows):
        with_rule, without_rule, under_mounts = 0, 0, 0
        v = Verifier()
        for r in rows:
            events, dets = ev.main.within(r)
            with_rule += sum(1 for d in dets if d["class"] == "D_write")
            for e in events:
                if e.kind != "write":
                    continue
                b = ev.main.store.binding(e.container_id)
                env = ev.main.store.envelope(b.image_digest) if b else None
                if env is None:
                    continue
                mounts = ev.main.store.mounts(b, env)
                if v.verify(e, env, b, mounts) is None and v.verify(e, env, b, ()) is not None:
                    under_mounts += 1
                without_rule += v.verify(e, env, b, ()) is not None
        ok = with_rule == 0 and under_mounts > 0
        notes = f"D_write with the mount rule: {with_rule}; under the draft's rule (Eq. 56, no exclusion): {without_rule}"
        if not under_mounts:
            notes += "; no write to a declared file under a mount happened, so the rule was not exercised"
        return ok, {"d_write_mount_rule": with_rule, "d_write_draft_rule": without_rule,
                    "declared_writes_under_mounts": under_mounts}, notes
    judge(record_result, "PH4-13", "benign-4", check)


def test_ph4_14_new_files_conform(record_result):
    """A write to /tmp/new.txt gives no detection (ground-truth row ph4-14; on the demo PC, any
    run that wrote /tmp/new.txt in a demo pod)."""
    ev = evidence()
    writes = [e for e in ev.main.events if e.kind == "write" and e.path == "/tmp/new.txt"]
    dets = [d for d in ev.main.detections if d["clause"]["path"] == "/tmp/new.txt"]
    ok = bool(writes) and not dets
    notes = f"{ev.source}: {len(writes)} writes to /tmp/new.txt, {len(dets)} detections for it"
    if not writes:
        status = "not_run"
        notes += "; the recording has no write to /tmp/new.txt: run `kubectl exec … -- sh -c 'echo x > /tmp/new.txt'`"
    elif not ev.real:
        status = "not_run" if ok else "fail"
        notes += "; synthetic library, so not a project result: set PROVBIND_RECORDING on the demo PC"
    else:
        status = "pass" if ok else "fail"
    record_result("PH4-14", status, metrics={"writes": len(writes), "detections": len(dets)}, notes=notes,
                  artifacts=ev.artifacts)
    assert status != "fail", notes


# PH4-03: binding failures ---------------------------------------------------------------------

def test_ph4_03_unknown_containers_are_binding_failures(record_result):
    """attack-9: a binding failure for the unbound container, and no envelope check of its events."""
    def check(ev, rows):
        failures, checked = 0, 0
        for r in rows:
            events, dets = ev.main.within(r)
            unbound = {e.container_id for e in events if ev.main.store.binding(e.container_id) is None
                       or not ev.main.store.binding(e.container_id).verified}
            failures += sum(1 for d in dets if d["class"] == "binding" and d["container_id"] in unbound)
            checked += sum(1 for d in dets if d["class"] != "binding" and d["container_id"] in unbound)
        ok = failures > 0 and checked == 0
        return ok, {"binding_failures": failures, "checked_against_an_envelope": checked}, \
            f"binding failures {failures}; detections from an envelope check of those containers {checked}"
    judge(record_result, "PH4-03", "attack-9", check)


# PH4-07, 08, 09 and 18: runtime hashes (C3) --------------------------------------------------------

PATH_ONLY_REASON = ("no runtime hash in the stream (path-only mode): D_hash cannot fire until the node "
                    "has a hash source (C3; ROLE3_STATUS.md R3-T9)")


def _no_hashes(ev):
    return PATH_ONLY_REASON if not any(e.hash for e in ev.main.events if e.kind == "exec") else None


def test_ph4_07_relocated_binary(record_result):
    def check(ev, rows):
        found = [sum(1 for d in dets if triple(d)[:2] == ("D_hash", "relocated")) for _, dets in per_row(ev, rows)]
        return all(found), {"relocated_per_run": found}, f"D_hash / relocated in runs: {found}"
    judge(record_result, "PH4-07", "attack-3", check, blocked=_no_hashes)


def test_ph4_08_modified_in_place(record_result):
    """attack-4: D_write on the binary, then D_hash / modified when it runs."""
    def check(ev, rows):
        ordered = []
        for _, dets in per_row(ev, rows):
            kinds = [triple(d)[:2] for d in dets]
            w = kinds.index(("D_write", "declared_file")) if ("D_write", "declared_file") in kinds else None
            m = kinds.index(("D_hash", "modified")) if ("D_hash", "modified") in kinds else None
            ordered.append(w is not None and m is not None and w < m)
        return all(ordered), {"write_then_modified_per_run": ordered}, f"D_write then D_hash / modified: {ordered}"
    judge(record_result, "PH4-08", "attack-4", check, blocked=_no_hashes)


def test_ph4_09_missing_hash_is_handled(record_result):
    """attack-3 replayed with hashing off: no crash, and a path-only result that says so."""
    def check(ev, rows):
        marked = []
        for _, dets in per_row(ev, rows, ev.path_only):
            marked.append(sum(1 for d in dets if triple(d)[:2] == ("D_exec", "undeclared")
                              and "path-only" in d["clause"]["detail"]))
        return all(marked), {"path_only_undeclared_per_run": marked}, \
            f"path-only D_exec / undeclared, marked as such, in runs: {marked}"
    judge(record_result, "PH4-09", "attack-3", check)


def test_ph4_18_one_class_per_event(record_result):
    """M12: an exec at a new path with declared content gives exactly one detection, D_hash / relocated."""
    def check(ev, rows):
        per_exec = []
        for r in rows:
            events, dets = ev.main.within(r)
            for e in events:
                if e.kind == "exec" and e.hash and ev.main.store.binding(e.container_id):
                    b = ev.main.store.binding(e.container_id)
                    env = ev.main.store.envelope(b.image_digest)
                    if env is not None and env.lookup(e.exe)[1] is None and e.hash in env.j.hash:
                        mine = [d for d in dets if d["pid"] == e.pid and d["time"] == e.time]
                        per_exec.append([triple(d)[:2] for d in mine])
        ok = bool(per_exec) and all(x == [("D_hash", "relocated")] for x in per_exec)
        return ok, {"relocated_execs": len(per_exec), "outcomes": per_exec}, \
            f"{len(per_exec)} execs at a new path with declared content; their detections: {per_exec}"
    judge(record_result, "PH4-18", "attack-3", check, blocked=_no_hashes)


# PH4-10 and 11: libraries ---------------------------------------------------------------------------

def test_ph4_10_library_in_no_layer(record_result):
    def check(ev, rows):
        found = [sum(1 for d in dets if triple(d)[:2] == ("D_load", "undeclared")) for _, dets in per_row(ev, rows)]
        return all(found), {"d_load_undeclared_per_run": found}, f"D_load / undeclared in runs: {found}"
    judge(record_result, "PH4-10", "attack-5", check)


def test_ph4_11_declared_library_outside_the_closure_is_weak(record_result):
    """benign-3 (DNS loads glibc's NSS modules): weak D_load only, never undeclared."""
    def check(ev, rows):
        loads, weak, strong = 0, 0, 0
        for events, dets in per_row(ev, rows):
            loads += sum(1 for e in events if e.kind == "load")
            weak += sum(1 for d in dets if triple(d)[:2] == ("D_load", "outside_closure"))
            strong += sum(1 for d in dets if d["class"] in ("D_load", "D_hash") and not is_weak(d))
        ok = loads > 0 and strong == 0
        notes = f"{loads} library loads: {weak} weak D_load, {strong} strong"
        if not loads:
            notes += "; no load event: is node/tetragon/load.yaml applied?"
        return ok, {"loads": loads, "weak": weak, "strong": strong}, notes
    judge(record_result, "PH4-11", "benign-3", check)


# PH4-15 and 16: capabilities and egress --------------------------------------------------------------

def test_ph4_15_capability_outside_the_envelope(record_result):
    def check(ev, rows):
        found = [[d["origin"] for d in dets if d["class"] == "D_cap"] for _, dets in per_row(ev, rows)]
        ok = all(o and all(x == "INFERRED" for x in o) for o in found)
        return ok, {"d_cap_origins_per_run": found}, f"D_cap origins per run: {found}"
    judge(record_result, "PH4-15", "attack-6", check)


def test_ph4_16_connection_outside_the_egress_list(record_result):
    def check(ev, rows):
        found = [sum(1 for d in dets if triple(d)[:2] == ("D_net", "not_allowed")) for _, dets in per_row(ev, rows)]
        return all(found), {"d_net_per_run": found}, f"D_net in runs: {found}"

    def no_egress(ev):
        return None if ev.egress else "no egress allow list (PROVBIND_EGRESS): the envelope has no egress set (M8)"
    judge(record_result, "PH4-16", "attack-7", check, blocked=no_egress)
