"""node/pipeline.py: binding, holding, releasing and verifying one stream (C4, Eq. 51)."""
import json

import pytest

from node.normalize import Event, format_time, parse_time
from node.pipeline import NS, Pipeline
from node.store import Store
from node.synth import DEMO_CID, DEMO_POD, DIGEST, SAMPLE, UNSIGNED_CID, demo_bindings
from node.verify import Verifier

T0 = parse_time("2026-09-28T10:00:00Z")
PY = "/usr/local/bin/python3.11"
ROGUE = "containerd://" + "9d2e" * 16


def sample():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def ev(sec, kind="exec", cid=DEMO_CID, exe=PY, **kw):
    t = T0 + int(sec * NS)
    return Event(time=format_time(t), t=t, kind=kind, container_id=cid, namespace="demo", pod=DEMO_POD,
                 container="app", pid=kw.pop("pid", 4402), ppid=4400, exe=exe, parent_exe=None, **kw)


class Sink(list):
    def __call__(self, item):
        self.append(item)


def pipeline(store, **kw):
    events, dets = Sink(), Sink()
    p = Pipeline(store, Verifier(), on_event=events, on_detection=dets, **kw)
    return p, events, dets


def kinds(dets):
    return [(d["class"], d["subclass"], d["clause"]["path"]) for d in dets]


def bound():
    return {DEMO_CID: demo_bindings()[DEMO_CID]}


def test_bound_events_are_verified_at_once():
    p, events, dets = pipeline(Store.static([sample()], bound()))
    p.feed(ev(0, exe=PY))
    p.feed(ev(1, exe="/tmp/.x9"))
    p.feed(ev(2, kind="write", path="/etc/passwd"))
    assert kinds(dets) == [("D_exec", "undeclared", "/tmp/.x9"), ("D_write", "declared_file", "/etc/passwd")]
    assert len(events) == 3 and p.stats["verified"] == 3 and not p.held


def test_events_wait_for_a_binding_that_arrives_within_the_grace_period():
    store = Store.static([sample()], {})
    p, _, dets = pipeline(store, grace=30)
    p.feed(ev(0, exe="/tmp/.x9"))
    p.feed(ev(1, exe="/usr/bin/ls"))
    assert dets == [] and len(p.held[DEMO_CID].events) == 2
    store.set_bindings(bound())
    p.feed(ev(5, kind="write", path="/etc/passwd"))                # released first, in order
    assert kinds(dets) == [("D_exec", "undeclared", "/tmp/.x9"), ("D_exec", "outside_closure", "/usr/bin/ls"),
                           ("D_write", "declared_file", "/etc/passwd")]
    assert p.cold[DEMO_CID]["held"] == 2 and p.cold[DEMO_CID]["window_s"] == 5.0


def test_no_binding_after_the_grace_period_is_one_unknown_container():
    p, _, dets = pipeline(Store.static([sample()], bound()), grace=30)
    for sec in (0, 1, 2):
        p.feed(ev(sec, cid=ROGUE, exe="/usr/bin/sleep"))
    p.feed(ev(29.9))
    assert dets == []
    p.feed(ev(30.5))
    p.tick()
    assert [(d["class"], d["subclass"]) for d in dets] == [("binding", "unknown_container")]
    assert dets[0]["time"] == ev(0).time and "30.5 s" in dets[0]["clause"]["detail"]
    assert p.stats["unbound_events"] == 2
    for sec in (31, 70, 75):                                        # more of the same container later
        p.feed(ev(sec, cid=ROGUE, exe="/usr/bin/sleep"))
    p.tick()
    assert len(dets) == 1 and p.stats["unknown_container_events"] == 1


def test_end_of_stream_fails_unbound_containers_at_once():
    p, _, dets = pipeline(Store.static([sample()], {}), grace=30)
    p.feed(ev(0, cid=ROGUE))
    p.close()
    assert kinds(dets) == [("binding", "unknown_container", PY)] and "end of stream" in dets[0]["clause"]["detail"]


def test_unverified_container_is_reported_once():
    p, _, dets = pipeline(Store.static([sample()], demo_bindings()))
    for sec in (0, 1, 2):
        p.feed(ev(sec, cid=UNSIGNED_CID, exe="/usr/bin/sleep"))
    assert [(d["class"], d["subclass"], d["image_digest"]) for d in dets] == \
           [("binding", "unverified", demo_bindings()[UNSIGNED_CID]["image_digest"])]
    assert p.stats["unverified_events"] == 2


def test_unverified_after_holding_is_reported_once():
    store = Store.static([sample()], {})
    p, _, dets = pipeline(store)
    p.feed(ev(0, cid=UNSIGNED_CID))
    p.feed(ev(1, cid=UNSIGNED_CID))
    store.set_bindings(demo_bindings())
    p.tick()
    assert [(d["class"], d["subclass"]) for d in dets] == [("binding", "unverified")]


def test_events_after_unbinding_are_counted_not_reported():
    store = Store.static([sample()], bound())
    p, _, dets = pipeline(store)
    p.feed(ev(0))
    store.set_bindings({})
    p.feed(ev(1, kind="exit"))
    p.feed(ev(2, exe="/tmp/.x9"))
    p.close()
    assert dets == [] and p.stats["after_unbind"] == 2


def test_cold_start_holds_events_until_the_envelope_is_ready():
    store = Store.static([], bound())
    p, _, dets = pipeline(store)
    p.feed(ev(0, exe=PY))
    p.feed(ev(2, exe="/tmp/.x9"))
    assert dets == [] and p.stats["held"] == 2
    store.provide(sample())
    p.tick(T0 + 7 * NS)
    assert kinds(dets) == [("D_exec", "undeclared", "/tmp/.x9")]
    assert p.cold[DEMO_CID] == {"first_event": T0, "ready": T0 + 7 * NS, "held": 2, "window_s": 7.0}
    assert p.stats["released"] == 2 and p.stats["lost"] == 0


def test_missing_envelope_is_reported_once_and_its_events_stay_held():
    store = Store.static([], bound())
    p, _, dets = pipeline(store, envelope_timeout=300)
    p.feed(ev(0, exe="/tmp/.x9"))
    p.tick(T0 + 299 * NS)
    assert dets == []
    p.tick(T0 + 301 * NS)
    p.tick(T0 + 400 * NS)
    assert [(d["class"], d["subclass"]) for d in dets] == [("binding", "no_envelope")]
    store.provide(sample())
    p.tick(T0 + 401 * NS)
    assert [(d["class"], d["subclass"]) for d in dets][1:] == [("D_exec", "undeclared")]


def test_holding_is_capped_and_the_oldest_are_counted_lost():
    p, _, _ = pipeline(Store.static([], bound()), max_held=3)
    for sec in range(5):
        p.feed(ev(sec))
    assert len(p.held[DEMO_CID].events) == 3 and p.stats["lost"] == 2
    assert p.held[DEMO_CID].events[0].t == ev(2).t
    p.close()
    assert p.stats["unverified_at_close"] == 3


def test_hasher_fills_exec_hashes_before_anyone_sees_the_event():
    doc = sample()
    ls_hash = doc["files"]["/usr/bin/ls"]["sha256"]
    p, events, dets = pipeline(Store.static([doc], bound()),
                               hasher=lambda e: ls_hash if e.exe == "/tmp/.l" else None)
    p.feed(ev(0, exe="/tmp/.l"))
    p.feed(ev(1, exe="/tmp/.x9"))
    p.feed(ev(2, kind="write", path="/tmp/a"))
    assert events[0].hash == ls_hash and events[1].hash is None and events[2].hash is None
    assert kinds(dets) == [("D_hash", "relocated", "/tmp/.l"), ("D_exec", "undeclared", "/tmp/.x9")]
    assert (p.stats["hashed"], p.stats["not_hashed"]) == (1, 1)


def test_timing_records_one_latency_per_verified_event():
    p, _, _ = pipeline(Store.static([sample()], bound()), timing=True)
    for sec in range(4):
        p.feed(ev(sec))
    assert len(p.latencies) == 4 and all(x >= 0 for x in p.latencies)


def test_every_event_is_passed_on_even_if_unbound():
    p, events, _ = pipeline(Store.static([sample()], {}))
    p.feed(ev(0, cid=ROGUE))
    assert len(events) == 1


def test_containers_fail_separately():
    other = "containerd://" + "5c3a" * 16
    p, _, dets = pipeline(Store.static([sample()], {}), grace=1)
    p.feed(ev(0, cid=ROGUE))
    p.feed(ev(0.5, cid=other))
    p.close()
    assert sorted(d["container_id"] for d in dets) == sorted([ROGUE, other])


def test_behaviour_stage_sees_every_verified_event_with_its_verdict():
    seen = []

    class Stage:
        def observe(self, e, det, env, b):
            seen.append((e.exe, None if det is None else det["class"]))
            return []

        def tick(self, now):
            return [{"class": "D_beh", "tick": now}]

        def close(self, now):
            return []

    p, _, dets = pipeline(Store.static([sample()], bound()), behaviour=Stage())
    p.feed(ev(0))
    p.feed(ev(1, exe="/tmp/.x9"))
    p.tick(T0 + 5 * NS)
    assert seen == [(PY, None), ("/tmp/.x9", "D_exec")]
    assert dets[-1] == {"class": "D_beh", "tick": T0 + 5 * NS}
