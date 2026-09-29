"""Phase 4 on one event stream: bind each event, hold it until its envelope is ready, verify it,
and pass the results on (Sprint Handoff §7, Day 3; fail point C4).

    event -> binding? --none-------> hold for up to `grace` seconds, then binding / unknown_container
               |      --unverified-> binding / unverified
               v
             envelope ready? --no---> hold until it is: the cold-start window (PH2-10)
               v
             verify --------------> a detection, or conforming (and on to ML-B)

- **Why wait for a binding.** A container starts before the controller has verified its image
  and written its binding, so its first events arrive before its binding does. Reporting them
  at once would turn every pod start into a binding failure. They are held for `grace` seconds
  (event time) first.
- **Once per container.** A binding failure is a fact about the container, not about each
  event, so it is reported once per container and kind. The rest are counted.
- **Order.** A container's events stay in order: while any of its events are held, new ones
  queue behind them.
- **After unbinding.** Events from a container that was bound earlier and has since left
  bindings.json (pod deleted, exit events) are counted, never reported as unknown.
- **Runtime hashes.** A `hasher`, if given, fills in an exec event's hash before anything else
  sees it (fail point C3). Without one, or when it returns None, the event stays path-only.
- **No envelope.** A bound, verified container whose envelope is still missing after
  `envelope_timeout` seconds gets one binding / no_envelope detection. Its events stay held, and
  are verified if the envelope arrives. `max_held` caps what one container can hold; beyond it
  the oldest events are dropped and counted as lost.
"""
from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Callable

from .normalize import Event
from .store import Binding, Envelope, Store, bare_id
from .verify import Verifier, binding_failure

NS = 1_000_000_000


@dataclass
class Held:
    first_t: int                                    # event time of the container's first held event
    events: deque = field(default_factory=deque)


class Pipeline:
    def __init__(self, store: Store, verifier: Verifier, *, grace: float = 30.0, envelope_timeout: float = 300.0,
                 max_held: int = 100_000, on_event: Callable[[Event], None] | None = None,
                 on_detection: Callable[[dict], None] | None = None, behaviour=None, timing: bool = False,
                 hasher: Callable[[Event], str | None] | None = None):
        self.store, self.verifier, self.hasher = store, verifier, hasher
        self.grace, self.envelope_timeout, self.max_held = int(grace * NS), int(envelope_timeout * NS), max_held
        self.on_event, self.on_detection, self.behaviour = on_event, on_detection, behaviour
        self.held: dict[str, Held] = {}
        self.reported: set[tuple] = set()           # (bare container ID, subclass) already reported
        self.cold: dict[str, dict] = {}             # container -> its cold-start window (PH2-10)
        self.clock = 0                              # the latest event time seen
        self.stats: Counter = Counter()
        self.latencies: list[int] | None = [] if timing else None

    # input ------------------------------------------------------------------------------------
    def feed(self, ev: Event) -> None:
        self.clock = max(self.clock, ev.t)
        self.stats["events"] += 1
        self.stats["kind:" + ev.kind] += 1
        if self.hasher is not None and ev.kind == "exec" and ev.hash is None:
            ev.hash = self.hasher(ev)                 # runtime hash (C3); None keeps path-only
            self.stats["hashed" if ev.hash else "not_hashed"] += 1
        if self.on_event is not None:
            self.on_event(ev)
        held = self.held.get(ev.container_id)
        if held is not None and not self._release(ev.container_id, self.clock):
            self._hold(held, ev)
            return
        self._route(ev)

    def tick(self, now: int | None = None) -> None:
        """Retry every held container: verify what became ready, fail what waited too long."""
        now = self.clock if now is None else now
        for cid in list(self.held):
            self._release(cid, now)
        if self.behaviour is not None:
            for det in self.behaviour.tick(now):
                self._emit(det)

    def close(self) -> None:
        """End of stream: the grace period can no longer be met, so unbound containers fail now.
        Events of bound containers whose envelope never arrived are counted, not verified."""
        for cid in list(self.held):
            if not self._release(cid, self.clock, closing=True):
                held = self.held.pop(cid)
                self.stats["unverified_at_close"] += len(held.events)
        if self.behaviour is not None:
            for det in self.behaviour.close(self.clock):
                self._emit(det)

    # routing ----------------------------------------------------------------------------------
    def _route(self, ev: Event) -> None:
        b = self.store.binding(ev.container_id)
        if b is None:
            if self.store.was_bound(ev.container_id):
                self.stats["after_unbind"] += 1
                return
            self._hold(self.held.setdefault(ev.container_id, Held(ev.t)), ev)
            return
        if not b.verified:
            self._fail(ev, b, "unverified", "bindings.json says this image's evidence did not verify")
            return
        env = self.store.envelope(b.image_digest)
        if env is None:
            self._hold(self.held.setdefault(ev.container_id, Held(ev.t)), ev)
            return
        self._verify(ev, env, b)

    def _hold(self, held: Held, ev: Event) -> None:
        if len(held.events) >= self.max_held:
            held.events.popleft()
            self.stats["lost"] += 1
        held.events.append(ev)
        self.stats["held"] += 1

    def _release(self, cid: str, now: int, closing: bool = False) -> bool:
        """Settle a held container if its fate is known. True if nothing is held for it any more."""
        held = self.held.get(cid)
        if held is None:
            return True
        b = self.store.binding(cid)
        if b is None:
            if self.store.was_bound(cid):
                self.stats["after_unbind"] += len(self.held.pop(cid).events)
                return True
            if not closing and now - held.first_t < self.grace:
                return False
            del self.held[cid]
            waited = (now - held.first_t) / NS
            self._fail(held.events[0], None, "unknown_container",
                       f"no binding in bindings.json after {waited:.1f} s" + (" (end of stream)" if closing else ""))
            self.stats["unbound_events"] += len(held.events) - 1
            return True
        if not b.verified:
            del self.held[cid]
            self._fail(held.events[0], b, "unverified", "bindings.json says this image's evidence did not verify")
            self.stats["unverified_events"] += len(held.events) - 1
            return True
        env = self.store.envelope(b.image_digest)
        if env is None:
            if now - held.first_t >= self.envelope_timeout and (bare_id(cid), "no_envelope") not in self.reported:
                self._fail(held.events[0], b, "no_envelope",
                           f"verified, but no envelope for {b.image_digest} after {(now - held.first_t) / NS:.0f} s; "
                           "its events are held")
            return False
        del self.held[cid]
        self.cold[cid] = {"first_event": held.first_t, "ready": now, "held": len(held.events),
                          "window_s": round((now - held.first_t) / NS, 3)}
        self.stats["released"] += len(held.events)
        for ev in held.events:
            self._verify(ev, env, b)
        return True

    # outcomes ---------------------------------------------------------------------------------
    def _verify(self, ev: Event, env: Envelope, b: Binding) -> None:
        mounts = self.store.mounts(b, env)
        if self.latencies is not None:
            t0 = time.perf_counter_ns()
            det = self.verifier.verify(ev, env, b, mounts)
            self.latencies.append(time.perf_counter_ns() - t0)
        else:
            det = self.verifier.verify(ev, env, b, mounts)
        self.stats["verified"] += 1
        if isinstance(det, dict):
            self._emit(det)
        if self.behaviour is not None:
            for d in self.behaviour.observe(ev, det, env, b):
                self._emit(d)

    def _fail(self, ev: Event, b: Binding | None, subclass: str, detail: str) -> None:
        key = (bare_id(ev.container_id), subclass)
        if key in self.reported:
            self.stats[subclass + "_events"] += 1
            return
        self.reported.add(key)
        self._emit(binding_failure(ev, b, subclass, detail))

    def _emit(self, det: dict) -> None:
        self.stats["detections"] += 1
        if self.on_detection is not None:
            self.on_detection(det)
