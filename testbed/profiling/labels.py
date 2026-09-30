"""Capability labels from Tetragon `cap_capable` events (MLA-03, Test Plan §4.2).

Role 1 profiles each corpus image (Test Plan §4.1, `ml/corpus.yaml`) under Role 3's
`cap_capable` tracing policy. Tetragon hooks `cap_capable`; its return value is 0 when the
check was granted and -1 when it was denied (Test Plan §4.2, §8). This module turns those
events into the label rows Role 2 joins to its features by digest.

Label rule (§4.2):
- an image's label is the set of capabilities with **at least one granted check** from the
  workload's own processes, during a 120-second run after the workload starts;
- denied checks are recorded separately: they are attempts, useful for analysis, not labels;
- two runs per image; the label is the **union**; report how often the two runs disagree,
  because that is the label noise;
- a label with fewer than 3 positive images is "too rare" and left out of training.

Measured on the demo VM (30 September; docs/ROLE1-RESULTS-2026-09-30.md §3.2), the return value alone
over-counts: cap_capable returned 0 for CAP_SYS_ADMIN in processes that do not hold it, and runc's init
step and kind's container hooks run in the pod with every capability. So, when the event carries the
process's own capability sets (Tetragon's enableProcessCred, process.cap):
- a check counts as granted only if the capability is in the process's own effective set (a missing
  set, once the capture carries sets at all, is empty: Tetragon omits empty lists);
- a process holding capabilities a default pod cannot have (outside RUNTIME_DEFAULT_CAPS) is the
  container runtime, not the workload, and is left out, as is runc's init step itself.
Without process.cap the return value is used as before.

The event parsing is best-effort against Tetragon's JSON and is verified against Role 3's
policy output on the demo PC; the label maths below is pure and unit-tested.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable

from ml.alg1 import ALL_CAPS, RUNTIME_DEFAULT_CAPS, normalise
from node.normalize import is_runtime_init, own_capabilities

# Capability index -> name, from include/uapi/linux/capability.h (ALL_CAPS is in that order).
CAP_BY_INDEX = {i: name for i, name in enumerate(ALL_CAPS)}
MIN_POSITIVE_IMAGES = 3          # §4.2: fewer positives than this is "too rare"


def capability_name(value):
    """Normalise a capability from Tetragon into a CAP_* name.

    Accepts an index (12), a numeric string ("12"), or a name in any case with or without the
    CAP_ prefix ("net_admin", "CAP_NET_ADMIN"). Returns None for anything unrecognised, so a
    stray value never becomes a bogus label.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return CAP_BY_INDEX.get(value)
    if value is None:
        return None
    s = str(value).strip()
    if s.isdigit():
        return CAP_BY_INDEX.get(int(s))
    try:
        return normalise(s)
    except (ValueError, KeyError):
        return None


@dataclass(frozen=True)
class CapCheck:
    """One capability check seen by the kernel."""
    capability: str
    granted: bool
    pid: int | None = None
    binary: str | None = None
    namespace: str | None = None
    pod: str | None = None
    time: str | None = None


def _get(d, *path, default=None):
    for key in path:
        if not isinstance(d, dict):
            return default
        d = d.get(key)
    return d if d is not None else default


def parse_tetragon_cap_events(source, namespace=None, pod_prefix=None, workload_caps=RUNTIME_DEFAULT_CAPS):
    """Yield CapCheck for every `cap_capable` kprobe event in a Tetragon JSON stream.

    `source` is an iterable of raw JSON lines or already-decoded dicts. `namespace` and
    `pod_prefix`, when given, keep only the workload's own pods (§4.2). A line that is not a
    cap_capable kprobe, or has no capability or return value, is skipped, and so are the
    container runtime's processes (see the module docstring): runc's init step, and, when the
    event carries process.cap, any process whose effective set is not within `workload_caps`
    (the default pod's set; None keeps them).
    """
    objs = []
    for item in source:
        if isinstance(item, (str, bytes)):
            item = item.strip()
            if not item:
                continue
            try:
                item = json.loads(item)
            except ValueError:
                continue
        objs.append(item)
    # Tetragon leaves out empty lists: once any event carries process.cap, an event without one is a
    # process holding no capabilities (a workload running as a non-root user), not an unknown.
    capsets_seen = any(isinstance(_get(o, "process_kprobe", "process", "cap"), dict) for o in objs)
    for obj in objs:
        ev = _get(obj, "process_kprobe")
        if not ev or ev.get("function_name") != "cap_capable":
            continue

        cap = None
        for arg in ev.get("args", []) or []:
            ca = arg.get("capability_arg") if isinstance(arg, dict) else None
            if ca:
                cap = capability_name(ca.get("name") if ca.get("name") is not None else ca.get("value"))
                if cap:
                    break
        if cap is None:
            continue

        ret = _get(ev, "return", "int_arg")
        if ret is None:
            continue
        proc, parent = ev.get("process"), ev.get("parent")
        if is_runtime_init(proc, parent):
            continue                                 # runc's init step: the runtime, not the workload
        own = own_capabilities(proc, assume_empty=capsets_seen)
        if own is not None and workload_caps is not None and not own <= workload_caps:
            continue                                 # holds what a default pod cannot: a runtime helper
        # §4.2/§8: 0 granted, -1 denied; and only a capability the process itself holds is its use
        granted = int(ret) == 0 and (own is None or cap in own)

        ns = _get(ev, "process", "pod", "namespace")
        pod = _get(ev, "process", "pod", "name")
        if namespace is not None and ns != namespace:
            continue
        if pod_prefix is not None and not (pod or "").startswith(pod_prefix):
            continue

        yield CapCheck(
            capability=cap, granted=granted,
            pid=_get(ev, "process", "pid"),
            binary=_get(ev, "process", "binary"),
            namespace=ns, pod=pod, time=obj.get("time") or _get(ev, "process", "start_time"),
        )


def labels_for_run(checks: Iterable[CapCheck]):
    """Split one run's checks into granted (the labels) and denied-only capabilities (§4.2).

    A capability granted at least once is a label. A capability only ever denied goes in
    `denied` and never in `granted`, even if the same run also denied a granted one elsewhere.
    """
    granted, denied = set(), set()
    for c in checks:
        (granted if c.granted else denied).add(c.capability)
    return {"granted": granted, "denied": denied - granted}


def union_runs(run_labels):
    """Combine per-run granted/denied sets (Test Plan §4.2: label is the union of two runs).

    Returns the union of granted labels, the union of denied-only capabilities, and the label
    noise: the capabilities not granted in *every* run, as a count and as a fraction of the
    union (0.0 when the runs agree exactly, higher when they disagree).
    """
    run_labels = list(run_labels)
    granted_sets = [set(r["granted"]) for r in run_labels]
    denied_sets = [set(r.get("denied", ())) for r in run_labels]
    union = set().union(*granted_sets) if granted_sets else set()
    intersection = set(granted_sets[0]).intersection(*granted_sets[1:]) if granted_sets else set()
    disagree = union - intersection
    return {
        "labels": sorted(union),
        "denied": sorted(set().union(*denied_sets) - union) if denied_sets else [],
        "runs": len(run_labels),
        "disagreement_count": len(disagree),
        "disagreement_caps": sorted(disagree),
        "disagreement_fraction": round(len(disagree) / len(union), 4) if union else 0.0,
    }


def build_label_row(image, digest, run_labels, workload=None):
    """One `ml/data/labels.jsonl` row for an image (Test Plan §12.2, dataset D1)."""
    merged = union_runs(run_labels)
    row = {"image": image, "digest": digest, "labels": merged["labels"], "denied": merged["denied"],
           "runs": merged["runs"], "run_disagreement": merged["disagreement_count"],
           "disagreement_fraction": merged["disagreement_fraction"]}
    if workload is not None:
        row["workload"] = workload
    return row


def rare_labels(rows, min_positive=MIN_POSITIVE_IMAGES):
    """Capabilities appearing as a label in fewer than `min_positive` images (§4.2: too rare
    to train). Returns {cap: positive_image_count} for those below the threshold."""
    counts = {}
    for r in rows:
        for cap in set(r.get("labels", ())):
            counts[cap] = counts.get(cap, 0) + 1
    return {cap: n for cap, n in sorted(counts.items()) if n < min_positive}
