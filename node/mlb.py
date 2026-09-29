"""Phase 4 Step 4 (Eqs. 57-59, Algorithm 2): the behavioural path, ML-B.

Only events that conformed to the envelope enter a window (Algorithm 2, lines 2-4). The draft
says the gating is the novelty, not the model: a behavioural detection, D_beh, never claims a
contradiction. The settings follow Test Plan §5.

- **Monitored processes (𝒬^beh).** Processes alive for 10 s or more. A process's age is measured
  from its first event in the stream, so a replay of events.jsonl gives the same windows.
- **Windows W_q.** One per process at a time: 30 s from its first event, or 200 events,
  whichever comes first.
  - A window that closes before its process is 10 s old is dropped.
  - A window still open when its process exits, or when the stream ends, is dropped unscored,
    so every scored window has the same meaning.
- **Features Ψ_I.** Per window, as counts and as rates per second:
  - child processes started, and distinct executables among them;
  - writes;
  - new files written (paths the envelope does not declare);
  - distinct directories written;
  - executable mappings;
  - granted capability checks;
  - connections, with distinct destination addresses and ports.
  An exec counts in its parent's window. Rates divide by 30 s, or by the window's span (at least
  1 s) when 200 events closed it.
- **Model IF_I.** `IsolationForest(n_estimators=100, max_samples=min(256, n), contamination="auto",
  random_state=0)`, trained on the image's benign windows. It is stored as JSON (node/forest.py)
  beside the envelope: `<run>/envelopes/<hex>.mlb/model.json` (Eq. 49).
- **Normaliser g_I.** The percentile rank of a window's anomaly score among the validation
  windows' scores.
- **Threshold θ_A.** The 99th percentile of the validation scores; the 95th, and the model says so,
  with fewer than 100 validation windows. A window scoring above θ_A is one D_beh detection,
  with origin INFERRED.
- **Range guard (a proposed fix, on by default).** A window with any feature above twice the
  largest value in the benign windows is also a D_beh. An Isolation Forest cannot say "far
  beyond normal":
  - A window beyond the training range in a feature follows the same path through every tree as
    the most extreme benign window, so it gets the same score. attack-2's 200-write window
    scored exactly θ_A on the synthetic data, while the benign maximum was 15 writes.
  - A feature that never varied in training gets no split at all, so its first change moves no
    score.
  MLB-04 and MLB-05 report the forest alone and the forest with the guard, side by side
  (Test Plan §0, rule 1). `train(guard=None)` turns the guard off.
"""
from __future__ import annotations

import argparse
import bisect
import dataclasses
import heapq
import json
import logging
import math
import os
import sys
import posixpath
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .forest import Forest, export
from .normalize import Event, format_time
from .store import Binding, Envelope, hex_of
from .verify import detection

log = logging.getLogger("provbind.node.mlb")

NS = 1_000_000_000
WINDOW_S, WINDOW_EVENTS, MIN_AGE_S = 30.0, 200, 10.0
COUNTS = ("exec", "write", "load", "cap", "connect", "new_files", "dirs_written", "distinct_exes",
          "distinct_daddrs", "distinct_dports")
FEATURES = COUNTS + tuple(f"{k}_per_s" for k in COUNTS)
SCHEMA = "provbind.mlb/v0"
PARAMS = {"n_estimators": 100, "max_samples": "min(256, n)", "contamination": "auto", "random_state": 0}


@dataclass
class Window:
    t0: int
    serial: int
    t_last: int = 0
    n: int = 0
    counts: Counter = field(default_factory=Counter)
    new_files: set = field(default_factory=set)
    dirs: set = field(default_factory=set)
    exes: set = field(default_factory=set)
    daddrs: set = field(default_factory=set)
    dports: set = field(default_factory=set)

    def features(self, duration_s: float) -> dict:
        raw = {"exec": self.counts["exec"], "write": self.counts["write"], "load": self.counts["load"],
               "cap": self.counts["cap"], "connect": self.counts["connect"], "new_files": len(self.new_files),
               "dirs_written": len(self.dirs), "distinct_exes": len(self.exes),
               "distinct_daddrs": len(self.daddrs), "distinct_dports": len(self.dports)}
        rates = {f"{k}_per_s": round(v / duration_s, 6) for k, v in raw.items()}
        return {**raw, **rates}


@dataclass
class Proc:
    """One process in one container, as ML-B tracks it."""
    container_id: str
    pid: int | None
    first_seen: int
    last: Event
    binding: Binding
    env: Envelope
    window: Window | None = None


class Model:
    """A per-image ML-B model: the forest, θ_A and g_I (the validation scores)."""

    def __init__(self, doc: Mapping):
        if doc.get("schema") != SCHEMA:
            raise ValueError(f"not a {SCHEMA} model")
        self.doc = doc
        self.forest = Forest(doc["forest"])
        if tuple(self.forest.features) != FEATURES:
            raise ValueError("the model's features are not this node's Ψ_I")
        self.theta = float(doc["theta_a"])
        self.validation = sorted(float(v) for v in doc["validation_scores"])
        self.mean, self.std = doc.get("feature_mean", {}), doc.get("feature_std", {})
        guard = doc.get("guard") or {}
        self.guard_factor = guard.get("factor")
        self.guard_max = guard.get("max", {})

    @classmethod
    def load(cls, path: str | os.PathLike) -> Model:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def anomaly(self, features: Mapping[str, float]) -> float:
        return self.forest.anomaly([float(features.get(f, 0.0)) for f in FEATURES])

    def beyond(self, features: Mapping[str, float]) -> list[tuple[str, float, float]]:
        """The range guard: (feature, value, benign maximum) for each feature above factor x maximum."""
        if not self.guard_factor:
            return []
        return [(f, features.get(f, 0.0), self.guard_max.get(f, 0.0)) for f in FEATURES
                if features.get(f, 0.0) > self.guard_factor * self.guard_max.get(f, 0.0)]

    def decide(self, features: Mapping[str, float]) -> dict:
        """Everything ML-B concludes about one window: the forest's view and the guard's."""
        a = self.anomaly(features)
        beyond = self.beyond(features)
        return {"anomaly": a, "g": self.normalise(a), "forest": a > self.theta, "guard": bool(beyond),
                "beyond": beyond, "anomalous": a > self.theta or bool(beyond)}

    def normalise(self, a: float) -> float:
        """g_I: the fraction of validation windows scoring at or below a."""
        return bisect.bisect_right(self.validation, a) / len(self.validation) if self.validation else 1.0

    def unusual(self, features: Mapping[str, float], k: int = 3) -> list[tuple[str, float, float]]:
        """The k features furthest above their training mean, in training standard deviations."""
        out = []
        for f in FEATURES:
            mean, std = self.mean.get(f, 0.0), self.std.get(f, 0.0)
            z = (features.get(f, 0.0) - mean) / std if std > 0 else (math.inf if features.get(f, 0.0) > mean else 0.0)
            out.append((f, features.get(f, 0.0), z))
        return sorted((x for x in out if x[2] > 0), key=lambda x: -x[2])[:k]


def model_path(run_dir: str | os.PathLike, digest: str) -> Path:
    return Path(run_dir) / "envelopes" / f"{hex_of(digest)}.mlb" / "model.json"


class ModelCache:
    """model_for(digest) from the run folder, reloaded when the file changes; None if there is none."""

    def __init__(self, run_dir: str | os.PathLike):
        self.run_dir = Path(run_dir)
        self._cache: dict[str, tuple] = {}

    def __call__(self, digest: str | None) -> Model | None:
        if not digest:
            return None
        path = model_path(self.run_dir, digest)
        try:
            st = path.stat()
        except FileNotFoundError:
            self._cache.pop(digest, None)
            return None
        stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
        cached = self._cache.get(digest)
        if cached is None or cached[0] != stamp:
            try:
                cached = (stamp, Model.load(path))
            except (OSError, ValueError, KeyError) as e:
                cached = (stamp, None)
                log.error("ML-B model %s unusable, windows stay unscored: %s", path, e)
            self._cache[digest] = cached
        return cached[1]


class Behaviour:
    """The pipeline's ML-B stage: windows from conforming events, scored when a model exists.

    `model_for(digest)` gives the image's Model, or None to record windows without scoring them.
    `on_window(record)` receives every window that closes (the D2 dataset is built from these).
    `entered`, if a list, receives every event that enters a window (MLB-01 checks it).
    """

    def __init__(self, model_for: Callable[[str | None], Model | None] | None = None,
                 on_window: Callable[[dict], None] | None = None, *, window_s: float = WINDOW_S,
                 window_events: int = WINDOW_EVENTS, min_age_s: float = MIN_AGE_S, entered: list | None = None):
        self.model_for = model_for or (lambda digest: None)
        self.on_window, self.entered = on_window, entered
        self.window, self.max_events, self.min_age = int(window_s * NS), window_events, int(min_age_s * NS)
        self.procs: dict[tuple, Proc] = {}
        self.stats: Counter = Counter()
        self._due: list = []                      # heap of (close time, serial, process key)
        self._serial = 0

    # the pipeline's interface -------------------------------------------------------------------
    def observe(self, ev: Event, det, env: Envelope, binding: Binding) -> list[dict]:
        out = self.tick(ev.t)
        key = (ev.container_id, ev.pid)
        p = self.procs.get(key)
        if ev.kind == "exec" or p is None:            # a new program in this pid starts a new process
            if p is not None and p.window is not None:
                self.stats["dropped_at_exec"] += 1
            p = self.procs[key] = Proc(ev.container_id, ev.pid, ev.t, ev, binding, env)
        p.last, p.binding, p.env = ev, binding, env
        if ev.kind == "exit":
            if p.window is not None:
                self.stats["dropped_at_exit"] += 1
            del self.procs[key]
            return out
        if det is not None:                           # the gate: no contradiction enters a window
            self.stats["gated"] += 1
            return out
        if ev.kind == "exec":
            parent = self.procs.get((ev.container_id, ev.ppid))
            if parent is None:
                return out                            # started from outside the container
            return out + self._add(parent, ev)
        if ev.kind == "cap" and ev.granted is False:
            return out                                # a denied check used nothing
        return out + self._add(p, ev)

    def tick(self, now: int) -> list[dict]:
        """Close every window whose 30 s have passed by `now`."""
        out = []
        while self._due and self._due[0][0] <= now:
            due, serial, key = heapq.heappop(self._due)
            p = self.procs.get(key)
            if p is not None and p.window is not None and p.window.serial == serial:
                out += self._close(p, "time", due)
        return out

    def close(self, now: int) -> list[dict]:
        out = self.tick(now)
        self.stats["dropped_at_end"] += sum(1 for p in self.procs.values() if p.window is not None)
        return out

    # windows ----------------------------------------------------------------------------------
    def _add(self, p: Proc, ev: Event) -> list[dict]:
        out = []
        w = p.window
        if w is not None and ev.t >= w.t0 + self.window:
            out += self._close(p, "time", w.t0 + self.window)
            w = None
        if w is None:
            self._serial += 1
            w = p.window = Window(t0=ev.t, serial=self._serial)
            heapq.heappush(self._due, (ev.t + self.window, self._serial, (p.container_id, p.pid)))
        w.n += 1
        w.t_last = ev.t
        if ev.kind == "exec":
            w.counts["exec"] += 1
            w.exes.add(ev.exe)
        elif ev.kind == "write":
            w.counts["write"] += 1
            w.dirs.add(posixpath.dirname(ev.path))
            if p.env.lookup(ev.path)[1] is None:
                w.new_files.add(ev.path)
        elif ev.kind == "connect":
            w.counts["connect"] += 1
            w.daddrs.add(ev.daddr)
            w.dports.add(ev.dport)
        else:
            w.counts[ev.kind] += 1                    # load, cap
        if self.entered is not None:
            self.entered.append(ev)
        if w.n >= self.max_events:
            out += self._close(p, "count", ev.t)
        return out

    def _close(self, p: Proc, closed_by: str, end: int) -> list[dict]:
        w, p.window = p.window, None
        if end - p.first_seen < self.min_age:
            self.stats["young"] += 1
            return []
        span = self.window / NS if closed_by == "time" else max((w.t_last - w.t0) / NS, 1.0)
        feats = w.features(span)
        rec = {"digest": p.binding.image_digest, "container_id": p.container_id, "namespace": p.last.namespace,
               "pod": p.last.pod, "pid": p.pid, "exe": p.last.exe, "start": format_time(w.t0), "end": format_time(end),
               "events": w.n, "closed_by": closed_by, "age_s": round((end - p.first_seen) / NS, 3), "features": feats}
        self.stats["windows"] += 1
        if self.on_window is not None:
            self.on_window(rec)
        model = self.model_for(p.binding.image_digest)
        if model is None:
            return []
        v = model.decide(feats)
        self.stats["scored"] += 1
        self.stats["forest_anomalous"] += v["forest"]
        self.stats["guard_anomalous"] += v["guard"]
        if not v["anomalous"]:
            return []
        self.stats["anomalous"] += 1
        return [self._detection(p, rec, v, model, end)]

    def _detection(self, p: Proc, rec: dict, v: dict, model: Model, end: int) -> dict:
        why = []
        if v["forest"]:
            why.append(f"anomaly {v['anomaly']:.4f} > θ_A {model.theta:.4f}")
        if v["beyond"]:
            why.append(f"beyond {model.guard_factor:g}x the benign maximum: "
                       + ", ".join(f"{f}={x:g} (max {m:g})" for f, x, m in v["beyond"][:3]))
        top = ", ".join(f"{f}={x:g}" for f, x, _ in model.unusual(rec["features"]))
        detail = (f"{rec['events']} events {rec['start']} to {rec['end']} (closed by {rec['closed_by']}): "
                  + "; ".join(why) + f"; anomaly {v['anomaly']:.4f}, g_I {v['g']:.3f}"
                  + (f"; most unusual: {top}" if top else ""))
        key, _ = p.env.lookup(p.last.exe)
        at = dataclasses.replace(p.last, time=format_time(end), t=end, pid=p.pid)
        return detection(at, p.binding, "D_beh", "anomalous_window", ("behaviour", p.last.exe, detail), "INFERRED",
                         p.env.context(key))


# training and evaluation -----------------------------------------------------------------------------

def vectors(windows: Sequence[Mapping]) -> list[list[float]]:
    return [[float(w["features"].get(f, 0.0)) for f in FEATURES] for w in windows]


def split(windows: Sequence[Mapping], train_fraction: float = 0.7) -> tuple[list, list]:
    """Chronological 70/30: the validation windows come after every training window."""
    ordered = sorted(windows, key=lambda w: (w["start"], w.get("container_id", ""), w.get("pid") or 0))
    cut = int(len(ordered) * train_fraction)
    return ordered[:cut], ordered[cut:]


def train(train_windows: Sequence[Mapping], validation_windows: Sequence[Mapping], digest: str,
          seed: int = 0, guard: float | None = 2.0) -> dict:
    """Eq. (49): fit IF_I, set g_I and θ_A from the validation windows; a JSON-ready model.
    `guard` is the range guard's factor over the benign maximum (train and validation); None is off."""
    import numpy as np
    from sklearn.ensemble import IsolationForest

    if len(train_windows) < 2 or not validation_windows:
        raise ValueError(f"need at least 2 training and 1 validation windows, got {len(train_windows)} "
                         f"and {len(validation_windows)}")
    X = np.array(vectors(train_windows))
    forest_model = IsolationForest(n_estimators=100, max_samples=min(256, len(X)), contamination="auto",
                                   random_state=seed).fit(X)
    doc_forest = export(forest_model, FEATURES)
    forest = Forest(doc_forest)
    scores = sorted(forest.anomaly(v) for v in vectors(validation_windows))
    pct = 99 if len(scores) >= 100 else 95
    return {"schema": SCHEMA, "digest": digest, "features": list(FEATURES), "forest": doc_forest,
            "theta_a": float(np.percentile(scores, pct)), "percentile": pct,
            "percentile_note": "" if pct == 99 else f"only {len(scores)} validation windows, so the 95th percentile",
            "validation_scores": scores,
            "windows": {"train": len(X), "validation": len(scores)},
            "feature_mean": {f: float(m) for f, m in zip(FEATURES, X.mean(axis=0))},
            "feature_std": {f: float(s) for f, s in zip(FEATURES, X.std(axis=0))},
            "guard": {"factor": guard, "max": {f: float(m) for f, m in zip(
                FEATURES, np.vstack([X, np.array(vectors(validation_windows))]).max(axis=0))}} if guard else None,
            "params": {**PARAMS, "max_samples": int(forest.max_samples), "random_state": seed},
            "window": {"seconds": WINDOW_S, "events": WINDOW_EVENTS, "min_age_s": MIN_AGE_S},
            "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def evaluate(model: Model, windows: Sequence[Mapping]) -> dict:
    """The window false-positive rate on benign windows (MLB-04), for the model as it decides and
    for the forest alone."""
    verdicts = [model.decide(w["features"]) for w in windows]
    n = len(verdicts)

    def rate(k):
        return round(k / n, 6) if n else None
    fp = sum(v["anomalous"] for v in verdicts)
    forest_fp = sum(v["forest"] for v in verdicts)
    return {"windows": n, "false_positives": fp, "fpr": rate(fp), "forest_false_positives": forest_fp,
            "forest_fpr": rate(forest_fp), "guard_false_positives": sum(v["guard"] for v in verdicts),
            "theta_a": model.theta, "max_score": max((v["anomaly"] for v in verdicts), default=None)}


def compare_global(datasets: Mapping[str, tuple], attack: Sequence[Mapping] = (), seed: int = 0) -> dict:
    """MLB-06 (C5): one model per image against one global model trained on every image's windows.

    `datasets` maps a digest to its (train, validation, heldout) windows; at least 3 images.
    `attack` windows are judged by their own image's model and by the global one. Each model is
    reported as it decides (forest and guard) and as the forest alone.
    """
    if len(datasets) < 3:
        raise ValueError(f"MLB-06 needs at least 3 images, got {len(datasets)}")
    per_image = {d: Model(train(tr, va, d, seed)) for d, (tr, va, _) in datasets.items()}
    pooled = Model(train([w for tr, _, _ in datasets.values() for w in tr],
                         [w for _, va, _ in datasets.values() for w in va], "global", seed))
    out = {"images": sorted(datasets), "per_image": {}, "global": {}}
    for d, (_, _, heldout) in datasets.items():
        out["per_image"][d] = evaluate(per_image[d], heldout)
        out["global"][d] = evaluate(pooled, heldout)
    if attack:
        own = [per_image[w["digest"]].decide(w["features"]) for w in attack if w.get("digest") in per_image]
        glob = [pooled.decide(w["features"]) for w in attack]
        out["attack"] = {"windows": len(attack),
                         "per_image": {"anomalous": sum(v["anomalous"] for v in own), "forest": sum(v["forest"] for v in own)},
                         "global": {"anomalous": sum(v["anomalous"] for v in glob), "forest": sum(v["forest"] for v in glob)}}
    return out


def write_model(run_dir: str | os.PathLike, doc: Mapping) -> Path:
    """<run>/envelopes/<hex>.mlb/model.json, beside the envelope, written atomically."""
    path = model_path(run_dir, doc["digest"])
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".model.{os.getpid()}.json.tmp")
    tmp.write_text(json.dumps(doc), encoding="utf-8")
    os.replace(tmp, path)
    return path


def read_windows(path: str | os.PathLike) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_windows(path: str | os.PathLike, windows: Sequence[Mapping]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for w in windows:
            f.write(json.dumps(w, separators=(",", ":")) + "\n")


# python -m node.mlb ---------------------------------------------------------------------------------

def digest_of(data_dir: Path, windows: Sequence[Mapping], given: str | None) -> str:
    """--digest, else ml/data/mlb/<hex>/'s name, else the one digest the windows share."""
    if given:
        return given if given.startswith("sha256:") else "sha256:" + given
    name = data_dir.name if data_dir else ""
    if len(name) == 64 and all(ch in "0123456789abcdef" for ch in name):
        return "sha256:" + name
    digests = {w.get("digest") for w in windows}
    if len(digests) != 1 or None in digests:
        raise SystemExit(f"windows from {len(digests)} digests; give --digest")
    return digests.pop()


def cmd_windows(args) -> int:
    from .scenarios import replay
    from .store import Store
    from .verify import Egress
    store = Store(args.run)
    store.refresh()
    out = []
    stage = Behaviour(on_window=out.append)
    with open(args.replay, encoding="utf-8", errors="replace") as f:
        replay(f, store, egress=Egress.load(args.egress) if args.egress else None, behaviour=stage,
               keep=lambda e: False)
    if args.digest:
        out = [w for w in out if w["digest"] == digest_of(None, out, args.digest)]
    if args.out:
        write_windows(args.out, out)
    else:
        for w in out:
            print(json.dumps(w, separators=(",", ":")))
    log.info("%d windows (%s)", len(out), dict(stage.stats))
    return 0


def cmd_split(args) -> int:
    windows = read_windows(args.windows)
    train_w, validation_w = split(windows, args.train_fraction)
    out = Path(args.out_dir)
    write_windows(out / "train.jsonl", train_w)
    write_windows(out / "validation.jsonl", validation_w)
    print(json.dumps({"train": len(train_w), "validation": len(validation_w), "out": str(out)}))
    return 0


def cmd_train(args) -> int:
    data = Path(args.data)
    train_w, validation_w = read_windows(data / "train.jsonl"), read_windows(data / "validation.jsonl")
    digest = digest_of(data, train_w + validation_w, args.digest)
    doc = train(train_w, validation_w, digest, seed=args.seed, guard=args.guard or None)
    path = write_model(args.run, doc)
    print(json.dumps({"model": str(path), "digest": digest, "windows": doc["windows"], "theta_a": doc["theta_a"],
                      "percentile": doc["percentile"], "percentile_note": doc["percentile_note"],
                      "guard": doc["guard"]["factor"] if doc["guard"] else None}))
    return 0


def cmd_evaluate(args) -> int:
    data = Path(args.data)
    windows = read_windows(args.windows or data / "heldout.jsonl")
    digest = digest_of(data, windows, args.digest)
    model = Model.load(model_path(args.run, digest))
    print(json.dumps({"digest": digest, **evaluate(model, windows)}))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m node.mlb", description="ML-B: windows, D2 dataset, model")
    ap.add_argument("--log-level", default="INFO")
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("windows", help="replay a recording and write every closed window (JSONL)")
    w.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"))
    w.add_argument("--replay", required=True, help="Tetragon JSON or events.jsonl")
    w.add_argument("--out", help="output file (default stdout)")
    w.add_argument("--digest", help="keep only this image's windows")
    w.add_argument("--egress", help="egress allow list, as node.run takes it")
    s = sub.add_parser("split", help="chronological 70/30 into train.jsonl and validation.jsonl")
    s.add_argument("--windows", required=True)
    s.add_argument("--out-dir", required=True, help="ml/data/mlb/<hex>")
    s.add_argument("--train-fraction", type=float, default=0.7)
    t = sub.add_parser("train", help="train IF_I and write it beside the envelope")
    t.add_argument("--data", required=True, help="ml/data/mlb/<hex>, with train.jsonl and validation.jsonl")
    t.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"))
    t.add_argument("--digest")
    t.add_argument("--seed", type=int, default=0)
    t.add_argument("--guard", type=float, default=2.0,
                   help="range guard: factor over the benign maximum (default 2; 0 turns it off)")
    e = sub.add_parser("evaluate", help="window false-positive rate on held-out benign windows")
    e.add_argument("--data", required=True, help="ml/data/mlb/<hex>, with heldout.jsonl")
    e.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"))
    e.add_argument("--digest")
    e.add_argument("--windows", help="another windows file instead of heldout.jsonl")
    args = ap.parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return {"windows": cmd_windows, "split": cmd_split, "train": cmd_train, "evaluate": cmd_evaluate}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
