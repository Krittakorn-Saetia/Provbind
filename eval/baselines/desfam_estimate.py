"""DeSFAM-E: an estimated function for DeSFAM [24] (IEEE Access 2025).

DeSFAM combines a syscall allow list, a sequence anomaly detector, and in-kernel blocking. This
estimate follows its published design (DeSFAM §IV); no DeSFAM code is used.

Phase 1 - allow list (its §IV-C, Eq. 1):
    S_final = ((S_static ∪ S_dynamic) ∩ S_template) \\ (S_blocked \\ S_template)
  S_static  : libc imports of the image binaries -> syscalls (as Confine-E).
  S_dynamic : the calls seen in the benign baseline traces.
  S_template: Docker's default seccomp allow list ∪ S_dynamic (Docker's list from --docker-seccomp;
              without it, S_static ∪ S_dynamic, stated as a simplification).
  S_blocked : the high-risk calls its paper names (syscalls.HIGH_RISK), minus the template.
A call outside S_final is blocked at runtime.

Phase 2 - anomaly detection (its §IV-D): syscall windows (length 15, stride 3), each turned into a
feature vector of per-category frequencies and inter-call timing (mean, std, max). An Isolation Forest
is trained on the benign baseline windows; a window whose anomaly score exceeds the 99.5th percentile
of the benign scores is anomalous. DeSFAM's paper also uses a Variational Autoencoder; this estimate
uses the Isolation Forest half only, and says so.

Phase 3 - enforcement (its §IV-E): a scenario is blocked from its first anomalous window.

Alongside the estimate, `published_bound()` gives what DeSFAM would score at its reported recall (0.90)
and false-positive rate (0.016), so the estimate carries a published reference.

    python -m eval.baselines.desfam_estimate --binaries DIR --docker-seccomp default.json \\
        --benign run/traces/loadgen-*.txt --trace run/traces/attack-1-1.txt ...

Capabilities are fixed by the design: runtime detection and blocking, attribution to a container /
process / MITRE technique (level 1), no admission check, no image-trust re-evaluation.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import sys

from .syscalls import CATEGORIES, HIGH_RISK, categorize, syscalls_for
from .trace import Event, imports_under, read_trace, syscalls_in

CAPABILITIES = {
    "admission_check": False,
    "runtime_detection": True,
    "prevents": True,
    "alert_text": True,
    "attribution_level": 1,        # container / process / MITRE ATT&CK technique; no package or layer
    "trust_reevaluation": False,
}
PUBLISHED = {"recall": 0.90, "false_positive_rate": 0.016, "precision": 0.94}
WINDOW, STRIDE, PERCENTILE = 15, 3, 99.5


# --- Phase 1: the allow list ------------------------------------------------------------------------

def docker_allowed(path: str | os.PathLike | None) -> set[str]:
    """The system calls Docker's default seccomp profile allows (its `syscalls[].names`)."""
    if not path:
        return set()
    doc = json.loads(open(path, encoding="utf-8").read())
    allowed: set[str] = set()
    for rule in doc.get("syscalls", []):
        if str(rule.get("action", "")).upper() in ("SCMP_ACT_ALLOW", "ALLOW"):
            allowed.update(rule.get("names", []))
    return allowed


def final_set(binaries_dir, benign_traces, docker_seccomp=None, blocked=HIGH_RISK) -> tuple[set[str], dict]:
    functions, n_elf = imports_under(binaries_dir)
    s_static = syscalls_for(functions)
    s_dynamic: set[str] = set()
    for path in benign_traces:
        s_dynamic |= syscalls_in(read_trace(path))
    template = docker_allowed(docker_seccomp) | s_dynamic
    if not docker_seccomp:
        template |= s_static                                # documented fallback when Docker's list is absent
    s_blocked = set(blocked) - template
    s_final = ((s_static | s_dynamic) & template) - s_blocked
    how = {"elf_files": n_elf, "static": len(s_static), "dynamic": len(s_dynamic),
           "template": len(template), "blocked": sorted(s_blocked), "final_size": len(s_final),
           "docker_seccomp": bool(docker_seccomp)}
    return s_final, how


# --- Phase 2: the anomaly detector ------------------------------------------------------------------

def _window_events(events, size=WINDOW, stride=STRIDE):
    kept = [e for e in events if e.syscall]
    if len(kept) < size:
        return [kept] if kept else []
    return [kept[i:i + size] for i in range(0, len(kept) - size + 1, stride)]


def features(window) -> list[float]:
    """Per-category frequencies plus inter-call timing (mean, std, max), for one window."""
    counts = {c: 0 for c in CATEGORIES}
    for e in window:
        counts[categorize(e.syscall)] += 1
    total = max(1, len(window))
    freqs = [counts[c] / total for c in CATEGORIES]
    deltas = [max(0, window[i].t_ns - window[i - 1].t_ns) for i in range(1, len(window))]
    if deltas:
        timing = [statistics.mean(deltas), statistics.pstdev(deltas), float(max(deltas))]
    else:
        timing = [0.0, 0.0, 0.0]
    return freqs + timing


class Detector:
    """Isolation Forest over benign windows, with DeSFAM's 99.5th-percentile threshold."""

    def __init__(self, model, threshold: float, n_train: int):
        self.model, self.threshold, self.n_train = model, threshold, n_train

    @classmethod
    def train(cls, benign_traces) -> "Detector":
        from sklearn.ensemble import IsolationForest
        rows = [features(w) for path in benign_traces for w in _window_events(read_trace(path))]
        if len(rows) < 2:
            raise ValueError("need at least two benign windows to train; record more baseline traffic")
        model = IsolationForest(n_estimators=100, contamination="auto", random_state=0).fit(rows)
        scores = [-s for s in model.score_samples(rows)]     # higher = more anomalous
        threshold = _percentile(scores, PERCENTILE)
        return cls(model, threshold, len(rows))

    def anomalous_windows(self, events) -> list[int]:
        wins = _window_events(events)
        if not wins:
            return []
        scores = [-s for s in self.model.score_samples([features(w) for w in wins])]
        return [i for i, s in enumerate(scores) if s > self.threshold]


def _percentile(values, q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return float("inf")
    k = min(len(ordered) - 1, int(round(q / 100 * (len(ordered) - 1))))
    return ordered[k]


# --- combined ---------------------------------------------------------------------------------------

def evaluate(events, s_final: set[str], detector: "Detector | None") -> dict:
    unlisted = [e.syscall for e in events if e.syscall and e.syscall not in s_final]
    phase1 = unlisted[0] if unlisted else None
    anomalous = detector.anomalous_windows(events) if detector else []
    detected = phase1 is not None or bool(anomalous)
    return {
        "detected": detected,
        "blocked": detected,                                # Phase 3 blocks a detected scenario
        "stage": "runtime" if detected else None,
        "phase1_unlisted_call": phase1,
        "phase2_anomalous_windows": len(anomalous),
        "syscalls_seen": len(syscalls_in(events)),
    }


def published_bound(is_malicious: bool) -> dict:
    """What DeSFAM's reported recall / FPR predict for a scenario of this kind (a reference, not a run)."""
    return {"detect_probability": PUBLISHED["recall"] if is_malicious else PUBLISHED["false_positive_rate"]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.baselines.desfam_estimate", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binaries", required=True, help="directory of the image's closure/startup ELF files")
    ap.add_argument("--docker-seccomp", help="Docker's default seccomp profile JSON (for S_template)")
    ap.add_argument("--benign", action="append", default=[], metavar="GLOB",
                    help="benign baseline trace(s) for S_dynamic and detector training (repeatable; globs allowed)")
    ap.add_argument("--trace", action="append", default=[], metavar="FILE", help="a scenario trace (repeatable)")
    ap.add_argument("--no-detector", action="store_true", help="Phase 1 only (skip the anomaly model)")
    ap.add_argument("--out", help="write the JSON result here as well as to stdout")
    args = ap.parse_args(argv)

    benign = [p for g in args.benign for p in sorted(glob.glob(g))] or args.benign
    s_final, how = final_set(args.binaries, benign, args.docker_seccomp)
    detector = None
    detector_note = "disabled (--no-detector)"
    if not args.no_detector:
        try:
            detector = Detector.train(benign)
            detector_note = f"trained on {detector.n_train} benign windows; threshold {detector.threshold:.4f}"
        except (ValueError, ImportError) as e:
            detector_note = f"not trained: {e}"
    results = {os.path.basename(p): evaluate(read_trace(p), s_final, detector) for p in args.trace}
    report = {"system": "DeSFAM-E", "estimated": True, "capabilities": CAPABILITIES,
              "published_reference": PUBLISHED, "allow_list": how, "detector": detector_note,
              "results": results}
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
