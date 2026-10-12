"""Ryu-E: an estimated function for Ryu et al. [17] (Computers, Materials & Continua 86(3), 2026).

Ryu et al. classify containers with machine-learning models trained on labelled examples. Their host-
based detector, the stronger of their two (98.39% accuracy against 87.49% for network flows), reads a
container's system calls from Tetragon, turns each call into its x86-64 number, cuts the sequence into
overlapping 5-call windows, and trains a classifier on the windows; a decision tree scored best (their
Sections 4.2-4.3 and Table 4). This estimate follows that design on the comparison run's recorded
traces; no code of theirs is used. Their flow-based detector needs per-connection flow records
(bpfFlowMon), which our runs did not record, so it is left out.

Two protocols:

- Theirs (parity): every window of every trace, labelled with its run's scenario, split at random
  70:30, a decision tree trained on the 70 and scored on the 30: accuracy and weighted precision,
  recall and F1, as in their Table 4. Windows of one run fall on both sides of the split, so this
  measures how well the model recognises behaviour it has already seen.

- Ours (the comparison): the model learns from labelled examples, as theirs does, but only from what is
  known before an attack: the normal-traffic recordings (traces/baseline/benign-*.txt, labelled benign)
  and the known attacks that show in system calls (rk-2 and rk-3 by default, each its own class, as Ryu
  et al. give each malware family its own label). It is then applied to every traced run. A run of a
  training attack is scored by a model trained without that run (leave one run out): the model has
  seen the attack's other runs, never the run it scores. The trust scenarios are not used for
  training, because their malice is a key or advisory state that system calls do not show. The
  admission scenarios are not traced, so like the other trace-based estimators Ryu-E cannot see them.

Labels in our protocol (`--labels`; this estimate's adaptation): an attack run also contains the app's
normal activity, unlike Ryu et al.'s malware containers. With `clean` (the default) only the windows of
an attack run that never occur in the normal-traffic recordings carry the attack's label; the shared
ones are left out of training. This favours Ryu-E. With `run`, every window of an attack run carries
the attack's label, as in Ryu et al.

Run-level decision (this estimate's calibration, as for DeSFAM-E): a window counts as malicious when the
tree predicts an attack class. A run is detected when its share of malicious windows exceeds the
largest share seen on normal traffic: each normal-traffic recording is scored by a model trained
without it (leave one out), and the largest share is the threshold. `--trace-rule window` detects a
run with any malicious window; `majority`, a run whose windows are mostly malicious.

Every trace is reduced to its distinct windows and how often each occurs; the tree is trained with
those counts as sample weights, which is the same as training on every window, without sampling.

    python -m eval.baselines.ryu_estimate --run "$PROVBIND_RUN"
    # writes $PROVBIND_RUN/results/ryu.json (keyed by trace file, like desfam.json) and RYU.md

Capabilities fixed by the design: runtime detection and classification, attribution to a container and
a malware class (level 1), no blocking, no admission check, no image-trust re-evaluation.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import zlib
from pathlib import Path

import numpy as np

from .trace import iter_syscalls

WINDOW = 5                          # Ryu et al. Section 4.2: overlapping 5-call windows (stride 1)
BITS = 11                           # a call number fits in 11 bits: the table ends at 461, unknown calls 1000-1999
BENIGN = "benign"
BASELINE = "baseline"               # the label of the normal-traffic recordings in their protocol
DEFAULT_TRAIN = ("rk-2", "rk-3")    # the comparison's known attacks that show in system calls
TRACE_NAME = re.compile(r"^(?P<scenario>.+)-(?P<k>\d+)\.txt$")
# The comparison's known and unknown attacks (as in eval/plots.py and eval/zero_day_check.py).
KNOWN = ("ak-1", "ak-2", "ak-3", "trust-1", "trust-2", "rk-2", "rk-3")
UNKNOWN = ("au-2", "attack-1", "attack-2", "ru-3", "ru-4", "ru-5")
NOT_COUNTED = ("tamper-1",)         # as eval/baselines/aggregate.py: not a detection scenario

CAPABILITIES = {
    "admission_check": False,
    "runtime_detection": True,
    "prevents": False,
    "alert_text": True,
    "attribution_level": 1,         # container and a malware class; no package or layer
    "trust_reevaluation": False,
}
PUBLISHED = {"host_accuracy": 0.9839, "host_f1": 0.9837, "flow_accuracy": 0.8749, "best_model": "decision tree",
             "scenarios": "6 malicious, 4 benign", "split": "random 70:30 of windows",
             "source": "Ryu et al., Computers, Materials & Continua 86(3), 2026, Tables 3 and 4"}

_TABLE: dict[str, int] | None = None


def syscall_numbers() -> dict[str, int]:
    """The x86-64 system-call table (name -> number)."""
    global _TABLE
    if _TABLE is None:
        doc = json.loads(Path(__file__).with_name("syscall_numbers_x86_64.json").read_text(encoding="utf-8"))
        _TABLE = doc["numbers"]
    return _TABLE


def number_of(name: str, unknown: set[str] | None = None) -> int:
    """A call's x86-64 number. A name missing from the table gets a fixed number from 1000 to 1999."""
    table = syscall_numbers()
    n = table.get(name, table.get("new" + name))
    if n is None:
        if unknown is not None:
            unknown.add(name)
        n = 1000 + zlib.crc32(name.encode()) % 1000
    return n


def read_calls(path, unknown: set[str] | None = None) -> np.ndarray:
    """A trace's system calls as x86-64 numbers, in order (the container runtime's own calls dropped)."""
    cache: dict[str, int] = {}

    def num(call: str) -> int:
        v = cache.get(call)
        if v is None:
            v = cache[call] = number_of(call, unknown)
        return v

    return np.fromiter((num(c) for c in iter_syscalls(path)), dtype=np.int32)


def windows_of(calls: np.ndarray) -> np.ndarray:
    """Every overlapping window of WINDOW calls (stride 1); none when the trace is shorter."""
    calls = np.asarray(calls, dtype=np.int32)
    if len(calls) < WINDOW:
        return np.empty((0, WINDOW), dtype=np.int32)
    return np.lib.stride_tricks.sliding_window_view(calls, WINDOW)


def keys_of(rows: np.ndarray) -> np.ndarray:
    """One integer per window (its five call numbers packed into BITS bits each)."""
    k = np.zeros(len(rows), dtype=np.int64)
    for j in range(WINDOW):
        k = (k << BITS) | rows[:, j].astype(np.int64)
    return k


class Table:
    """A trace reduced to its distinct windows: the rows, how often each occurs, and their keys."""

    def __init__(self, rows: np.ndarray, counts: np.ndarray, keys: np.ndarray):
        self.rows, self.counts, self.keys = rows, counts, keys

    @classmethod
    def of_calls(cls, calls: np.ndarray) -> "Table":
        wins = windows_of(calls)
        if not len(wins):
            return cls(np.empty((0, WINDOW), dtype=np.int32), np.empty(0, dtype=np.int64), np.empty(0, dtype=np.int64))
        keys = keys_of(wins)
        uniq, first, counts = np.unique(keys, return_index=True, return_counts=True)
        return cls(np.array(wins[first], dtype=np.int32), counts.astype(np.int64), uniq)

    @property
    def windows(self) -> int:
        return int(self.counts.sum())

    def without(self, keys: np.ndarray) -> "Table":
        """The windows whose key is not in `keys` (a sorted array)."""
        if not len(self.keys) or not len(keys):
            return self
        keep = ~np.isin(self.keys, keys, assume_unique=True)
        return Table(self.rows[keep], self.counts[keep], self.keys[keep])


def merge_keys(tables) -> np.ndarray:
    parts = [t.keys for t in tables if len(t.keys)]
    return np.unique(np.concatenate(parts)) if parts else np.empty(0, dtype=np.int64)


def fit(benign: list[Table], attacks: list[tuple[str, Table]], labels: str = "clean"):
    """A decision tree on the benign windows and the attack windows (sample weight = occurrences).
    With labels="clean", an attack window that occurs in the benign tables is left out. Returns None
    when there is nothing to learn (no windows at all)."""
    from sklearn.tree import DecisionTreeClassifier
    benign_keys = merge_keys(benign) if labels == "clean" else None
    xs, ys, ws = [], [], []
    for t in benign:
        if len(t.rows):
            xs.append(t.rows); ys += [BENIGN] * len(t.rows); ws.append(t.counts)
    for label, t in attacks:
        t = t.without(benign_keys) if benign_keys is not None else t
        if len(t.rows):
            xs.append(t.rows); ys += [label] * len(t.rows); ws.append(t.counts)
    if not xs:
        return None
    model = DecisionTreeClassifier(random_state=0)
    model.fit(np.vstack(xs), np.array(ys), sample_weight=np.concatenate(ws).astype(float))
    return model


def malicious_share(model, t: Table) -> tuple[float, int, dict]:
    """(share of the trace's windows predicted as an attack class, malicious windows, windows per class)."""
    total = t.windows
    if model is None or not total:
        return 0.0, 0, {}
    pred = model.predict(t.rows)
    per_class: dict[str, int] = {}
    for label in np.unique(pred):
        per_class[str(label)] = int(t.counts[pred == label].sum())
    bad = sum(v for k, v in per_class.items() if k != BENIGN)
    return bad / total, bad, per_class


def thirds(calls: np.ndarray) -> list[Table]:
    """A single normal-traffic recording cut in three, to stand in for separate recordings."""
    n = len(calls)
    cuts = [0, n // 3, 2 * n // 3, n]
    return [Table.of_calls(calls[cuts[i]:cuts[i + 1]]) for i in range(3)]


def decide(share: float, malicious: int, threshold: float, rule: str) -> bool:
    if rule == "window":
        return malicious > 0
    if rule == "majority":
        return share > 0.5
    return malicious > 0 and share > threshold


# --- their protocol (parity) ----------------------------------------------------------------------

def parity(labelled: list[tuple[str, Table]], seed: int = 0, test_size: float = 0.3) -> dict:
    """Ryu et al.'s own protocol: every window labelled with its trace's scenario, split at random 70:30
    (each occurrence goes to the test side with probability 0.3), a decision tree trained on the 70 and
    scored on the 30. Returns accuracy and weighted precision, recall and F1, as in their Table 4."""
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    from sklearn.tree import DecisionTreeClassifier
    merged: dict[str, dict[int, list]] = {}
    for label, t in labelled:
        d = merged.setdefault(label, {})
        for row, c, k in zip(t.rows, t.counts, t.keys):
            if k in d:
                d[k][1] += int(c)
            else:
                d[k] = [row, int(c)]
    rng = np.random.default_rng(seed)
    xs, ys, w_train, w_test = [], [], [], []
    for label, d in sorted(merged.items()):
        for row, c in d.values():
            test = int(rng.binomial(c, test_size))
            xs.append(row); ys.append(label); w_train.append(c - test); w_test.append(test)
    if not xs:
        return {"windows": 0}
    x, y = np.vstack(xs), np.array(ys)
    w_train, w_test = np.array(w_train, dtype=float), np.array(w_test, dtype=float)
    tr, te = w_train > 0, w_test > 0
    model = DecisionTreeClassifier(random_state=0).fit(x[tr], y[tr], sample_weight=w_train[tr])
    pred = model.predict(x[te])
    p, r, f, _ = precision_recall_fscore_support(y[te], pred, average="weighted", sample_weight=w_test[te],
                                                 zero_division=0)
    return {"windows": int(w_train.sum() + w_test.sum()), "test_windows": int(w_test.sum()),
            "classes": len(merged), "accuracy": round(float(accuracy_score(y[te], pred, sample_weight=w_test[te])), 4),
            "precision_weighted": round(float(p), 4), "recall_weighted": round(float(r), 4),
            "f1_weighted": round(float(f), 4)}


# --- the estimate ---------------------------------------------------------------------------------

def scenario_traces(paths) -> list[tuple[str, int, str]]:
    """(scenario, k, path) for every `<scenario>-<k>.txt` trace, sorted."""
    out = []
    for p in sorted(paths):
        m = TRACE_NAME.match(os.path.basename(p))
        if m:
            out.append((m["scenario"], int(m["k"]), p))
    return out


def estimate(traces, benign_paths, train_attacks=DEFAULT_TRAIN, labels="clean", rule="fraction",
             seed=0, with_parity=True) -> dict:
    unknown: set[str] = set()
    base_calls = [read_calls(p, unknown) for p in benign_paths]
    baseline = [Table.of_calls(c) for c in base_calls]
    if not any(t.windows for t in baseline):
        raise ValueError("no normal-traffic windows: give the baseline recordings (traces/baseline/benign-*.txt)")
    scen = scenario_traces(traces)
    train = [(s, k, p) for s, k, p in scen if s in train_attacks]
    attack_tables = {(s, k): Table.of_calls(read_calls(p, unknown)) for s, k, p in train}
    attacks = [(s, attack_tables[(s, k)]) for s, k, _ in train]

    # The run threshold: the largest malicious share over the normal-traffic recordings, each scored by a
    # model trained without it (cleaned against the remaining recordings only).
    folds = baseline if len(baseline) > 1 else thirds(base_calls[0])
    del base_calls                           # the reduced tables are all that is needed from here on
    shares = []
    for i, held in enumerate(folds):
        model = fit([t for j, t in enumerate(folds) if j != i], attacks, labels)
        shares.append(round(malicious_share(model, held)[0], 6))
    threshold = max(shares) if shares else 0.0

    full = fit(baseline, attacks, labels)
    results = {}
    for s, k, p in scen:
        if (s, k) in attack_tables:          # a training attack's run: scored by a model trained without it
            t = attack_tables[(s, k)]
            model = fit(baseline, [(s2, attack_tables[(s2, k2)]) for s2, k2, _ in train if (s2, k2) != (s, k)], labels)
            how = "leave-one-run-out"
        else:
            t = Table.of_calls(read_calls(p, unknown))
            model, how = full, "all training data"
        share, bad, per_class = malicious_share(model, t)
        results[os.path.basename(p)] = {
            "detected": decide(share, bad, threshold, rule),
            "malicious_share": round(share, 6), "malicious_windows": bad, "windows": t.windows,
            "distinct_windows": int(len(t.rows)), "predicted": per_class, "model": how,
        }
    report = {
        "system": "Ryu-E", "estimated": True, "capabilities": CAPABILITIES, "published_reference": PUBLISHED,
        "design": {"window": WINDOW, "stride": 1, "features": "x86-64 call numbers", "model": "decision tree",
                   "labels": labels, "train_attacks": list(train_attacks), "trace_rule": rule,
                   "baseline_recordings": [os.path.basename(p) for p in benign_paths],
                   "training_attack_runs": [os.path.basename(p) for _, _, p in train]},
        "calibration": {"threshold": round(threshold, 6), "baseline_shares": shares,
                        "how": "leave one recording out" if len(baseline) > 1 else "thirds of one recording"},
        "unknown_syscalls": sorted(unknown),
        "results": results,
    }
    if with_parity:
        labelled = [(BASELINE, t) for t in baseline]
        for s, k, p in scen:
            t = attack_tables.get((s, k)) or Table.of_calls(read_calls(p, unknown))
            labelled.append((s, t))
        report["their_protocol"] = parity(labelled, seed=seed)
    return report


# --- the summary beside the other systems ---------------------------------------------------------

def _f(v):
    return "—" if v is None else (f"{v:.2f}" if isinstance(v, float) else str(v))


def summary(run_dir, report) -> dict:
    """Ryu-E judged per ground-truth row like the other systems (the k-th trace of a scenario is its k-th
    row, as in eval/baselines/aggregate.py), with the confusion matrix, metrics and known/unknown counts;
    the other systems' figures come from results/COMPARISON.json when it exists."""
    from eval.compare import confusion, load_ground_truth, metrics
    gt = load_ground_truth(os.path.join(run_dir, "ground_truth.csv"))
    by_trace = {}
    for name, res in (report.get("results") or {}).items():
        m = TRACE_NAME.match(name)
        if m:
            by_trace[(m["scenario"], int(m["k"]))] = res
    seen: dict[str, int] = {}
    rows = []
    for g in gt:
        s = g["scenario"]
        k = seen[s] = seen.get(s, 0) + 1
        res = by_trace.get((s, k))
        rows.append({"scenario": s, "label": g.get("label"), "run": k, "Ryu-E": bool(res and res.get("detected")),
                     "traced": res is not None})
    counted = [r for r in rows if r["label"] in ("malicious", "benign") and r["scenario"] not in NOT_COUNTED]
    c = confusion(counted, "Ryu-E")
    known = [r for r in counted if r["scenario"] in KNOWN]
    unknown = [r for r in counted if r["scenario"] in UNKNOWN]
    per_scenario: dict[str, dict] = {}
    for r in rows:
        e = per_scenario.setdefault(r["scenario"], {"scenario": r["scenario"], "label": r["label"], "runs": 0,
                                                    "Ryu-E": 0, "traced": 0})
        e["runs"] += 1; e["Ryu-E"] += r["Ryu-E"]; e["traced"] += r["traced"]
    out = {"rows": len(counted), **c, **metrics(c),
           "known": [sum(r["Ryu-E"] for r in known), len(known)],
           "unknown": [sum(r["Ryu-E"] for r in unknown), len(unknown)],
           "per_scenario": list(per_scenario.values()), "others": {}}
    comp_path = os.path.join(run_dir, "results", "COMPARISON.json")
    if os.path.isfile(comp_path):
        comp = json.load(open(comp_path, encoding="utf-8")).get("tables", {})
        per = {s["scenario"]: s for s in comp.get("per_scenario", [])}
        for name, m in (comp.get("systems") or {}).items():
            kn = [sum(per[s].get(name, 0) for s in KNOWN if s in per), sum(per[s]["runs"] for s in KNOWN if s in per)]
            un = [sum(per[s].get(name, 0) for s in UNKNOWN if s in per), sum(per[s]["runs"] for s in UNKNOWN if s in per)]
            out["others"][name] = {"kind": m.get("kind"), "TP": m.get("TP"), "FP": m.get("FP"), "FN": m.get("FN"),
                                   "TN": m.get("TN"), "precision": m.get("precision"), "recall": m.get("recall"),
                                   "f1": m.get("f1"), "fpr": m.get("fpr"), "known": kn, "unknown": un}
    return out


def render(report, summ) -> str:
    d, cal, par = report["design"], report["calibration"], report.get("their_protocol") or {}
    lines = ["# Ryu-E: Ryu et al. [17] rebuilt on the comparison run", "",
             f"Host-based detector as published: {d['window']}-call windows of x86-64 call numbers, a decision "
             f"tree trained on labelled examples. Trained on {len(d['baseline_recordings'])} normal-traffic "
             f"recording(s) and the known attacks {', '.join(d['train_attacks'])} "
             f"({len(d['training_attack_runs'])} runs, each scored without itself); labels `{d['labels']}`; "
             f"run rule `{d['trace_rule']}`, threshold {cal['threshold']:.4f} ({cal['how']}: {cal['baseline_shares']}).",
             ""]
    if par.get("windows"):
        lines += [f"**Their protocol** (random 70:30 split of windows, {par['classes']} classes, "
                  f"{par['test_windows']} test windows): accuracy {par['accuracy']:.4f}, weighted precision "
                  f"{par['precision_weighted']:.4f}, recall {par['recall_weighted']:.4f}, F1 {par['f1_weighted']:.4f} "
                  f"(published: accuracy {PUBLISHED['host_accuracy']}, F1 {PUBLISHED['host_f1']}).", ""]
    lines += ["**Our protocol** (trained only on what is known before an attack; every run scored out of sample):",
              "", "| Scenario | Truth | Runs | Ryu-E | traced |", "|---|---|---|---|---|"]
    for e in summ["per_scenario"]:
        lines.append(f"| {e['scenario']} | {e['label']} | {e['runs']} | {e['Ryu-E']}/{e['runs']} | {e['traced']} |")
    lines += ["", "| System | TP | FP | Precision | Recall | F1 | FPR | Known caught | Unknown caught |",
              "|---|---|---|---|---|---|---|---|---|"]
    order = ["PROVBIND", "Falco", "DeSFAM-E", "Confine-E", "Sig-only"]
    for name in order:
        m = summ["others"].get(name)
        if m:
            lines.append(f"| {name} | {_f(m['TP'])} | {_f(m['FP'])} | {_f(m['precision'])} | {_f(m['recall'])} | "
                         f"{_f(m['f1'])} | {_f(m['fpr'])} | {m['known'][0]}/{m['known'][1]} | "
                         f"{m['unknown'][0]}/{m['unknown'][1]} |")
    lines.append(f"| **Ryu-E** (estimated) | {summ['TP']} | {summ['FP']} | {_f(summ['precision'])} | "
                 f"{_f(summ['recall'])} | {_f(summ['f1'])} | {_f(summ['fpr'])} | {summ['known'][0]}/{summ['known'][1]} | "
                 f"{summ['unknown'][0]}/{summ['unknown'][1]} |")
    lines += ["", "Ryu-E is estimated from the published design on recorded traces, not Ryu et al.'s code. The "
              "admission scenarios are not traced, so no trace-based estimator can see them. Their network-flow "
              "detector is left out: our runs did not record flows."]
    if report.get("unknown_syscalls"):
        lines += ["", "Calls missing from the x86-64 table (numbered 1000-1999): " + ", ".join(report["unknown_syscalls"])]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.baselines.ryu_estimate", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"), help="the comparison run folder")
    ap.add_argument("--trace", action="append", default=[], metavar="FILE",
                    help="a scenario trace (repeatable; default: every <run>/traces/<scenario>-<k>.txt)")
    ap.add_argument("--benign", action="append", default=[], metavar="GLOB",
                    help="normal-traffic recordings (default: <run>/traces/baseline/benign-*.txt)")
    ap.add_argument("--train-attacks", default=",".join(DEFAULT_TRAIN),
                    help="comma-separated known attacks to learn from (default: %(default)s)")
    ap.add_argument("--labels", choices=("clean", "run"), default="clean",
                    help="clean: attack windows also seen in normal traffic are not labelled (default); "
                         "run: every window of an attack run is labelled, as in Ryu et al.")
    ap.add_argument("--trace-rule", choices=("fraction", "window", "majority"), default="fraction")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--no-parity", action="store_true", help="skip their 70:30 protocol")
    ap.add_argument("--out", help="the JSON report (default: <run>/results/ryu.json)")
    ap.add_argument("--summary", help="the Markdown summary (default: <run>/results/RYU.md)")
    args = ap.parse_args(argv)

    traces = args.trace or sorted(glob.glob(os.path.join(args.run, "traces", "*.txt")))
    benign = [p for g in (args.benign or [os.path.join(args.run, "traces", "baseline", "benign-*.txt")])
              for p in sorted(glob.glob(g))]
    if not traces:
        print(f"ryu_estimate: no scenario traces under {args.run}/traces", file=sys.stderr)
        return 2
    if not benign:
        print("ryu_estimate: no normal-traffic recordings (traces/baseline/benign-*.txt)", file=sys.stderr)
        return 2
    try:
        report = estimate(traces, benign, tuple(a for a in args.train_attacks.split(",") if a), args.labels,
                          args.trace_rule, args.seed, not args.no_parity)
    except ValueError as e:
        print(f"ryu_estimate: {e}", file=sys.stderr)
        return 2
    summ = summary(args.run, report)
    report["summary"] = {k: v for k, v in summ.items() if k != "per_scenario"}
    out = args.out or os.path.join(args.run, "results", "ryu.json")
    md = args.summary or os.path.join(args.run, "results", "RYU.md")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    Path(out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    text = render(report, summ)
    Path(md).write_text(text, encoding="utf-8")
    print(text)
    print(f"ryu_estimate: wrote {out} and {md}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
