"""Compare PROVBIND alerts and Falco lines against the ground truth (Role 1).

    python -m eval.compare --run $PROVBIND_RUN            # the table, then the scoring matrix
    python -m eval.compare --run $PROVBIND_RUN --write    # also results/SCORING.md and SCORING.json
    python -m eval.compare --run $PROVBIND_RUN --json     # machine-readable rows
    python -m eval.compare --run $PROVBIND_RUN --matrix-json   # machine-readable scoring matrix

Sprint Handoff §5 (Day 3): "matches alerts and Falco lines to ground-truth rows by pod and
time window, and prints one row per scenario: the truth, PROVBIND's alerts with their highest
bucket, and Falco's rules with their priority." This is the evidence for EV-01 (detection per
scenario, PROVBIND vs Falco) and EV-02 (false positives on the benign catalogue).

Inputs, all in the run folder (Sprint Handoff §3.2):
- `ground_truth.csv`  scenario,label,namespace,pod_prefix,start,end,expected   (Role 1)
- `alerts.jsonl`      one alert per line (Sprint Handoff §4.5)                  (Role 4)
- `falco.jsonl`       Falco JSON output, one event per line                    (Role 1)

A ground-truth row owns every alert/Falco line whose pod is in its namespace, whose pod name
starts with its `pod_prefix`, and whose time is inside [start, end]. A scenario runs several
times (Test Plan §12.2, dataset D4), so there is one row per run and windows do not overlap.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import sys

# Most-severe first. PROVBIND buckets (Sprint Handoff scoring rules) and Falco priorities
# (falco: syslog levels). Comparisons use the index; unknown values sort last.
BUCKET_ORDER = ("critical", "high", "medium", "low")
FALCO_PRIORITY_ORDER = ("emergency", "alert", "critical", "error", "warning",
                        "notice", "informational", "info", "debug")


def parse_time(value):
    """Parse an ISO-8601 UTC timestamp into an aware datetime.

    Accepts a trailing 'Z', an explicit offset, and fractional seconds of any precision
    (Falco prints nanoseconds; Python keeps microseconds, so extra digits are dropped).
    Returns None when the value is missing or unparseable, so one bad line never aborts a run.
    """
    if not value:
        return None
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Trim fractional seconds to 6 digits: 2026-09-28T10:14:22.123456789+00:00 -> .123456
    if "." in s:
        head, _, tail = s.partition(".")
        frac = ""
        for ch in tail:
            if ch.isdigit():
                frac += ch
            else:
                tail = tail[len(frac):]
                break
        else:
            tail = ""
        s = head + "." + frac[:6] + tail
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def load_jsonl(path):
    """Read a JSON-lines file into a list of dicts. A missing file is an empty list; a bad
    line is skipped with a note on stderr rather than aborting the comparison."""
    out = []
    if not path or not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError as e:
                print(f"compare: skipping {path}:{n}: {e}", file=sys.stderr)
    return out


def load_ground_truth(path):
    rows = []
    if not path or not os.path.isfile(path):
        return rows
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("scenario"):
                rows.append(row)
    return rows


def alert_pod(alert):
    """(namespace, pod) for an alert. `container` is "namespace/pod/container" (§4.5); fall
    back to explicit fields if a producer adds them."""
    container = alert.get("container", "")
    parts = container.split("/") if container else []
    ns = alert.get("namespace") or (parts[0] if len(parts) >= 1 else "")
    pod = alert.get("pod") or (parts[1] if len(parts) >= 2 else "")
    return ns, pod


def falco_pod(line):
    f = line.get("output_fields", {}) or {}
    return f.get("k8s.ns.name", "") or "", f.get("k8s.pod.name", "") or ""


def _in_window(t, start, end):
    return t is not None and start is not None and end is not None and start <= t <= end


def _rank(value, order):
    v = (value or "").strip().lower()
    return order.index(v) if v in order else len(order)


def _matches(gt, ns, pod):
    return ns == gt.get("namespace", "") and pod.startswith(gt.get("pod_prefix", "")) \
        and bool(gt.get("pod_prefix", ""))


def compare(ground_truth, alerts, falco):
    """One result row per ground-truth row. Each row is plain data so tests and the CLI share it."""
    rows = []
    for gt in ground_truth:
        start, end = parse_time(gt.get("start")), parse_time(gt.get("end"))

        my_alerts = [a for a in alerts
                     if _matches(gt, *alert_pod(a)) and _in_window(parse_time(a.get("time")), start, end)]
        falco_hits = [l for l in falco
                      if _matches(gt, *falco_pod(l)) and _in_window(parse_time(l.get("time")), start, end)]

        classes = []
        for a in my_alerts:
            label = a.get("class", "?")
            if a.get("subclass"):
                label += "/" + a["subclass"]
            if label not in classes:
                classes.append(label)
        buckets = [a.get("bucket", "") for a in my_alerts]
        buckets_no_dcap = [a.get("bucket", "") for a in my_alerts if a.get("class") != "D_cap"]
        top_bucket = min(buckets, key=lambda b: _rank(b, BUCKET_ORDER)).lower() if buckets else ""

        rules = []
        for l in falco_hits:
            r = l.get("rule", "?")
            if r not in rules:
                rules.append(r)
        prios = [l.get("priority", "") for l in falco_hits]
        top_prio = min(prios, key=lambda p: _rank(p, FALCO_PRIORITY_ORDER)).lower() if prios else ""

        rows.append({
            "scenario": gt.get("scenario", ""),
            "label": gt.get("label", ""),
            "expected": gt.get("expected", ""),
            "provbind_alerts": len(my_alerts),
            "provbind_classes": classes,
            "provbind_top_bucket": top_bucket,
            # "detected" for the comparison table means an alert above the benign floor (Low).
            "provbind_detected": any(_rank(b, BUCKET_ORDER) < BUCKET_ORDER.index("low") for b in buckets),
            # The same, ignoring D_cap: an ablation for runs whose envelope has no ML-A capabilities.
            "provbind_detected_no_dcap": any(_rank(b, BUCKET_ORDER) < BUCKET_ORDER.index("low")
                                             for b in buckets_no_dcap),
            "provbind_alerted": bool(my_alerts),
            "falco_hits": len(falco_hits),
            "falco_rules": rules,
            "falco_top_priority": top_prio,
            "falco_detected": bool(falco_hits),
        })
    return rows


def render_table(rows):
    def cell_pb(r):
        if not r["provbind_alerts"]:
            return "—"
        b = f" ({r['provbind_top_bucket'].title()})" if r["provbind_top_bucket"] else ""
        return ", ".join(r["provbind_classes"]) + b

    def cell_falco(r):
        if not r["falco_hits"]:
            return "—"
        p = f" ({r['falco_top_priority'].title()})" if r["falco_top_priority"] else ""
        return ", ".join(r["falco_rules"]) + p

    header = ["Scenario", "Truth", "Expected", "PROVBIND", "Falco"]
    table = [header] + [[r["scenario"], r["label"], r["expected"], cell_pb(r), cell_falco(r)] for r in rows]
    widths = [max(len(str(row[i])) for row in table) for i in range(len(header))]
    out = []
    for i, row in enumerate(table):
        out.append(" | ".join(str(c).ljust(widths[j]) for j, c in enumerate(row)))
        if i == 0:
            out.append("-+-".join("-" * w for w in widths))
    return "\n".join(out)


# --- Scoring matrix (EV-01, EV-02; the metrics EV-04 names) -----------------------------------------
#
# Every ground-truth row is one run, judged per system: a malicious run the system detected is a TP,
# one it missed an FN; a benign run it alerted on is an FP, one it stayed quiet on a TN. "Detected"
# is the table's rule: PROVBIND raised an alert above Low (trust alerts are High), Falco fired any rule.
#
# Two scopes, because Falco watches runtime behaviour only and has no notion of supply-chain trust:
# - "all": every detection scenario;
# - "runtime": the trust-* scenarios left out, for a like-for-like PROVBIND vs Falco comparison.
# tamper-1 is an integrity check of the violation log (E2E-12), not a detection case, so it is listed
# but never counted.

# "PROVBIND w/o D_cap" is an ablation, never the headline: without ML-A profiling the envelope lists no
# capabilities, so every capability the app uses is a D_cap (ROLE1-READINESS §3), benign runs included.
SYSTEMS = (("PROVBIND", "provbind_detected"), ("PROVBIND w/o D_cap", "provbind_detected_no_dcap"),
           ("Falco", "falco_detected"))
NON_DETECTION_SCENARIOS = frozenset({"tamper-1"})
MIN_RUNS = 3                                    # Test Plan §12.2, dataset D4


def _ratio(num, den):
    return round(num / den, 4) if den else None


def confusion(rows, field):
    """TP, FP, FN and TN for one system over ground-truth rows (runs)."""
    c = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for r in rows:
        malicious, hit = r.get("label") == "malicious", bool(r.get(field))
        c[("TP" if hit else "FN") if malicious else ("FP" if hit else "TN")] += 1
    return c


def metrics(c):
    """Precision, recall, F1, false-positive rate and accuracy; None where a denominator is 0."""
    tp, fp, fn, tn = c["TP"], c["FP"], c["FN"], c["TN"]
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = (round(2 * precision * recall / (precision + recall), 4)
          if precision is not None and recall is not None and precision + recall else None)
    return {"precision": precision, "recall": recall, "f1": f1,
            "fpr": _ratio(fp, fp + tn), "accuracy": _ratio(tp + tn, tp + fp + fn + tn)}


def scoring_matrix(rows):
    """The per-scenario summary and the per-system confusion matrix and metrics, as plain data."""
    counted = [r for r in rows if r.get("scenario") not in NON_DETECTION_SCENARIOS
               and r.get("label") in ("malicious", "benign")]
    scopes = {"all": counted,
              "runtime": [r for r in counted if not str(r.get("scenario", "")).startswith("trust-")]}

    per_scenario = {}
    for r in rows:
        s = per_scenario.setdefault(r.get("scenario", ""), {
            "scenario": r.get("scenario", ""), "label": r.get("label", ""), "runs": 0,
            "counted": r.get("scenario") not in NON_DETECTION_SCENARIOS,
            **{name: 0 for name, _ in SYSTEMS}})
        s["runs"] += 1
        for name, field in SYSTEMS:
            s[name] += bool(r.get(field))

    out = {"scopes": {}, "per_scenario": list(per_scenario.values()),
           "too_few_runs": sorted(s["scenario"] for s in per_scenario.values() if s["runs"] < MIN_RUNS)}
    for scope, subset in scopes.items():
        mal = sum(r["label"] == "malicious" for r in subset)
        out["scopes"][scope] = {
            "runs": len(subset), "malicious": mal, "benign": len(subset) - mal,
            "systems": {name: {**confusion(subset, field), **metrics(confusion(subset, field))}
                        for name, field in SYSTEMS}}
    return out


def _fmt(v):
    return "—" if v is None else f"{v:.2f}" if isinstance(v, float) else str(v)


def _grid(header, body):
    widths = [max(len(str(x)) for x in col) for col in zip(header, *body)]
    lines = [" | ".join(str(c).ljust(w) for c, w in zip(header, widths)),
             "-+-".join("-" * w for w in widths)]
    lines += [" | ".join(str(c).ljust(w) for c, w in zip(row, widths)) for row in body]
    return "\n".join(lines)


def render_matrix(m):
    names = [name for name, _ in SYSTEMS]
    parts = ["Scoring matrix", "",
             _grid(["Scenario", "Truth", "Runs"] + [f"{n} detected" for n in names],
                   [[s["scenario"] + ("" if s["counted"] else " (not counted)"), s["label"], s["runs"]]
                    + [f"{s[n]}/{s['runs']}" for n in names] for s in m["per_scenario"]])]
    for scope, title in (("all", "All detection scenarios"),
                         ("runtime", "Runtime scenarios only (trust-* left out: Falco has no trust check)")):
        sc = m["scopes"][scope]
        parts += ["", f"{title}: {sc['runs']} runs, {sc['malicious']} malicious / {sc['benign']} benign",
                  _grid(["System", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1", "FPR", "Accuracy"],
                        [[n] + [_fmt(sc["systems"][n][k]) for k in
                                ("TP", "FP", "FN", "TN", "precision", "recall", "f1", "fpr", "accuracy")]
                         for n in names])]
        if sc["runs"] and sc["malicious"] != sc["benign"]:
            parts.append(f"note: unbalanced ({sc['malicious']} malicious vs {sc['benign']} benign runs); "
                         "accuracy favours the larger class")
    if m["too_few_runs"]:
        parts += ["", f"note: fewer than {MIN_RUNS} runs (Test Plan §12.2, D4): " + ", ".join(m["too_few_runs"])]
    parts += ["", "Detected = PROVBIND alert above Low / any Falco rule. tamper-1 checks the log, not detection.",
              "PROVBIND w/o D_cap = the same alerts minus D_cap: an ablation for envelopes without ML-A "
              "capabilities; PROVBIND is the headline."]
    return "\n".join(parts)


def write_scoring(run, rows, m):
    """Write results/SCORING.md and results/SCORING.json beside REPORT.md; return their paths."""
    d = os.path.join(run, "results")
    os.makedirs(d, exist_ok=True)
    md, js = os.path.join(d, "SCORING.md"), os.path.join(d, "SCORING.json")
    with open(md, "w", encoding="utf-8") as f:
        f.write("# PROVBIND scoring matrix\n\n```\n" + render_table(rows) + "\n\n" + render_matrix(m) + "\n```\n")
    with open(js, "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "matrix": m}, f, indent=2)
    return md, js


def main(argv=None):
    ap = argparse.ArgumentParser(description="PROVBIND vs Falco vs ground truth")
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"))
    ap.add_argument("--json", action="store_true", help="print the rows as JSON")
    ap.add_argument("--matrix-json", action="store_true", help="print the scoring matrix as JSON")
    ap.add_argument("--write", action="store_true",
                    help="also write results/SCORING.md and results/SCORING.json in the run folder")
    args = ap.parse_args(argv)

    gt = load_ground_truth(os.path.join(args.run, "ground_truth.csv"))
    alerts = load_jsonl(os.path.join(args.run, "alerts.jsonl"))
    falco = load_jsonl(os.path.join(args.run, "falco.jsonl"))
    rows = compare(gt, alerts, falco)

    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("compare: no ground-truth rows in "
              f"{os.path.join(args.run, 'ground_truth.csv')}", file=sys.stderr)
        return 1
    m = scoring_matrix(rows)
    if args.matrix_json:
        print(json.dumps(m, indent=2))
    else:
        print(render_table(rows))
        print()
        print(render_matrix(m))
    if args.write:
        for path in write_scoring(args.run, rows, m):
            print(f"compare: wrote {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
