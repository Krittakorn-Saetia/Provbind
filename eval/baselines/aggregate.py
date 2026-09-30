"""Build the comparison tables (docs/COMPARISON-RUN.md): PROVBIND and Falco (measured), Confine-E and DeSFAM-E
(estimated), and a signature-only admission baseline (Sig-only, derived), from one run folder.

    python -m eval.baselines.aggregate --run "$PROVBIND_RUN" \
        --confine run/results/confine.json --desfam run/results/desfam.json [--write]

Inputs:
- the run folder's ground_truth.csv, alerts.jsonl and falco.jsonl, judged per ground-truth row by
  eval.compare (the same "detected" rule as the scoring matrix);
- the two estimators' JSON reports. Their results are keyed by trace file name, which must be
  `<scenario>-<k>.txt`: the k-th trace of a scenario is matched to the k-th ground-truth row of that
  scenario (record_trace.sh output named that way by the orchestration script);
- bindings.json and results/admission-bindings.jsonl, for the Sig-only baseline (below).

Per row and system it records detected / not, and the stage (admission, runtime or trust); then the
confusion matrix and metrics per system (eval.compare.confusion/metrics), the per-scenario counts and
each system's attribution level. Estimated systems are labelled as such everywhere.

Sig-only is the draft's fifth baseline: a plain admission signature/attestation check (the draft's
"signature check at admission only"). A run counts as detected iff a binding for that row's pod was
NOT verified for a signature or attestation reason (an unsigned or tampered artifact). A revoked key
(reason "key: ...") or a missing transparency entry ("v_trans: ...") is a MISS, because a signature
check alone does not see key state -- that is exactly what separates it from PROVBIND's trust loop.
It never sees runtime behaviour or advisories. The controller forgets a deleted pod's binding, so
the admission scripts save each short-lived pod's binding, stamped `snapshot_at`, to
results/admission-bindings.jsonl before tearing it down (deploy_lib.sh snapshot_binding). A saved
binding counts only for the ground-truth row whose window contains its `snapshot_at`; a live
bindings.json record (no stamp) counts for any row with a matching namespace and pod prefix.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

from eval.compare import compare, confusion, load_ground_truth, load_jsonl, metrics, parse_time

SYSTEMS = (("PROVBIND", "measured"), ("Falco", "measured"), ("Confine-E", "estimated"),
           ("DeSFAM-E", "estimated"), ("Sig-only", "derived"))
ATTRIBUTION = {"PROVBIND": 3, "Falco": 1, "Confine-E": 0, "DeSFAM-E": 1, "Sig-only": 0}
TRACE_NAME = re.compile(r"^(?P<scenario>.+)-(?P<k>\d+)\.txt$")


def _estimates(path):
    """{(scenario, k): result} from an estimator JSON report, or {} when absent."""
    if not path or not os.path.isfile(path):
        return {}
    out = {}
    for name, res in (json.load(open(path, encoding="utf-8")).get("results") or {}).items():
        m = TRACE_NAME.match(name)
        if m:
            out[(m["scenario"], int(m["k"]))] = res
    return out


def _provbind_stage(row):
    classes = " ".join(row.get("provbind_classes") or [])
    if "binding" in classes:
        return "admission"
    if "trust" in classes:
        return "trust"
    return "runtime" if row.get("provbind_detected") else None


def _load_bindings(run):
    """Binding records: the live bindings.json plus the saved copies in results/admission-bindings.jsonl
    (each stamped `snapshot_at`). Missing or unreadable files give no records."""
    out = []
    try:
        b = json.load(open(os.path.join(run, "bindings.json"), encoding="utf-8"))
        out += list(b.values()) if isinstance(b, dict) else (b if isinstance(b, list) else [])
    except (OSError, ValueError):
        pass
    return out + [r for r in load_jsonl(os.path.join(run, "results", "admission-bindings.jsonl"))
                  if isinstance(r, dict)]


def _sig_only_detects(gt_row, bindings):
    """A signature-only admission check detects this row iff a matching binding failed verification for
    a signature/attestation reason. Key-revocation ("key: ...") and missing-transparency ("v_trans:
    ...") failures are misses: a signature check does not see them."""
    ns, prefix = gt_row.get("namespace", ""), gt_row.get("pod_prefix", "")
    if not prefix:
        return False
    start, end = parse_time(gt_row.get("start")), parse_time(gt_row.get("end"))
    for b in bindings:
        if b.get("namespace") != ns or not str(b.get("pod", "")).startswith(prefix):
            continue
        if "snapshot_at" in b:          # a saved copy belongs to the run whose window it was taken in
            t = parse_time(b["snapshot_at"])
            if t is None or start is None or end is None or not start <= t <= end:
                continue
        if b.get("verified"):
            continue
        reason = (b.get("reason") or "").strip().lower()
        if reason.startswith("key:") or reason.startswith("v_trans:"):
            continue        # revoked key / no transparency entry: a signature check passes here
        return True         # unsigned or tampered artifact: the signature/attestation check fails
    return False


def rows_for(run, confine_json=None, desfam_json=None):
    gt = load_ground_truth(os.path.join(run, "ground_truth.csv"))
    base = compare(gt, load_jsonl(os.path.join(run, "alerts.jsonl")), load_jsonl(os.path.join(run, "falco.jsonl")))
    confine, desfam = _estimates(confine_json), _estimates(desfam_json)
    bindings = _load_bindings(run)
    seen: dict[str, int] = {}
    rows = []
    for gt_row, r in zip(gt, base):
        k = seen[r["scenario"]] = seen.get(r["scenario"], 0) + 1
        c, d = confine.get((r["scenario"], k)), desfam.get((r["scenario"], k))
        sig = _sig_only_detects(gt_row, bindings)
        rows.append({
            "scenario": r["scenario"], "label": r["label"], "run": k,
            "PROVBIND": bool(r["provbind_detected"]), "PROVBIND_stage": _provbind_stage(r),
            "Falco": bool(r["falco_detected"]), "Falco_stage": "runtime" if r["falco_detected"] else None,
            "Confine-E": bool(c and c.get("blocked")), "Confine-E_stage": "runtime" if c and c.get("blocked") else None,
            "DeSFAM-E": bool(d and d.get("detected")), "DeSFAM-E_stage": "runtime" if d and d.get("detected") else None,
            "Sig-only": sig, "Sig-only_stage": "admission" if sig else None,
            "estimated_input": {"Confine-E": c is not None, "DeSFAM-E": d is not None},
        })
    return rows


def tables(rows):
    counted = [r for r in rows if r["label"] in ("malicious", "benign") and r["scenario"] != "tamper-1"]
    per_scenario = {}
    for r in rows:
        s = per_scenario.setdefault(r["scenario"], {"scenario": r["scenario"], "label": r["label"], "runs": 0,
                                                    **{n: 0 for n, _ in SYSTEMS}})
        s["runs"] += 1
        for n, _ in SYSTEMS:
            s[n] += r[n]
    systems = {n: {"kind": kind, "attribution_level": ATTRIBUTION[n],
                   **confusion(counted, n), **metrics(confusion(counted, n))} for n, kind in SYSTEMS}
    return {"per_scenario": list(per_scenario.values()), "systems": systems, "runs": len(counted)}


def render(t):
    names = [n for n, _ in SYSTEMS]
    lines = ["| Scenario | Truth | Runs | " + " | ".join(names) + " |", "|---|---|---|" + "---|" * len(names)]
    for s in t["per_scenario"]:
        lines.append(f"| {s['scenario']} | {s['label']} | {s['runs']} | "
                     + " | ".join(f"{s[n]}/{s['runs']}" for n in names) + " |")
    lines += ["", "| System | Kind | TP | FP | FN | TN | Precision | Recall | F1 | FPR | Attribution |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
    for n in names:
        m = t["systems"][n]
        f = lambda v: "—" if v is None else (f"{v:.2f}" if isinstance(v, float) else str(v))  # noqa: E731
        lines.append(f"| {n} | {m['kind']} | {m['TP']} | {m['FP']} | {m['FN']} | {m['TN']} | {f(m['precision'])} | "
                     f"{f(m['recall'])} | {f(m['f1'])} | {f(m['fpr'])} | {m['attribution_level']} |")
    lines += ["", "Confine-E and DeSFAM-E are estimated from published designs applied to recorded traces, not "
              "measured. Sig-only is a signature/attestation check at admission (derived from bindings.json): it "
              "catches unsigned or tampered artifacts but not revoked keys, advisories or runtime behaviour."]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.baselines.aggregate", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"))
    ap.add_argument("--confine", help="Confine-E JSON report")
    ap.add_argument("--desfam", help="DeSFAM-E JSON report")
    ap.add_argument("--write", action="store_true", help="write results/COMPARISON.md and .json")
    args = ap.parse_args(argv)
    rows = rows_for(args.run, args.confine, args.desfam)
    if not rows:
        print("aggregate: no ground-truth rows", file=sys.stderr)
        return 1
    t = tables(rows)
    text = render(t)
    print(text)
    if args.write:
        d = os.path.join(args.run, "results")
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "COMPARISON.md"), "w", encoding="utf-8").write("# System comparison\n\n" + text + "\n")
        json.dump({"rows": rows, "tables": t}, open(os.path.join(d, "COMPARISON.json"), "w", encoding="utf-8"), indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
