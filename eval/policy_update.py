"""Her et al.'s policy enforcement benchmark [F] for PROVBIND and Falco (scripts/policy-update-test.sh):
how long a new policy takes to act.

    python -m eval.policy_update falco-row --rep 3 --seconds 17.4 --out rows.jsonl
    python -m eval.policy_update provbind-row --rep 3 --summary node-summary.json --ready-s 9.8 --out rows.jsonl
    python -m eval.policy_update report --rows rows.jsonl --out DIR      # DIR/POLICY-UPDATE.md and .json

- Falco, measured as Her et al. measure it: from `helm upgrade` with one new rule until that rule's
  first alert, while a loop in the demo pod runs the program the rule names every millisecond. Falco
  restarts its pods to load the rule.
- PROVBIND: a new workload's policy is its envelope, compiled from the signed evidence when the pod is
  admitted. `seconds` is the cold-start window the node measures (node.run --summary, cold_start_s): from
  the new pod's first event, which the node holds, until the envelope is in force and the held events are
  checked. `ready_s` is the time from scaling the app up to `envelope_ready`, which also counts the pod's
  own start. `lost` held events would mean the window hid something; it should be 0.

Her et al.'s published numbers (Section V-C, 10 runs each, one Xeon node) are shown beside ours.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

# Her et al. [F], IEEE Access 13 (2025), Section V-C, Figure 6: average policy enforcement time (s).
HER_ET_AL = {"KubeArmor": 0.52, "Tetragon": 4.38, "Tracee": 11.84, "Falco": 18.15}


def node_window(summary: dict) -> dict:
    """The longest cold-start window in a node summary, and its held / released / lost event counts."""
    windows = summary.get("cold_start_s") or {}
    held = summary.get("held") or {}
    return {"seconds": max(windows.values()) if windows else None, "containers": len(windows),
            "held": held.get("held", 0), "released": held.get("released", 0), "lost": held.get("lost", 0)}


def append(path: str, row: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")


def load(path) -> list[dict]:
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
    return rows


def stats(values) -> dict:
    vals = [v for v in values if isinstance(v, (int, float))]
    if not vals:
        return {"n": 0, "median": None, "min": None, "max": None}
    return {"n": len(vals), "median": round(statistics.median(vals), 3), "min": round(min(vals), 3),
            "max": round(max(vals), 3)}


def build(rows) -> dict:
    falco = [r for r in rows if r.get("system") == "falco"]
    prov = [r for r in rows if r.get("system") == "provbind"]
    return {"falco": {**stats(r.get("seconds") for r in falco),
                      "timeouts": sum(1 for r in falco if r.get("seconds") is None)},
            "provbind": {**stats(r.get("seconds") for r in prov),
                         "ready_s": stats(r.get("ready_s") for r in prov),
                         "lost": sum(r.get("lost") or 0 for r in prov),
                         "no_window": sum(1 for r in prov if r.get("seconds") is None)},
            "her_et_al": HER_ET_AL, "rows": rows}


def _f(v, unit=" s"):
    return "—" if v is None else f"{v:.2f}{unit}"


def render(doc) -> str:
    f, p = doc["falco"], doc["provbind"]
    lines = ["# Time for a new policy to act (Her et al.'s policy enforcement benchmark)", "",
             "| System | Our VM: median (min – max) | Runs | Her et al. (average of 10) |", "|---|---|---|---|"]
    lines.append(f"| PROVBIND (new pod's envelope in force) | {_f(p['median'])} ({_f(p['min'])} – {_f(p['max'])}) | "
                 f"{p['n']} | — |")
    lines.append(f"| Falco (rule added, Falco restarted) | {_f(f['median'])} ({_f(f['min'])} – {_f(f['max'])}) | "
                 f"{f['n']} | {_f(HER_ET_AL['Falco'])} |")
    for name in ("Tetragon", "Tracee", "KubeArmor"):
        lines.append(f"| {name} | — | — | {_f(HER_ET_AL[name])} |")
    r = p["ready_s"]
    lines += ["", f"PROVBIND, from scaling the app up to `envelope_ready` (includes the pod's own start): median "
                  f"{_f(r['median'])} ({_f(r['min'])} – {_f(r['max'])}), {r['n']} runs. Held events lost: {p['lost']} "
                  "(the node holds a new pod's events until its envelope is in force, then checks them)."]
    if f.get("timeouts"):
        lines.append(f"Falco runs that timed out before the rule fired: {f['timeouts']}.")
    if p.get("no_window"):
        lines.append(f"PROVBIND runs with no cold-start window (the envelope was ready before the first event): "
                     f"{p['no_window']}.")
    lines += ["", "Falco loads a new rule by restarting its pods and sees nothing while they restart, the blind spot "
              "Her et al. point out. Times depend on the hardware: compare Her et al.'s Falco with ours first."]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.policy_update", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    fr = sub.add_parser("falco-row")
    fr.add_argument("--rep", type=int, required=True)
    fr.add_argument("--seconds", help="seconds until the rule fired; empty or 'timeout' for none")
    fr.add_argument("--out", required=True)
    pr = sub.add_parser("provbind-row")
    pr.add_argument("--rep", type=int, required=True)
    pr.add_argument("--summary", required=True, help="the node's --summary JSON")
    pr.add_argument("--ready-s", help="seconds from scaling up to envelope_ready")
    pr.add_argument("--out", required=True)
    rp = sub.add_parser("report")
    rp.add_argument("--rows", required=True)
    rp.add_argument("--out", required=True, help="folder for POLICY-UPDATE.md and .json")
    args = ap.parse_args(argv)

    def num(v):
        try:
            return round(float(v), 3)
        except (TypeError, ValueError):
            return None

    if args.cmd == "falco-row":
        row = {"system": "falco", "rep": args.rep, "seconds": num(args.seconds)}
        append(args.out, row)
        print(json.dumps(row))
    elif args.cmd == "provbind-row":
        try:
            summary = json.loads(Path(args.summary).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            summary = {}
        row = {"system": "provbind", "rep": args.rep, **node_window(summary), "ready_s": num(args.ready_s)}
        append(args.out, row)
        print(json.dumps(row))
    else:
        rows = load(args.rows)
        if not rows:
            print(f"policy_update: no rows in {args.rows}", file=sys.stderr)
            return 1
        doc = build(rows)
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "POLICY-UPDATE.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
        text = render(doc)
        (out / "POLICY-UPDATE.md").write_text(text, encoding="utf-8")
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
