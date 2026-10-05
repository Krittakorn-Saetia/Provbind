"""Check that the comparison's "unknown" (zero-day) attacks really were unknown to every detector.

The recognised way to evaluate zero-day detection without real zero-days is to make sure the test
attacks were never seen when the detector was built (normal-only training, as in ADFA-LD and LID-DS),
and to report any leakage. This script runs those checks on a finished comparison run folder:

    python -m eval.zero_day_check --run run --mlb-data ml/data/mlb/<hex> --egress testbed/egress.json

| Check | Passes when |
|---|---|
| Z1 specification first | the demo image's envelope was compiled before the first scenario run started |
| Z2 artefacts undeclared | each unknown attack's artefact is absent from the specification: /tmp/.x9 (attack-1), /tmp/.cache (attack-2), /tmp/.inj.so (rk-3) in no image file; 203.0.113.9 (ru-3) outside the egress allow list; /usr/local/bin/helperd (au-2) owned by no package |
| Z3 ML-B never saw an attack | every ML-B training and validation window ended before the first scenario run, and none overlaps an attack row |
| Z4 ML-B model first | the ML-B model file was written before the first scenario run |
| Z5 DeSFAM baseline first | the benign baseline traces were written before the first scenario run |
| Z6 no advisory for unknown attacks | no advisory in the run folder names anything but the known-trust test package |
| Z7 Falco unchanged | Falco runs its default rules: no custom rules in its Helm values (needs helm; skipped otherwise) |

Writes ZERODAY.md and ZERODAY.json into <run>/results and prints the table. Exit 0 when nothing failed.
"""
from __future__ import annotations

import argparse
import glob
import ipaddress
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from eval.compare import load_ground_truth, parse_time

UNKNOWN = ("au-2", "attack-1", "attack-2", "ru-3", "ru-4", "ru-5")
KNOWN_TRUST_PACKAGE = "requestz-helper"            # the package trust-1 / ak-1 put an advisory on


def _mtime(path) -> datetime | None:
    try:
        return datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc)
    except OSError:
        return None


def _envelopes(run: Path):
    out = []
    for p in sorted((run / "envelopes").glob("*.json")):
        try:
            out.append((p, json.loads(p.read_text(encoding="utf-8"))))
        except (OSError, ValueError):
            pass
    return out


def _row(check, status, detail):
    return {"check": check, "status": status, "detail": detail}


def run_checks(run: Path, mlb_data: Path | None, egress: Path | None, helm=True, digest: str = "") -> list[dict]:
    gt = load_ground_truth(run / "ground_truth.csv")
    starts = [parse_time(g.get("start")) for g in gt if g.get("start")]
    starts = [s for s in starts if s]
    first = min(starts) if starts else None
    attacks = [(parse_time(g.get("start")), parse_time(g.get("end"))) for g in gt if g.get("label") == "malicious"]
    rows = []
    envs = _envelopes(run)

    # Z1: the demo image's envelope was compiled before the first scenario run (the admission scenarios
    # build a new image each round, so their envelopes are compiled during the run, as the test intends)
    if not envs or first is None:
        rows.append(_row("Z1 specification first", "skip", "no envelope or no ground truth in the run folder"))
    else:
        demo = [(p, e) for p, e in envs if not digest or p.stem == digest]
        times = [(parse_time(e.get("compiled_at")), p.name) for p, e in demo if parse_time(e.get("compiled_at"))]
        ok = bool(times) and min(t for t, _ in times) < first
        during = sum(1 for p, e in envs if parse_time(e.get("compiled_at")) and parse_time(e["compiled_at"]) > first)
        rows.append(_row("Z1 specification first", "pass" if ok else "fail",
                         (f"demo envelope compiled {min(times)[0]:%Y-%m-%d %H:%M:%S}Z, " if times else "demo envelope not found, ")
                         + f"first scenario {first:%Y-%m-%d %H:%M:%S}Z; {during} admission-test envelopes compiled during the run"))

    # Z2: unknown attacks' artefacts are not in the specification
    if envs:
        files_all = {}
        for _, e in envs:
            files_all.update(e.get("files") or {})
        issues = []
        for path, scen in (("/tmp/.x9", "attack-1"), ("/tmp/.inj.so", "rk-3")):
            if path in files_all:
                issues.append(f"{path} ({scen}) is declared")
        if any(p.startswith("/tmp/.cache/") for p in files_all):
            issues.append("/tmp/.cache files (attack-2) are declared")
        helperd = [e["files"]["/usr/local/bin/helperd"] for _, e in envs if "/usr/local/bin/helperd" in (e.get("files") or {})]
        if any(h.get("package") for h in helperd):
            issues.append("/usr/local/bin/helperd (au-2) is owned by a package")
        if egress and egress.exists():
            allow = [ipaddress.ip_network(c) for c in json.loads(egress.read_text()).get("allow", [])]
            if any(ipaddress.ip_address("203.0.113.9") in n for n in allow):
                issues.append("203.0.113.9 (ru-3) is inside the egress allow list")
        rows.append(_row("Z2 artefacts undeclared", "pass" if not issues else "fail",
                         "; ".join(issues) or "/tmp/.x9, /tmp/.cache, /tmp/.inj.so in no image file; 203.0.113.9 outside "
                         "the egress list; " + ("helperd owned by no package" if helperd else "au-2 envelope not found")))

    # Z3 / Z4: ML-B
    if mlb_data and mlb_data.exists() and first is not None:
        n, after, overlap = 0, 0, 0
        for name in ("train.jsonl", "validation.jsonl"):
            p = mlb_data / name
            if not p.exists():
                continue
            for line in p.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                w = json.loads(line)
                s, e = parse_time(w.get("start")), parse_time(w.get("end"))
                n += 1
                if e and e > first:
                    after += 1
                if s and e and any(a0 and a1 and s < a1 and e > a0 for a0, a1 in attacks):
                    overlap += 1
        rows.append(_row("Z3 ML-B never saw an attack", "pass" if n and not after and not overlap else "fail",
                         f"{n} training/validation windows; {after} end after the first scenario; {overlap} overlap an attack row"))
        hexd = mlb_data.name
        model = run / "envelopes" / f"{hexd}.mlb" / "model.json"
        m = _mtime(model)
        rows.append(_row("Z4 ML-B model first", "skip" if m is None else ("pass" if m < first else "fail"),
                         "no model file" if m is None else f"model written {m:%Y-%m-%d %H:%M:%S}Z"))
    else:
        rows.append(_row("Z3 ML-B never saw an attack", "skip", "no ML-B data folder or no ground truth"))

    # Z5: DeSFAM baseline before the scenarios
    base = sorted(glob.glob(str(run / "traces" / "baseline" / "benign-*.txt")))
    if base and first is not None:
        late = [os.path.basename(b) for b in base if (_mtime(b) or first) > first]
        rows.append(_row("Z5 DeSFAM baseline first", "pass" if not late else "fail",
                         f"{len(base)} baseline traces" + (f"; written after the first scenario: {late}" if late else "")))
    else:
        rows.append(_row("Z5 DeSFAM baseline first", "skip", "no baseline traces"))

    # Z6: advisories name only the known-trust package
    advs = sorted(glob.glob(str(run / "advisories" / "*.json")))
    other = []
    for a in advs:
        try:
            doc = json.loads(Path(a).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for aff in doc.get("affected", []):
            name = (aff.get("package") or {}).get("name", "")
            if name and name != KNOWN_TRUST_PACKAGE:
                other.append(name)
    rows.append(_row("Z6 no advisory for unknown attacks", "pass" if not other else "fail",
                     f"{len(advs)} advisory files; names other than {KNOWN_TRUST_PACKAGE}: {sorted(set(other)) or 'none'}"))

    # Z7: Falco default rules
    if helm:
        try:
            out = subprocess.run(["helm", "get", "values", "falco", "-n", "falco", "-o", "json"],
                                 capture_output=True, text=True, timeout=30)
            vals = json.loads(out.stdout or "{}") if out.returncode == 0 else None
        except (OSError, ValueError, subprocess.TimeoutExpired):
            vals = None
        if vals is None:
            rows.append(_row("Z7 Falco unchanged", "skip", "helm not available or Falco release not found"))
        else:
            custom = vals.get("customRules") or (vals.get("falco") or {}).get("rules_files")
            rows.append(_row("Z7 Falco unchanged", "pass" if not custom else "fail",
                             "default rules (no customRules in the Helm values)" if not custom else f"custom rules: {custom}"))
    return rows


def render(rows) -> str:
    out = ["# Zero-day validity checks", "", "| Check | Result | Detail |", "|---|---|---|"]
    for r in rows:
        out.append(f"| {r['check']} | {r['status']} | {r['detail']} |")
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.zero_day_check", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"))
    ap.add_argument("--mlb-data", help="ml/data/mlb/<hex> of the demo image")
    ap.add_argument("--egress", default="testbed/egress.json")
    ap.add_argument("--digest", default="", help="the demo image's sha256 hex (default: the --mlb-data folder name)")
    ap.add_argument("--no-helm", action="store_true")
    args = ap.parse_args(argv)
    run = Path(args.run)
    digest = args.digest or (Path(args.mlb_data).name if args.mlb_data else "")
    rows = run_checks(run, Path(args.mlb_data) if args.mlb_data else None, Path(args.egress), not args.no_helm, digest)
    text = render(rows)
    (run / "results").mkdir(parents=True, exist_ok=True)
    (run / "results" / "ZERODAY.md").write_text(text, encoding="utf-8")
    (run / "results" / "ZERODAY.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(text)
    return 1 if any(r["status"] == "fail" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
