"""Helpers for scripts/live-demo.sh: counts and short summaries read from the run folder.

    python -m eval.live_demo count    --run R [--cls D_exec] [--sub undeclared] [--low | --alerts]
    python -m eval.live_demo envelope --run R [--pod-prefix demo-app]          # envelope act
    python -m eval.live_demo since    --run R --since N   # the alerts after the first N (attack act)
    python -m eval.live_demo incident --run R                                  # attack-1's two alerts
    python -m eval.live_demo trust    --run R                                  # trust act
    python -m eval.live_demo binding  --run R --pod-prefix demo-app-unsigned   # unsigned act
    python -m eval.live_demo falco    --run R --since N   # Falco's alerts after line N of falco.jsonl
    python -m eval.live_demo lines    --file F            # number of lines, 0 when F does not exist
    python -m eval.live_demo advisory --run R --id MAL-2026-9001 --ecosystem PyPI --package requestz-helper \
                                      [--pkg-version 0.1.0]  # write the trust act's advisory; prints its path

Prints plain text for the presenter's terminal (docs/LIVE-DEMO.md). Every command but `advisory` only
reads. A summary whose data is not there yet prints one line saying so; every command exits 0, so the
demo goes on.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

from eval.demo_view import clause_parts, title_of

CHECK_NAMES = {"v_sig": "signature", "v_M": "manifest", "v_C": "config", "v_B": "SBOM", "v_P": "provenance",
               "v_trans": "transparency log", "v_trust": "signer trusted"}
TRUST_REASONS = {"key": "signing key revoked", "comp": "component advisory",
                 "builder": "builder denied", "trans": "transparency record broken"}


def load_json(path: Path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def load_jsonl(path: Path) -> list[dict]:
    out = []
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return out
    for line in lines:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def alerts(run: Path) -> list[dict]:
    return load_jsonl(Path(run) / "alerts.jsonl")


def is_low(a: dict) -> bool:
    return a.get("class") != "trust" and str(a.get("bucket") or "low").lower() == "low"


def count(run: Path, cls: str | None = None, sub: str | None = None, which: str = "any") -> int:
    """Alerts of a class (and subclass); which = "any", "alerts" (above Low) or "low"."""
    n = 0
    for a in alerts(run):
        if cls and a.get("class") != cls or sub and a.get("subclass") != sub:
            continue
        if which == "alerts" and is_low(a) or which == "low" and not is_low(a):
            continue
        n += 1
    return n


def newest(run: Path, cls: str, sub: str | None = None) -> dict | None:
    found = [a for a in alerts(run) if a.get("class") == cls and (sub is None or a.get("subclass") == sub)]
    return found[-1] if found else None


def binding_for(run: Path, prefix: str, ready: bool | None = None) -> dict | None:
    doc = load_json(Path(run) / "bindings.json", {})
    for b in (doc.values() if isinstance(doc, dict) else []):
        if not isinstance(b, dict) or not str(b.get("pod", "")).startswith(prefix):
            continue
        if prefix == "demo-app" and str(b.get("pod", "")).startswith("demo-app-unsigned"):
            continue
        if ready is None or bool(b.get("envelope_ready")) == ready:
            return b
    return None


def hex_of(digest) -> str:
    return str(digest or "").split(":", 1)[-1]


def checks_line(checks: dict) -> str:
    marks = [f"{CHECK_NAMES.get(k, k)} {'ok' if v else 'FAILED'}" for k, v in checks.items() if v is not None]
    return ", ".join(marks) or "no checks recorded"


def envelope_summary(run: Path, prefix: str = "demo-app") -> list[str]:
    b = binding_for(run, prefix, ready=True) or binding_for(run, prefix)
    if not b:
        return [f"no binding yet for a pod named {prefix}*"]
    digest = b.get("image_digest")
    ctx = load_json(Path(run) / "contexts" / f"{hex_of(digest)}.json", {}) or {}
    env = load_json(Path(run) / "envelopes" / f"{hex_of(digest)}.json", {}) or {}
    verify_s = (ctx.get("verify_ms") or 0) / 1000
    lines = [f"admission: {checks_line(ctx.get('checks') or {})}"
             + (f" (verified in {verify_s:.1f} s)" if verify_s else "")]
    if not env:
        lines.append("no envelope yet" if b.get("verified") else f"not verified: {b.get('reason')}")
        return lines
    compile_s = sum(v for v in (env.get("timings_ms") or {}).values() if isinstance(v, (int, float))) / 1000
    image = env.get("image") or {}
    lines.append(f"envelope compiled in {compile_s:.1f} s, from the signed evidence alone "
                 f"(no training, no observation period):")
    lines.append(f"  {len(env.get('layers') or [])} layers · {len(env.get('files') or {}):,} files · "
                 f"{len(env.get('packages') or {}):,} packages · {len(env.get('closure') or [])} programs and "
                 f"libraries in the execution closure")
    who = [f"built by {image['builder_id']}" if image.get("builder_id") else "",
           f"commit {str(image['source_commit'])[:8]}" if image.get("source_commit") else "",
           f"Rekor entry {image['rekor_log_index']}" if image.get("rekor_log_index") is not None else ""]
    who = [w for w in who if w]
    if who:
        lines.append("  " + " · ".join(who))
    return lines


def where_from(a: dict) -> str:
    attr = a.get("attribution") or {}
    bits = []
    if attr.get("layer"):
        bits.append(f"layer {hex_of(attr['layer'])[:12]}")
    if attr.get("package"):
        bits.append(f"package {attr['package']}")
    if attr.get("depth") is not None:
        bits.append(f"depth {attr['depth']}")
    return ", ".join(bits) or "no layer or package: not part of the signed image"


def incident_summary(run: Path) -> list[str]:
    ex, wr = newest(run, "D_exec", "undeclared"), newest(run, "D_write")
    if not ex and not wr:
        return ["no attack alert yet"]
    lines = []
    for a in (ex, wr):
        if a:
            lines.append(f"{str(a.get('bucket', '')).upper()} {a.get('score')}: {a.get('class')}/{a.get('subclass')}"
                         f" -> {where_from(a)}")
    if ex and wr:
        same = ex.get("chain_id") and ex.get("chain_id") == wr.get("chain_id")
        lines.append(f"one incident ({ex.get('chain_id')})" if same else
                     f"two incidents ({ex.get('chain_id')}, {wr.get('chain_id')})")
    return lines


def since_summary(run: Path, since: int = 0) -> list[str]:
    """One line per alert above Low after the first `since` alerts, then how many Low records came."""
    new = alerts(run)[since:]
    shown = [a for a in new if not is_low(a)]
    lines, prev_chain = [], None
    for a in shown:
        if a.get("class") == "trust":
            label = "TRUST"
            what = "Trust withdrawn: " + (", ".join(TRUST_REASONS.get(r, r) for r in a.get("trust_reason") or [])
                                          or "trust check failed")
        else:
            label = f"{str(a.get('bucket') or '').upper()} {a.get('score')}"
            path, _ = clause_parts(a)
            what = f"{title_of(a)}: {path}" if path else title_of(a)
        chain = a.get("chain_id")
        same = bool(chain) and chain == prev_chain
        prev_chain = chain
        lines.append(f"{label}  {what} -> {where_from(a)}" + ("  (same incident)" if same else ""))
    if not shown:
        lines.append("no alert")
    lows = len(new) - len(shown)
    if lows:
        lines.append(f"(and {lows} Low record{'s' if lows != 1 else ''}: logged, not alerts)")
    return lines


def trust_summary(run: Path) -> list[str]:
    a = newest(run, "trust")
    if not a:
        return ["no trust alert yet"]
    why = a.get("trust_reason") or []
    reasons = ", ".join(TRUST_REASONS.get(r, r) for r in why) or "trust check failed"
    attr = a.get("attribution") or {}
    lines = [f"trust withdrawn: {reasons}" + (f"; {where_from(a)}" if attr.get("package") or attr.get("layer") else "")]
    if isinstance(a.get("latency_s"), (int, float)):
        lines.append(f"raised {a['latency_s']:.1f} s after {'the advisory appeared' if 'comp' in why else 'the change'}")
    if a.get("runtime_state"):
        lines.append(f"runtime state of the pod: {str(a['runtime_state']).upper()} (its behaviour did not change)")
    return lines


def binding_summary(run: Path, prefix: str) -> list[str]:
    b = binding_for(run, prefix)
    if not b:
        return [f"no binding yet for a pod named {prefix}*"]
    ctx = load_json(Path(run) / "contexts" / f"{hex_of(b.get('image_digest'))}.json", {}) or {}
    verdict = "VERIFIED" if b.get("verified") else "NOT VERIFIED"
    lines = [f"{b.get('pod')}: {verdict}: {b.get('reason') or 'no reason recorded'}"]
    if ctx.get("checks"):
        lines.append(f"admission checks: {checks_line(ctx['checks'])}")
    lines.append("envelope: none (nothing to verify its behaviour against)" if not b.get("envelope_ready")
                 else "envelope: ready")
    return lines


def falco_summary(run: Path, since: int = 0, limit: int = 3) -> list[str]:
    events = load_jsonl(Path(run) / "falco.jsonl")[since:]
    if not events:
        return ["Falco: no alert"]
    rules: dict[str, str] = {}
    for e in events:
        rules.setdefault(str(e.get("rule") or "?"), str(e.get("priority") or "?"))
    lines = [f"Falco: {rule} ({priority})" for rule, priority in list(rules.items())[:limit]]
    if len(rules) > limit:
        lines.append(f"Falco: and {len(rules) - limit} more rules")
    lines.append(f"Falco: {len(events)} alert{'s' if len(events) != 1 else ''} in all")
    return lines


def write_advisory(run: Path, aid: str, ecosystem: str, package: str, version: str | None = None) -> Path:
    """An OSV advisory for one package in the trust loop's local feed, run/advisories/<package>.json,
    written to a temporary name first so the loop never reads half a file. No version: every version.
    A MAL- id withdraws trust; any other id is only reported (alerts/trust.py)."""
    affected: dict = {"package": {"ecosystem": ecosystem, "name": package}}
    if version:
        affected["versions"] = [version]
    malicious = aid.upper().startswith("MAL-")
    doc = {"id": aid,
           "summary": f"{package} is malicious (PROVBIND live-demo advisory)" if malicious
           else f"{package} has a vulnerability (PROVBIND live-demo advisory)",
           "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "affected": [affected],
           "database_specific": {"provbind_test": True}}
    path = Path(run) / "advisories" / (re.sub(r"[^A-Za-z0-9._-]+", "_", package).strip("._") + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")          # not *.json, so the loop's glob skips it
    tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def lines_in(path: Path) -> int:
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.live_demo", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("what", choices=("count", "envelope", "since", "incident", "trust", "binding", "falco", "lines",
                                     "advisory"))
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"))
    ap.add_argument("--cls")
    ap.add_argument("--sub")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--low", action="store_true", help="count: Low records only")
    group.add_argument("--alerts", action="store_true", help="count: alerts above Low only")
    ap.add_argument("--pod-prefix", default="demo-app")
    ap.add_argument("--since", type=int, default=0, help="since: alerts already shown; falco: lines already shown")
    ap.add_argument("--file")
    ap.add_argument("--id", help="advisory: its id (MAL-... withdraws trust)")
    ap.add_argument("--ecosystem", default="PyPI", help="advisory: the OSV ecosystem (default PyPI)")
    ap.add_argument("--package", help="advisory: the package name")
    ap.add_argument("--pkg-version", default="", help="advisory: the affected version (default: every version)")
    args = ap.parse_args(argv)
    run = Path(args.run)
    if args.what == "count":
        print(count(run, args.cls, args.sub, "low" if args.low else "alerts" if args.alerts else "any"))
    elif args.what == "lines":
        print(lines_in(Path(args.file or run / "falco.jsonl")))
    elif args.what == "advisory":
        if not args.id or not args.package:
            ap.error("advisory needs --id and --package")
        print(write_advisory(run, args.id, args.ecosystem, args.package, args.pkg_version or None))
    else:
        out = {"envelope": lambda: envelope_summary(run, args.pod_prefix),
               "since": lambda: since_summary(run, args.since),
               "incident": lambda: incident_summary(run),
               "trust": lambda: trust_summary(run),
               "binding": lambda: binding_summary(run, args.pod_prefix),
               "falco": lambda: falco_summary(run, args.since)}[args.what]()
        for line in out:
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
