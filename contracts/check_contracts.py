"""Check a run folder against the Sprint Handoff §4 contracts (Role 4 keeps this, §3.4).

    python contracts/check_contracts.py --run $PROVBIND_RUN

| File | Checked against |
|---|---|
| `envelopes/<hex>.json` | `contracts/envelope.schema.json`, and the file name is the image digest's hex |
| `bindings.json` | §4.2: the required keys and their types |
| `detections.jsonl` | §4.4's keys, and `node/detection.schema.json` (Role 3) when it exists |
| `alerts.jsonl` | §4.5's keys and bucket values |
| `log/violations.jsonl` | the §4.6 hash chain (alerts.verify_log) |

Files that do not exist yet are skipped. stdout: one JSON summary; the findings go to stderr.
Exit 0 when every present file passes, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
BINDING_TYPES = {"namespace": str, "pod": str, "container": str, "image_digest": str, "verified": bool,
                 "run_as_root": bool, "privileged": bool, "mounts": list, "envelope_ready": bool}
DETECTION_KEYS = ["id", "time", "container_id", "namespace", "pod", "container", "image_digest", "pid", "ppid",
                  "exe", "parent_exe", "class", "subclass", "clause", "origin", "context"]
ALERT_KEYS = ["alert_id", "detection_id", "time", "image_digest", "container", "class", "subclass",
              "violated_clause", "origin", "score", "bucket", "attribution", "signing_identity", "chain_id", "log_k"]
BUCKETS = {"critical", "high", "medium", "low"}


def jsonl(path: Path):
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if line.strip():
                try:
                    yield n, json.loads(line)
                except ValueError as e:
                    yield n, e


def check_envelopes(run: Path, errors: list) -> int:
    folder = run / "envelopes"
    if not folder.is_dir():
        return 0
    try:
        import jsonschema
        validator = jsonschema.Draft202012Validator(json.loads((ROOT / "contracts" / "envelope.schema.json").read_text()))
    except ImportError:
        validator = None
    count = 0
    for path in sorted(folder.glob("*.json")):
        count += 1
        try:
            env = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as e:
            errors.append(f"{path.name}: not JSON ({e})")
            continue
        if validator is not None:
            for err in list(validator.iter_errors(env))[:3]:
                errors.append(f"{path.name}: {'/'.join(map(str, err.path)) or '(top)'}: {err.message[:120]}")
        digest = (env.get("image") or {}).get("digest", "")
        if path.stem != digest.split(":", 1)[-1]:
            errors.append(f"{path.name}: the file name is not the hex of image.digest {digest}")
    return count


def check_bindings(run: Path, errors: list) -> int:
    path = run / "bindings.json"
    if not path.exists():
        return 0
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as e:
        errors.append(f"bindings.json: not JSON ({e})")
        return 0
    if not isinstance(doc, dict):
        errors.append("bindings.json: not an object keyed by container ID")
        return 0
    for cid, b in doc.items():
        for key, kind in BINDING_TYPES.items():
            if not isinstance(b, dict) or key not in b:
                errors.append(f"bindings.json {cid}: missing {key}")
            elif not isinstance(b[key], kind):
                errors.append(f"bindings.json {cid}: {key} is not {kind.__name__}")
        if isinstance(b, dict) and isinstance(b.get("image_digest"), str) and not DIGEST.match(b["image_digest"]):
            errors.append(f"bindings.json {cid}: image_digest is not sha256:<64 hex>")
        if isinstance(b, dict) and any(not str(m).startswith("/") for m in b.get("mounts") or []):
            errors.append(f"bindings.json {cid}: a mount is not an absolute path")
    return len(doc)


def check_detections(run: Path, errors: list) -> int:
    path = run / "detections.jsonl"
    if not path.exists():
        return 0
    validator = None
    schema_path = ROOT / "node" / "detection.schema.json"
    if schema_path.exists():
        try:
            import jsonschema
            validator = jsonschema.Draft202012Validator(json.loads(schema_path.read_text()))
        except ImportError:
            pass
    count = 0
    for n, det in jsonl(path):
        count += 1
        if isinstance(det, Exception):
            errors.append(f"detections.jsonl:{n}: not JSON")
            continue
        missing = [k for k in DETECTION_KEYS if k not in det]
        if missing:
            errors.append(f"detections.jsonl:{n}: missing {missing}")
        if validator is not None:
            for err in list(validator.iter_errors(det))[:2]:
                errors.append(f"detections.jsonl:{n}: {err.message[:120]}")
    return count


def check_alerts(run: Path, errors: list) -> int:
    path = run / "alerts.jsonl"
    if not path.exists():
        return 0
    count = 0
    for n, a in jsonl(path):
        count += 1
        if isinstance(a, Exception):
            errors.append(f"alerts.jsonl:{n}: not JSON")
            continue
        missing = [k for k in ALERT_KEYS if k not in a]
        if missing:
            errors.append(f"alerts.jsonl:{n}: missing {missing}")
        if str(a.get("bucket")) not in BUCKETS:
            errors.append(f"alerts.jsonl:{n}: bucket {a.get('bucket')!r}")
    return count


def check_log(run: Path, errors: list) -> int:
    if not (run / "log" / "violations.jsonl").exists():
        return 0
    from alerts.verify_log import verify
    result = verify(run)
    if not result.ok:
        errors.append(f"log/violations.jsonl: {result.reason}")
    return result.records


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"), help="run folder (default $PROVBIND_RUN or ./run)")
    ap.add_argument("run_dir", nargs="?", help=argparse.SUPPRESS)          # the old positional form
    args = ap.parse_args(argv)
    run = Path(args.run_dir or args.run)
    errors: list[str] = []
    counts = {"envelopes": check_envelopes(run, errors), "bindings": check_bindings(run, errors),
              "detections": check_detections(run, errors), "alerts": check_alerts(run, errors),
              "log_records": check_log(run, errors)}
    for e in errors:
        print(f"[check_contracts] {e}", file=sys.stderr)
    print(json.dumps({"ok": not errors, "checked": counts, "errors": len(errors)}))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
