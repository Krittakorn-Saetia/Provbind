"""Dataset D1: Role 1's labels joined to our features by image digest (handoff T13 step 3).

    python -m ml.dataset --labels ml/data/labels.jsonl --features ml/data/features.jsonl \
                         --out ml/data/dataset.jsonl

Inputs, one JSON object per line:
- labels.jsonl, from Role 1's profiling (testbed/profiling/labels.py, build_label_row):
  {"image", "digest", "labels", "denied", "runs", "run_disagreement", "disagreement_fraction"
  [, "workload"]}
- features.jsonl, from `python -m compiler.compile <ref@digest> --features-out ...`
  (compiler/compile.py, append_features):
  {"digest", "ref", "features_version", "features", "packages", "exposed_ports"}

Each output row is what ml.train.load_dataset reads: the label row's fields, then "ref",
"features", "packages" and "exposed_ports" from the feature line, and "allowed".

- **allowed (𝒞_K8s).** Role 1 profiles every image in a default pod (testbed/profile_corpus.sh:
  `kubectl run` with no securityContext), and the compiler computes the features for the
  default pod, so allowed is the runtime's default set (ml.alg1.RUNTIME_DEFAULT_CAPS). A label
  row that records a pod of its own ("allowed", "securityContext" or "deployment") is refused:
  its dep.* features would then be wrong.
- **Several lines for one digest** (a re-profiled or recompiled image): the last line wins, since
  both files are appended to.
- **Feature lines from another FEATURES_VERSION** are skipped with a warning: recompile those
  images.
- **Digests in only one file** are reported on stderr: labels without features need a compile
  with --features-out; features without labels were never profiled.

The output is written to a temp file and renamed, and its path printed on stdout. Exit 0
written; 1 when an input is missing or malformed, or no digest is in both files, and then
nothing is written.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sys
from pathlib import Path
from typing import Iterator

from .alg1 import RUNTIME_DEFAULT_CAPS, normalise
from .features import FEATURES_VERSION, feature_names

log = logging.getLogger("provbind.ml.dataset")

LABEL_FIELDS = ("image", "digest", "labels")
FEATURE_FIELDS = ("digest", "features_version", "features", "packages")
OWN_POD_FIELDS = ("allowed", "securityContext", "deployment")


class DatasetError(Exception):
    """An input file is missing or malformed. Nothing is written."""


def read_lines(path: str | Path) -> Iterator[tuple[int, dict]]:
    """(line number, object) for each non-blank line."""
    try:
        f = open(path, encoding="utf-8")
    except OSError as e:
        raise DatasetError(f"cannot read {path}: {e.strerror or e}") from None
    with f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                raise DatasetError(f"{path}:{n}: not JSON: {e.msg}") from None
            if not isinstance(row, dict):
                raise DatasetError(f"{path}:{n}: not a JSON object")
            yield n, row


def _check_digest(path, n, row) -> str:
    d = row.get("digest")
    if not isinstance(d, str) or not d.startswith("sha256:") or len(d) != 71:
        raise DatasetError(f"{path}:{n}: digest is not sha256:<64 hex>: {d!r}")
    return d


def load_labels(path: str | Path) -> dict[str, dict]:
    """Role 1's rows by digest, last line winning; capability names normalised to CAP_*."""
    rows: dict[str, dict] = {}
    for n, row in read_lines(path):
        missing = [k for k in LABEL_FIELDS if k not in row]
        if missing:
            raise DatasetError(f"{path}:{n}: missing {', '.join(missing)}")
        own_pod = [k for k in OWN_POD_FIELDS if k in row]
        if own_pod:
            raise DatasetError(f"{path}:{n}: records its own pod ({', '.join(own_pod)}); ml.dataset assumes "
                               "default pods, which is how testbed/profile_corpus.sh profiles")
        digest = _check_digest(path, n, row)
        try:
            row = {**row, "labels": sorted({normalise(c) for c in row["labels"]})}
        except (ValueError, AttributeError, TypeError) as e:
            raise DatasetError(f"{path}:{n}: {e}") from None
        if digest in rows:
            log.info("%s:%d: %s appears again; the later line wins", path, n, digest)
        rows[digest] = row
    return rows


def load_features(path: str | Path) -> dict[str, dict]:
    """The compiler's feature lines by digest, last line winning; lines of another
    FEATURES_VERSION are skipped with a warning."""
    fixed = set(feature_names())
    rows: dict[str, dict] = {}
    for n, row in read_lines(path):
        missing = [k for k in FEATURE_FIELDS if k not in row]
        if missing:
            raise DatasetError(f"{path}:{n}: missing {', '.join(missing)}")
        digest = _check_digest(path, n, row)
        if row["features_version"] != FEATURES_VERSION:
            log.warning("%s:%d: %s has features version %r, not %d; skipped (recompile it with --features-out)",
                        path, n, digest, row["features_version"], FEATURES_VERSION)
            continue
        features = row["features"]
        if not isinstance(features, dict) or set(features) != fixed:
            got = set(features) if isinstance(features, dict) else set()
            raise DatasetError(f"{path}:{n}: features are not the {len(fixed)} fixed features "
                               f"(missing {sorted(fixed - got)[:3]}, extra {sorted(got - fixed)[:3]})")
        rows[digest] = row
    return rows


def join(labels: dict[str, dict], features: dict[str, dict]) -> tuple[list[dict], list[str], list[str]]:
    """(joined rows in label-file order, digests with labels only, digests with features only)."""
    allowed = sorted(RUNTIME_DEFAULT_CAPS)
    rows = []
    for digest, label_row in labels.items():
        f = features.get(digest)
        if f is None:
            continue
        rows.append({**label_row, "ref": f.get("ref"), "features": f["features"], "packages": list(f["packages"]),
                     "exposed_ports": list(f.get("exposed_ports") or ()), "allowed": allowed})
    labels_only = [d for d in labels if d not in features]
    features_only = [d for d in features if d not in labels]
    return rows, labels_only, features_only


def write_atomically(rows: list[dict], out: str | Path) -> Path:
    """One JSON object per line, via a temp file in the same folder and a rename."""
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{out.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        with open(tmp, "x", encoding="utf-8", newline="\n") as f:
            for row in rows:
                f.write(json.dumps(row, allow_nan=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, out)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return out


def build(labels_path: str | Path, features_path: str | Path, out: str | Path) -> Path:
    """Join the two files and write D1. Raises DatasetError, and writes nothing, when an input
    is bad or no digest is in both."""
    labels, features = load_labels(labels_path), load_features(features_path)
    rows, labels_only, features_only = join(labels, features)
    for d in labels_only:
        log.warning("labels but no features: %s (%s); compile it with --features-out %s",
                    d, labels[d].get("image"), features_path)
    for d in features_only:
        log.warning("features but no labels: %s (%s); not profiled", d, features[d].get("ref"))
    if not rows:
        raise DatasetError(f"no digest is in both {labels_path} ({len(labels)}) and {features_path} ({len(features)})")
    path = write_atomically(rows, out)
    log.info("%d images joined (%d labelled only, %d with features only) -> %s",
             len(rows), len(labels_only), len(features_only), path)
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ml.dataset", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--labels", default="ml/data/labels.jsonl", help="Role 1's labels (MLA-03)")
    ap.add_argument("--features", default="ml/data/features.jsonl", help="the compiler's --features-out file")
    ap.add_argument("--out", default="ml/data/dataset.jsonl", help="dataset D1 for ml.train")
    args = ap.parse_args(argv)

    logger = logging.getLogger("provbind")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[dataset] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        path = build(args.labels, args.features, args.out)
    except DatasetError as e:
        log.error("%s; nothing written", e)
        return 1
    finally:
        logger.removeHandler(handler)
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
