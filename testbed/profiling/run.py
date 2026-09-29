"""Assemble ML-A capability labels into ml/data/labels.jsonl (MLA-03, Test Plan §4.2, §12.2).

Profiling has two halves. The **capture** half needs the cluster and Tetragon and runs on the
demo PC (`testbed/profile_corpus.sh`): it re-tags and attests each corpus image, runs its
workload twice for 120 s under Role 3's `cap_capable` policy, and saves the raw Tetragon events.
The **assemble** half is pure and runs anywhere:

    python -m testbed.profiling.run --raw ml/data/raw --out ml/data/labels.jsonl --namespace demo

Raw layout, one directory per image (ml/data/raw/ is git-ignored):

    ml/data/raw/<slug>/meta.json     {"image": "nginx:1.27", "digest": "sha256:..."}
    ml/data/raw/<slug>/run1.jsonl    Tetragon JSON, first 120 s run
    ml/data/raw/<slug>/run2.jsonl    second run

Output: one `labels.jsonl` row per image (build_label_row), plus a summary on stderr with the
label-noise (two-run disagreement) and the capabilities too rare to train (§4.2).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .labels import build_label_row, labels_for_run, parse_tetragon_cap_events, rare_labels


def _read_meta(image_dir):
    meta_path = os.path.join(image_dir, "meta.json")
    if os.path.isfile(meta_path):
        with open(meta_path, encoding="utf-8") as f:
            m = json.load(f)
        return m.get("image", os.path.basename(image_dir)), m.get("digest"), m.get("workload")
    digest = None
    digest_path = os.path.join(image_dir, "digest")
    if os.path.isfile(digest_path):
        digest = open(digest_path, encoding="utf-8").read().strip() or None
    return os.path.basename(image_dir), digest, None


def assemble(raw_root, namespace=None, pod_prefix=None):
    """Build label rows from every image directory under raw_root. Returns (rows, skipped)."""
    rows, skipped = [], []
    if not os.path.isdir(raw_root):
        return rows, skipped
    for slug in sorted(os.listdir(raw_root)):
        image_dir = os.path.join(raw_root, slug)
        if not os.path.isdir(image_dir):
            continue
        run_files = sorted(f for f in os.listdir(image_dir) if f.startswith("run") and f.endswith(".jsonl"))
        if not run_files:
            skipped.append((slug, "no run*.jsonl captures"))
            continue
        image, digest, workload = _read_meta(image_dir)
        if not digest:
            skipped.append((slug, "no digest (needed to join to features by digest)"))
            continue
        run_labels = []
        for rf in run_files:
            with open(os.path.join(image_dir, rf), encoding="utf-8") as f:
                checks = list(parse_tetragon_cap_events(f, namespace=namespace, pod_prefix=pod_prefix))
            run_labels.append(labels_for_run(checks))
        rows.append(build_label_row(image, digest, run_labels, workload=workload))
    return rows, skipped


def write_labels(rows, out_path):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    os.replace(tmp, out_path)


def main(argv=None):
    ap = argparse.ArgumentParser(description="assemble ML-A labels from captured Tetragon events")
    ap.add_argument("--raw", default="ml/data/raw", help="root of per-image raw captures")
    ap.add_argument("--out", default="ml/data/labels.jsonl")
    ap.add_argument("--namespace", default="demo", help="keep only this namespace (§4.2)")
    ap.add_argument("--pod-prefix", default=None, help="keep only pods with this name prefix")
    args = ap.parse_args(argv)

    rows, skipped = assemble(args.raw, namespace=args.namespace, pod_prefix=args.pod_prefix)
    if not rows:
        print(f"profiling: no label rows built from {args.raw}. "
              "Run testbed/profile_corpus.sh on the demo PC first.", file=sys.stderr)
        for slug, why in skipped:
            print(f"  skipped {slug}: {why}", file=sys.stderr)
        return 1

    write_labels(rows, args.out)
    noisy = [r for r in rows if r["run_disagreement"]]
    rare = rare_labels(rows)
    print(f"profiling: wrote {len(rows)} images to {args.out}", file=sys.stderr)
    print(f"  two-run disagreement: {len(noisy)}/{len(rows)} images "
          f"(label noise, §4.2)", file=sys.stderr)
    if rare:
        print(f"  too rare to train (<3 positive images): "
              f"{', '.join(f'{c}={n}' for c, n in rare.items())}", file=sys.stderr)
    for slug, why in skipped:
        print(f"  skipped {slug}: {why}", file=sys.stderr)
    if len(rows) < 20:
        print(f"  WARNING: {len(rows)} images; Test Plan §4.7 wants at least 20 for D1", file=sys.stderr)
    print(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
