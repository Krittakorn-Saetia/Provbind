"""PH3-09: the runtime indices J_I agree with the envelope (Eq. 37) (Test Plan §3.3).

Property test on 500 random files. For each sampled file, all five indices must agree with the
envelope:
- J_path gives its sha256 and layer;
- J_hash lists it under its sha256;
- J_layer gives its layer's digest;
- J_pkg gives its package;
- J_depth gives that package's depth.

The whole-index checks must also hold: J_path covers exactly the files, J_hash is its exact
inverse, and J_depth covers exactly the packages. None of 500 random non-member paths may be in
any path index. Pass: 100% agreement.

Envelope: PROVBIND_ENVELOPE; without it, a synthetic envelope of 5,000 files built on the golden
one, and the result is not_run.
"""
import copy
import hashlib
import json
import os
import random
from collections import Counter
from pathlib import Path

from compiler.indices import build

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "compiler" / "tests" / "golden" / "envelope.json"
SAMPLE = 500


def synthetic_envelope(n: int = 5000, seed: int = 9) -> dict:
    """The golden envelope plus n files over its layers and packages: one in ten repeats the
    content of an earlier file, and one in three has no package."""
    rng = random.Random(seed)
    env = copy.deepcopy(json.loads(GOLDEN.read_text(encoding="utf-8")))
    packages, layers = sorted(env["packages"]), [entry["index"] for entry in env["layers"]]
    hashes = []
    for i in range(n):
        h = rng.choice(hashes) if hashes and rng.random() < 0.1 else hashlib.sha256(f"file {i}".encode()).hexdigest()
        hashes.append(h)
        env["files"][f"/usr/local/lib/python3.11/site-packages/pkg{i % 97}/mod{i}.py"] = {
            "sha256": h, "layer": rng.choice(layers), "mode": "0644",
            "package": None if rng.random() < 1 / 3 else rng.choice(packages)}
    return env


def agreement(env: dict, n: int = SAMPLE, seed: int = 37) -> dict:
    """Disagreements per index over n sampled files, plus the whole-index checks."""
    j = build(env)
    files, packages = env["files"], env["packages"]
    digest_of = {entry["index"]: entry["digest"] for entry in env["layers"]}
    rng = random.Random(seed)
    sample = rng.sample(sorted(files), min(n, len(files)))
    wrong = Counter()
    for p in sample:
        f = files[p]
        wrong["J_path"] += j.path.get(p) != (f["sha256"], f["layer"])
        wrong["J_hash"] += p not in j.hash.get(f["sha256"], ())
        wrong["J_layer"] += j.layer.get(p) != digest_of.get(f["layer"])
        wrong["J_pkg"] += j.pkg.get(p, "absent") != f.get("package")
        if f.get("package") is not None:
            wrong["J_depth"] += j.depth.get(f["package"], "absent") != packages.get(f["package"], {}).get("depth", "?")
    inverse: dict[str, set[str]] = {}
    for p, (sha, _) in j.path.items():
        inverse.setdefault(sha, set()).add(p)
    whole = {"J_path covers the files": set(j.path) == set(files),
             "J_hash is the inverse of J_path": {h: frozenset(ps) for h, ps in inverse.items()} == j.hash,
             "J_depth covers the packages": set(j.depth) == set(packages)}
    absent = [f"/nonmember/{rng.getrandbits(64):016x}" for _ in range(n)]
    false_hits = sum(a in j.path or a in j.layer or a in j.pkg for a in absent)
    checked = len(sample) * 4 + sum(files[p].get("package") is not None for p in sample)
    return {"sampled": len(sample), "files": len(files), "checked": checked,
            "disagreements": {k: wrong[k] for k in ("J_path", "J_hash", "J_layer", "J_pkg", "J_depth")},
            "whole_index_checks_failed": [k for k, good in whole.items() if not good],
            "nonmember_hits": false_hits}


def test_ph3_09_indices_agree_with_the_envelope(record_result):
    path = os.environ.get("PROVBIND_ENVELOPE")
    env = json.loads(Path(path).read_text(encoding="utf-8")) if path else synthetic_envelope()
    m = agreement(env)
    bad = sum(m["disagreements"].values())
    ok = bad == 0 and not m["whole_index_checks_failed"] and m["nonmember_hits"] == 0
    m["agreement"] = round(1 - bad / m["checked"], 6) if m["checked"] else None
    status = "pass" if ok and path else ("fail" if not ok else "not_run")
    notes = (f"envelope {path}" if path else "synthetic envelope: golden plus 5,000 generated files; "
             "set PROVBIND_ENVELOPE for the real test")
    if not ok:
        notes += f"; disagreements {m['disagreements']}, failed checks {m['whole_index_checks_failed']}, " \
                 f"non-member hits {m['nonmember_hits']}"
    record_result("PH3-09", status,
                  metrics={"agreement": m["agreement"], "sampled": m["sampled"], "files": m["files"],
                           "nonmember_hits": m["nonmember_hits"], "disagreements": m["disagreements"],
                           "whole_index_checks_failed": m["whole_index_checks_failed"]},
                  notes=notes, artifacts=[path] if path else [])
    assert ok, notes
