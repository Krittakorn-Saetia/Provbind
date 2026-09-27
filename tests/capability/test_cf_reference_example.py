"""EXAMPLE of the harness pattern, using the reference cuckoo filter.

It runs CF-01 and CF-02 on SYNTHETIC paths, so its results are not project results.
For the real tests, set PROVBIND_ENVELOPE to a compiled envelope file: its `files`
keys are then used instead of synthetic paths, and the results count.
"""
import json, os, random, sys, pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from node.ref_cuckoo import CuckooFilter  # noqa: E402


def _paths():
    env = os.environ.get("PROVBIND_ENVELOPE")
    if env:
        with open(env, encoding="utf-8") as f:
            return list(json.load(f)["files"]), True
    return [f"/usr/local/lib/python3.11/site-packages/pkg{i%900}/mod{i}.py" for i in range(15000)], False


def test_cf_01_no_false_negatives(record_result):
    paths, real = _paths()
    cf = CuckooFilter(len(paths), fp_bits=16)
    assert all(cf.add(p) for p in paths), "filter full: see CF-06"
    misses = sum(p not in cf for p in paths)
    record_result("CF-01", "pass" if misses == 0 and real else ("fail" if misses else "not_run"),
                  metrics={"paths": len(paths), "false_negatives": misses},
                  notes="" if real else "synthetic paths only; set PROVBIND_ENVELOPE for the real test")
    assert misses == 0


def test_cf_02_false_positive_rate(record_result):
    paths, real = _paths()
    random.seed(0)
    queries = [f"/nonmember/{random.getrandbits(64):016x}" for _ in range(400_000)]
    metrics = {}
    for bits in (8, 16):
        cf = CuckooFilter(len(paths), fp_bits=bits)
        for p in paths:
            cf.add(p)
        rate = sum(q in cf for q in queries) / len(queries)
        metrics[f"fp_rate_{bits}bit"] = round(rate, 7)
        metrics[f"theory_{bits}bit"] = round(8 / 2 ** bits, 7)     # 2b/2^f with b = 4
    ok = all(metrics[f"fp_rate_{b}bit"] <= 1.5 * metrics[f"theory_{b}bit"] for b in (8, 16))
    record_result("CF-02", ("pass" if ok else "fail") if real else "not_run", metrics=metrics,
                  notes="reference filter" if real else "synthetic paths only; set PROVBIND_ENVELOPE")
    assert ok
