"""CF-04: lookup time for hits and misses, reference cuckoo filter vs a Python set (§3.6, §6.2).

Owner R1. Microbenchmark of at least 10,000 lookups each. On synthetic paths this is the §6.2
pre-check (`not_run`); with PROVBIND_ENVELOPE it measures a real envelope (`pass`). The pass
criterion is only that ns-per-lookup is reported; there is no threshold, and absolute numbers
in a shared sandbox are indicative (§3.12: real numbers come from the demo PC).
"""
import json
import os
import random
import time

from node.ref_cuckoo import CuckooFilter

LOOKUPS = 20_000       # "at least 10,000 lookups each"


def _paths():
    env = os.environ.get("PROVBIND_ENVELOPE")
    if env:
        with open(env, encoding="utf-8") as f:
            return list(json.load(f)["files"]), True
    return [f"/usr/local/lib/python3.11/site-packages/pkg{i % 900}/mod{i}.py" for i in range(15000)], False


def _ns_per_lookup(fn, keys):
    start = time.perf_counter_ns()
    for k in keys:
        fn(k)
    return round((time.perf_counter_ns() - start) / len(keys), 1)


def test_cf_04_lookup(record_result):
    paths, real = _paths()
    cf = CuckooFilter(len(paths), fp_bits=16)
    for p in paths:
        cf.add(p)
    pyset = set(paths)

    random.seed(0)
    hit_keys = [paths[random.randrange(len(paths))] for _ in range(LOOKUPS)]
    miss_keys = [f"/nonmember/{random.getrandbits(64):016x}" for _ in range(LOOKUPS)]

    # No false negatives on the hit set (guards the benchmark itself).
    assert all(k in cf for k in set(hit_keys))

    metrics = {
        "lookups": LOOKUPS,
        "filter_hit_ns": _ns_per_lookup(lambda k: k in cf, hit_keys),
        "filter_miss_ns": _ns_per_lookup(lambda k: k in cf, miss_keys),
        "set_hit_ns": _ns_per_lookup(lambda k: k in pyset, hit_keys),
        "set_miss_ns": _ns_per_lookup(lambda k: k in pyset, miss_keys),
    }
    record_result("CF-04", "pass" if real else "not_run", metrics=metrics,
                  notes="reference filter vs set, 16-bit" if real
                  else "synthetic paths only; set PROVBIND_ENVELOPE for the real test")
    assert metrics["filter_hit_ns"] > 0 and metrics["set_hit_ns"] > 0
