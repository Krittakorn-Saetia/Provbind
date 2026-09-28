"""CF-03: reference cuckoo filter memory against a Python set and dict (Test Plan §3.6, §6.2).

Owner R1. On synthetic paths this is the §6.2 pre-check, recorded `not_run` (not a project
result). Set PROVBIND_ENVELOPE=run/envelopes/<digest>.json to measure a real envelope's paths,
which is recorded `pass` (the pass criterion is only that the ratio is reported).
"""
import json
import os
import sys

from node.ref_cuckoo import CuckooFilter


def _paths():
    env = os.environ.get("PROVBIND_ENVELOPE")
    if env:
        with open(env, encoding="utf-8") as f:
            return list(json.load(f)["files"]), True
    return [f"/usr/local/lib/python3.11/site-packages/pkg{i % 900}/mod{i}.py" for i in range(15000)], False


def test_cf_03_memory(record_result):
    paths, real = _paths()
    cf = CuckooFilter(len(paths), fp_bits=16)
    assert all(cf.add(p) for p in paths), "filter full: see CF-06"

    filter_bytes = cf.nbytes()
    # The path strings exist anyway (§6.2), so a set/dict only adds its container overhead.
    set_bytes = sys.getsizeof(set(paths))
    dict_bytes = sys.getsizeof({p: i for i, p in enumerate(paths)})
    string_bytes = sum(sys.getsizeof(p) for p in paths)

    metrics = {
        "paths": len(paths),
        "fp_bits": 16,
        "filter_bytes": filter_bytes,
        "set_container_bytes": set_bytes,
        "dict_container_bytes": dict_bytes,
        "string_bytes": string_bytes,
        "ratio_filter_over_set_container": round(filter_bytes / set_bytes, 4) if set_bytes else None,
    }
    record_result("CF-03", "pass" if real else "not_run", metrics=metrics,
                  notes="reference filter, 16-bit" if real
                  else "synthetic paths only; set PROVBIND_ENVELOPE for the real test")
    assert filter_bytes > 0 and set_bytes > 0
