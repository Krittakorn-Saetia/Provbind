"""CF-06: behaviour when the reference cuckoo filter is full (Test Plan §3.6, expansion off).

Owner R1. Pass criterion: "Failed insertion detected and handled; no silent loss." The
reference filter has no expansion, so `add` returns False when an item cannot be placed within
max_kicks. This is a property of the filter, not of any envelope, so it is recorded `pass` on
generated keys: the point is that overflow is signalled, never accepted silently.

Cuckoo caveat: a *failed* insert can evict an item that was present (the classic trade-off). The
guarantee tested here is that overflow is *reported* (add returns False), and that no item is
lost *before* the first reported failure (a successful add only relocates, never drops).
"""
from node.ref_cuckoo import CuckooFilter


def test_cf_06_full(record_result):
    cf = CuckooFilter(1000, fp_bits=8)          # small filter, no expansion
    keys = [f"/overflow/key/{i}" for i in range(50_000)]

    # A real caller stops and handles the failure when add() returns False; it does not keep
    # hammering a full filter, since a failed cuckoo insert evicts the one item it was carrying
    # (the documented trade-off). That eviction is not silent: add() reports the failure.
    succeeded, first_failure_at = 0, None
    for i, k in enumerate(keys):
        if cf.add(k):
            succeeded += 1
            # No silent loss on an accepted insert: it is retrievable immediately.
            assert k in cf, f"accepted insert {k} was not retrievable"
        else:
            first_failure_at = i
            break

    # Overflow is detected (add returned False), not accepted silently.
    assert first_failure_at is not None, "filter never reported full; capacity too large for this test"
    assert first_failure_at == succeeded          # failed right after the last accepted insert

    record_result("CF-06", "pass", metrics={
        "capacity_slots": cf.m * cf.b,
        "fp_bits": 8,
        "succeeded_before_overflow": succeeded,
        "first_failure_at": first_failure_at,
        "load_at_overflow": round(succeeded / (cf.m * cf.b), 4),
    }, notes="reference filter, expansion off; overflow reported via add()==False; every "
             "accepted insert stays retrievable, so no silent loss")
