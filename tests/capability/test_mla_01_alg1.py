"""MLA-01: Algorithm 1 logic with fixed probabilities: threshold θ_C, the cap at 𝒞_K8s, and the
origin labels (Aj Ohm's draft, Eqs. 33-34 and Algorithm 1; Test Plan §3.4).

Pass: every case gives exactly the expected set and labels, and nothing falls outside 𝒞_K8s.
The cases are in tests/ml/alg1_cases.py; no model is needed.
"""
from ml.alg1 import normalise
from tests.ml.alg1_cases import CASES, run


def test_mla_01_algorithm_1_logic(record_result):
    mismatches, outside = [], 0
    for case in CASES:
        got, expected = run(case)
        if got != expected:
            mismatches.append(case["name"])
        if case["allowed"] is not None:
            bound = {normalise(c) for c in case["allowed"]}
            outside += sum(cap not in bound for cap, _, _ in got)
    ok = not mismatches and outside == 0
    record_result("MLA-01", "pass" if ok else "fail",
                  metrics={"cases": len(CASES), "mismatches": len(mismatches), "outside_k8s": outside},
                  notes="Algorithm 1 lines 3-14 with fixed probabilities, θ_C, 𝒞_K8s and 𝒞_decl; no model yet"
                        + ("" if ok else "; failed: " + "; ".join(mismatches)))
    assert ok, mismatches
