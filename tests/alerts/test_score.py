"""alerts/score.py: Sprint Handoff §8, Explanation §8 and Role 3's classes (PH5-01 to 05)."""
import random

import pytest

from alerts.score import BEH_CAP, BINDING_SCORE, WEAK_CAP, bucket_of, score_detection

ROOT_POD = {"run_as_root": True, "privileged": False}


def det(cls, sub, origin="AUTHENTICATED", **ctx):
    return {"class": cls, "subclass": sub, "origin": origin,
            "context": {"declared": True, "package": None, "depth": None, "layer": 0, **ctx}}


@pytest.mark.parametrize("d,expected", [
    (det("D_exec", "undeclared", declared=False), (90, "critical")),
    (det("D_write", "declared_file"), (72, "high")),
    (det("D_exec", "outside_closure", package="pkg:deb/debian/coreutils@9.1-1", depth=1), (34, "low")),
], ids=["x9-exec", "passwd-write", "ls-exec"])
def test_the_sprint_handoff_examples(d, expected):
    assert score_detection(d, ROOT_POD)[:2] == expected


@pytest.mark.parametrize("cls,sub,s_type", [
    ("D_exec", "undeclared", 1.00), ("D_hash", "modified", 1.00), ("D_load", "undeclared", 0.85),
    ("D_write", "declared_file", 0.80), ("D_hash", "relocated", 0.70), ("D_cap", "not_in_envelope", 0.60),
    ("D_net", "not_allowed", 0.55), ("D_exec", "outside_closure", 0.25), ("D_load", "outside_closure", 0.25),
])
def test_every_class_role_3_emits_has_its_value(cls, sub, s_type):
    parts = score_detection(det(cls, sub), ROOT_POD)[2]
    assert parts["s_type"] == s_type and "unknown_class" not in parts


@pytest.mark.parametrize("cls", ["D_exec", "D_load"])
def test_the_weak_classes_never_leave_low(cls):
    worst = det(cls, "outside_closure", declared=False)
    score, bucket, _ = score_detection(worst, {"privileged": True})
    assert score <= WEAK_CAP and bucket == "low"


def test_d_beh_uses_g_i_and_is_capped_at_medium():
    beh = {"class": "D_beh", "subclass": "anomalous_window", "origin": "INFERRED",
           "clause": {"detail": "120 events ...: anomaly 0.9 > θ_A 0.6; anomaly 0.9000, g_I 1.000"},
           "context": {"declared": False}}
    score, bucket, parts = score_detection(beh, {"privileged": True})
    assert (score, bucket, parts["g_I"]) == (BEH_CAP, "medium", 1.0)
    low = dict(beh, clause={"detail": "anomaly 0.1, g_I 0.100"})
    assert score_detection(low, ROOT_POD)[0] < BEH_CAP


def test_a_behavioural_hint_never_outranks_a_signed_contradiction():         # M2, MLB-07
    beh = {"class": "D_beh", "subclass": "anomalous_window", "origin": "INFERRED", "clause": {"detail": "g_I 1.0"},
           "context": {"declared": False}}
    assert score_detection(beh, {"privileged": True})[0] < score_detection(det("D_write", "declared_file"), ROOT_POD)[0]


@pytest.mark.parametrize("sub", ["unknown_container", "unverified", "no_envelope"])
def test_binding_failures_score_a_fixed_60(sub):
    assert score_detection({"class": "binding", "subclass": sub, "context": {"declared": None}})[:2] == \
        (BINDING_SCORE, "high")


def test_authenticated_outranks_inferred():                                  # PH5-02
    for cls, sub in [("D_exec", "undeclared"), ("D_write", "declared_file"), ("D_cap", "not_in_envelope")]:
        a = score_detection(det(cls, sub, "AUTHENTICATED"), ROOT_POD)[0]
        i = score_detection(det(cls, sub, "INFERRED"), ROOT_POD)[0]
        assert a > i


def test_scores_stay_in_range_and_never_drop_a_detection():                  # PH5-03
    rng = random.Random(7)
    classes = [("D_exec", "undeclared"), ("D_exec", "outside_closure"), ("D_write", "declared_file"),
               ("D_hash", "modified"), ("D_hash", "relocated"), ("D_load", "undeclared"), ("D_cap", "x"),
               ("D_net", "x"), ("D_beh", "anomalous_window"), ("binding", "unverified"), ("D_new", "future")]
    dets = []
    for _ in range(2000):
        cls, sub = rng.choice(classes)
        dets.append({"class": cls, "subclass": sub, "origin": rng.choice(["AUTHENTICATED", "INFERRED", "CONFIGURED", None]),
                     "clause": {"detail": f"g_I {rng.random():.3f}"},
                     "context": {"declared": rng.choice([True, False, None]),
                                 "package": rng.choice([None, "pkg:pypi/x@1"]), "depth": rng.choice([None, 0, 1, 5, 40])}})
    scores = [score_detection(d, {"privileged": rng.random() < .3, "run_as_root": rng.random() < .5}) for d in dets]
    assert len(scores) == len(dets)
    assert all(0 <= s <= 100 and b == bucket_of(s) for s, b, _ in scores)


def test_an_undeclared_file_outranks_any_declared_one_before_rounding():       # PH5-04
    """S is always lower for a declared file (rho < 1), but the integer score ties from depth 39:
    100*S = 70 + 20*d/(1+d) reaches 89.5 there, which rounds to the undeclared file's 90."""
    und_score, _, und = score_detection(det("D_exec", "undeclared", declared=False), ROOT_POD)
    ties = []
    for depth in range(0, 200):
        score, _, parts = score_detection(det("D_exec", "undeclared", package="pkg:pypi/x@1", depth=depth), ROOT_POD)
        assert parts["S"] < und["S"] and score <= und_score
        if score == und_score:
            ties.append(depth)
    assert ties and min(ties) == 39


def test_an_unresolved_depth_is_one_half_not_one():                           # PH5-05, M16
    parts = score_detection(det("D_write", "declared_file", package="pkg:deb/debian/login@1", depth=None), ROOT_POD)[2]
    assert parts["rho"] == 0.5


@pytest.mark.parametrize("binding,kappa", [({"privileged": True}, 1.0), ({"run_as_root": True}, 0.5),
                                           ({"run_as_root": False}, 0.2), (None, 0.5)])
def test_kappa_comes_from_the_binding(binding, kappa):
    assert score_detection(det("D_exec", "undeclared"), binding)[2]["kappa"] == kappa


def test_an_unknown_class_is_still_scored():
    score, bucket, parts = score_detection(det("D_future", "new"), ROOT_POD)
    assert parts["unknown_class"] and 0 <= score <= 100
