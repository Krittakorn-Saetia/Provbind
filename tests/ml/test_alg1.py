"""Unit tests for ml/alg1.py: Algorithm 1 with fixed probabilities (MLA-01), effective_set,
and a randomised check that the output is exactly what lines 3-13 define."""
import json
import math
import random
from pathlib import Path

import jsonschema
import pytest

from ml.alg1 import (ALL_CAPS, AUTHENTICATED, CONFIGURED, INFERRED, RUNTIME_DEFAULT_CAPS, Capability,
                     effective_set, infer, normalise)

from .alg1_cases import CASES, run

SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "contracts" / "envelope.schema.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_fixed_probabilities(case):
    got, expected = run(case)
    assert got == expected


# --- inputs Algorithm 1 cannot accept ------------------------------------------------------

@pytest.mark.parametrize("p", [1.2, -0.1, math.nan])
def test_probability_outside_0_1_raises(p):
    with pytest.raises(ValueError, match="probability"):
        infer({"CAP_KILL": p}, None)


@pytest.mark.parametrize("theta", [-0.01, 1.01, math.nan, "0.5"])
def test_theta_outside_0_1_raises(theta):
    with pytest.raises(ValueError, match="theta"):
        infer({}, None, theta=theta)


def test_unknown_capability_raises():
    with pytest.raises(ValueError, match="unknown capability"):
        infer({"CAP_TELEPORT": 0.9}, None)


def test_same_capability_twice_raises():
    with pytest.raises(ValueError, match="twice"):
        infer({"NET_RAW": 0.2, "CAP_NET_RAW": 0.9}, None)


def test_declared_origin_must_be_authenticated_or_configured():
    with pytest.raises(ValueError, match="declared_origin"):
        infer({}, None, declared=["CAP_KILL"], declared_origin=INFERRED)


def test_theta_0_and_1_are_the_extremes():
    probs = {"CAP_KILL": 0.0, "CAP_CHOWN": 1.0}
    assert [c.cap for c in infer(probs, None, theta=0.0)] == ["CAP_CHOWN", "CAP_KILL"]
    assert [c.cap for c in infer(probs, None, theta=1.0)] == ["CAP_CHOWN"]


# --- the envelope entry ---------------------------------------------------------------------

def test_envelope_entries_follow_the_contract():
    got = infer({"CAP_NET_BIND_SERVICE": 0.9, "CAP_KILL": 0.7}, sorted(RUNTIME_DEFAULT_CAPS), declared=["CAP_CHOWN"])
    entries = [c.to_envelope() for c in got]
    assert entries == [{"cap": "CAP_CHOWN", "origin": AUTHENTICATED},
                       {"cap": "CAP_KILL", "origin": INFERRED, "probability": 0.7},
                       {"cap": "CAP_NET_BIND_SERVICE", "origin": INFERRED, "probability": 0.9}]
    jsonschema.Draft202012Validator(SCHEMA["properties"]["capabilities"]).validate(entries)


def test_configured_entry_follows_the_contract():
    entries = [Capability("CAP_CHOWN", CONFIGURED).to_envelope()]
    jsonschema.Draft202012Validator(SCHEMA["properties"]["capabilities"]).validate(entries)


# --- effective_set: 𝒞_K8s from a securityContext ------------------------------------------------

def test_all_caps_is_the_kernel_list():
    assert len(ALL_CAPS) == 41 and len(set(ALL_CAPS)) == 41
    assert ALL_CAPS[0] == "CAP_CHOWN" and ALL_CAPS[-1] == "CAP_CHECKPOINT_RESTORE"
    assert RUNTIME_DEFAULT_CAPS < set(ALL_CAPS) and len(RUNTIME_DEFAULT_CAPS) == 14


@pytest.mark.parametrize("kwargs,expected", [
    ({}, RUNTIME_DEFAULT_CAPS),
    ({"privileged": True, "drop": ["ALL"]}, set(ALL_CAPS)),
    ({"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]}, {"CAP_NET_BIND_SERVICE"}),
    ({"drop": ["all"], "add": ["net_bind_service"]}, {"CAP_NET_BIND_SERVICE"}),
    ({"add": ["ALL"], "drop": ["CHOWN"]}, set(ALL_CAPS) - {"CAP_CHOWN"}),
    ({"add": ["ALL"], "drop": ["ALL"]}, set()),
    ({"drop": ["NET_RAW"]}, RUNTIME_DEFAULT_CAPS - {"CAP_NET_RAW"}),
    ({"add": ["NET_ADMIN"]}, RUNTIME_DEFAULT_CAPS | {"CAP_NET_ADMIN"}),
    ({"add": ["SYS_TIME"], "drop": ["SYS_TIME"]}, RUNTIME_DEFAULT_CAPS),     # drops are applied last
], ids=["defaults", "privileged", "drop-all-add-one", "lowercase", "add-all-drop-one", "add-all-drop-all",
        "drop-one", "add-one", "add-and-drop-same"])
def test_effective_set(kwargs, expected):
    assert effective_set(**kwargs) == frozenset(expected)


def test_normalise():
    assert normalise(" net_raw ") == normalise("NET_RAW") == normalise("CAP_NET_RAW") == "CAP_NET_RAW"
    with pytest.raises(ValueError):
        normalise("ALL")


# --- randomised: the output is exactly lines 3-13 ---------------------------------------------------

def test_output_is_exactly_what_lines_3_to_13_define():
    rng = random.Random(1)
    for _ in range(500):
        probs = {c: rng.random() for c in rng.sample(ALL_CAPS, rng.randint(0, 12))}
        declared = set(rng.sample(ALL_CAPS, rng.randint(0, 4)))
        allowed = None if rng.random() < 0.2 else set(rng.sample(ALL_CAPS, rng.randint(0, 20)))
        theta = rng.choice([0.2, 0.35, 0.5, 0.65, 0.8])
        got = {c.cap: c for c in infer(probs, allowed, declared, theta=theta)}

        bound = set(ALL_CAPS) if allowed is None else allowed
        want_declared = declared & bound
        want_inferred = {c for c, p in probs.items() if p >= theta} & bound
        assert set(got) == want_declared | want_inferred
        for cap, c in got.items():
            assert c.origin == (AUTHENTICATED if cap in want_declared else INFERRED)
            assert c.probability == probs.get(cap)
