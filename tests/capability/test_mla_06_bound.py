"""MLA-06: predictions never exceed the pod's allowed set 𝒞_K8s (Eq. 34; Test Plan §3.4).

Algorithm 1 runs end to end for each pod: z_I from the envelope and the pod's securityContext
(line 1), a predictor (line 2), then lines 3-14 with 𝒞_K8s from that securityContext. The
predictor is the worst case: probability 1.0 for all 41 kernel capabilities, and every
capability declared as well. If nothing escapes 𝒞_K8s then, no trained model can make it
escape, so this needs no model. Pods: named cases (capabilities dropped, added, privileged)
plus 1,000 random securityContexts.

Pass: zero capabilities outside 𝒞_K8s.

Scope: this proves Algorithm 1 never exceeds the allowed set it is given. It does not prove
that envelopes are capped: the compiler works per image, cannot know the pod, and leaves
𝒞_K8s unset until handoff §13 decision 4 settles who applies it. The notes say so.
"""
import json
import random
from pathlib import Path

from ml.alg1 import ALL_CAPS, RUNTIME_DEFAULT_CAPS, effective_set, infer
from ml.features import extract

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = json.loads((ROOT / "compiler" / "tests" / "golden" / "envelope.json").read_text())
CONFIG = {"User": "", "ExposedPorts": {"8080/tcp": {}}, "Env": []}
SHORT = [c[len("CAP_"):] for c in ALL_CAPS]

NAMED_PODS = {
    "drop ALL, add NET_BIND_SERVICE": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE"]},
    "drop ALL": {"drop": ["ALL"]},
    "drop NET_RAW and CHOWN": {"drop": ["NET_RAW", "CHOWN"]},
    "runtime defaults": {},
    "add NET_ADMIN": {"add": ["NET_ADMIN"]},
    "privileged": {"privileged": True},
}


def worst_case_model(z):
    """Line 2 at its most permissive: every capability, with certainty."""
    return {cap: 1.0 for cap in ALL_CAPS}


def random_pods(n, seed=6):
    rng = random.Random(seed)
    for _ in range(n):
        yield {"add": rng.sample(SHORT + ["ALL"], rng.randint(0, 3)),
               "drop": rng.sample(SHORT + ["ALL"], rng.randint(0, 5)),
               "privileged": rng.random() < 0.05}


def test_mla_06_predictions_never_exceed_the_allowed_set(record_result):
    pods = list(NAMED_PODS.values()) + list(random_pods(1000))
    predictions = outside = 0
    for pod in pods:
        allowed = effective_set(pod.get("add", ()), pod.get("drop", ()), pod.get("privileged", False))
        z = extract(GOLDEN, CONFIG, deployment=pod)                              # line 1
        got = infer(worst_case_model(z), sorted(allowed), declared=ALL_CAPS)    # lines 2-14
        predictions += len(got)
        outside += sum(c.cap not in allowed for c in got)
    tightest = infer(worst_case_model(None), sorted(effective_set(add=["NET_BIND_SERVICE"], drop=["ALL"])))
    ok = outside == 0 and [c.cap for c in tightest] == ["CAP_NET_BIND_SERVICE"]
    record_result("MLA-06", "pass" if ok else "fail",
                  metrics={"pods": len(pods), "predictions": predictions, "outside_k8s": outside,
                           "runtime_defaults": len(RUNTIME_DEFAULT_CAPS)},
                  notes="worst-case predictor (p = 1.0 for all 41 capabilities, all declared) through Ω_I and "
                        "Algorithm 1; 6 named pods and 1,000 random securityContexts; no trained model needed. "
                        "Algorithm 1 only: envelopes are not capped at 𝒞_K8s yet, because the compiler cannot "
                        "know the pod (handoff §13 decision 4)"
                        + ("" if ok else f"; {outside} capabilities outside 𝒞_K8s"))
    assert ok
