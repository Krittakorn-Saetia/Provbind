"""Algorithm 1 with fixed probabilities: the cases MLA-01 checks (tests/ml/test_alg1.py and
tests/capability/test_mla_01_alg1.py both use this table).

Each case: probabilities p_I(c), allowed 𝒞_K8s (None: applied later, per pod), declared 𝒞_decl,
θ_C, the origin for declared capabilities, and the expected (cap, origin, probability) list.
"""
from ml.alg1 import AUTHENTICATED, CONFIGURED, INFERRED, RUNTIME_DEFAULT_CAPS, effective_set

DEFAULTS = sorted(RUNTIME_DEFAULT_CAPS)
A, I = AUTHENTICATED, INFERRED

CASES = [
    dict(name="line 3: the threshold is inclusive",
         probabilities={"CAP_NET_BIND_SERVICE": 0.5, "CAP_NET_RAW": 0.4999}, allowed=DEFAULTS,
         expected=[("CAP_NET_BIND_SERVICE", I, 0.5)]),
    dict(name="line 3: θ_C changes the set",
         probabilities={"CAP_SETUID": 0.8, "CAP_SETGID": 0.2}, allowed=DEFAULTS, theta=0.1,
         expected=[("CAP_SETGID", I, 0.2), ("CAP_SETUID", I, 0.8)]),
    dict(name="line 4: a prediction outside 𝒞_K8s is dropped",
         probabilities={"CAP_NET_ADMIN": 0.95, "CAP_CHOWN": 0.7}, allowed=DEFAULTS,
         expected=[("CAP_CHOWN", I, 0.7)]),
    dict(name="line 5: a declared capability outside 𝒞_K8s is dropped",
         probabilities={}, declared=["CAP_SYS_TIME", "CAP_KILL"], allowed=DEFAULTS,
         expected=[("CAP_KILL", A, None)]),
    dict(name="line 6: declared and inferred are united",
         probabilities={"CAP_SETUID": 0.8, "CAP_SETGID": 0.2}, declared=["CAP_CHOWN"], allowed=DEFAULTS,
         expected=[("CAP_CHOWN", A, None), ("CAP_SETUID", I, 0.8)]),
    dict(name="line 8: declared and predicted is AUTHENTICATED",
         probabilities={"CAP_NET_BIND_SERVICE": 0.9}, declared=["CAP_NET_BIND_SERVICE"], allowed=DEFAULTS,
         expected=[("CAP_NET_BIND_SERVICE", A, 0.9)]),
    dict(name="Eq. (34): with nothing declared, Ĉ ∩ 𝒞_K8s",
         probabilities={"CAP_KILL": 0.6, "CAP_MKNOD": 0.3, "CAP_SYS_ADMIN": 0.99}, allowed=DEFAULTS,
         expected=[("CAP_KILL", I, 0.6)]),
    dict(name="a pod that drops ALL and adds NET_BIND_SERVICE",
         probabilities={"CAP_NET_BIND_SERVICE": 0.8, "CAP_NET_RAW": 0.9, "CAP_CHOWN": 0.6},
         allowed=sorted(effective_set(add=["NET_BIND_SERVICE"], drop=["ALL"])),
         expected=[("CAP_NET_BIND_SERVICE", I, 0.8)]),
    dict(name="a pod with every capability dropped gets none, declared or not",
         probabilities={"CAP_NET_BIND_SERVICE": 0.99}, declared=["CAP_NET_BIND_SERVICE"], allowed=[],
         expected=[]),
    dict(name="pod-spec names without the CAP_ prefix",
         probabilities={"net_bind_service": 0.9}, allowed=["NET_BIND_SERVICE"],
         expected=[("CAP_NET_BIND_SERVICE", I, 0.9)]),
    dict(name="allowed=None skips lines 4-5 (bound applied later, per pod)",
         probabilities={"CAP_NET_ADMIN": 0.9}, declared=["CAP_SYS_TIME"], allowed=None,
         expected=[("CAP_NET_ADMIN", I, 0.9), ("CAP_SYS_TIME", A, None)]),
    dict(name="M9 variant: declared capabilities labelled CONFIGURED",
         probabilities={"CAP_NET_RAW": 0.7}, declared=["CAP_CHOWN"], allowed=DEFAULTS,
         declared_origin=CONFIGURED,
         expected=[("CAP_CHOWN", CONFIGURED, None), ("CAP_NET_RAW", I, 0.7)]),
]


def run(case):
    """Run one case through ml.alg1.infer; returns (got, expected) as comparable lists."""
    from ml.alg1 import THETA_C, infer
    got = infer(case["probabilities"], case["allowed"], case.get("declared", ()),
                theta=case.get("theta", THETA_C), declared_origin=case.get("declared_origin", A))
    return [(c.cap, c.origin, c.probability) for c in got], case["expected"]
