"""Algorithm 1, Evidence-Aware Capability Inference (Aj Ohm's draft, Phase 3 Step 3,
Eqs. 33-34), from the model's probabilities onwards:

    3:  Ĉ_inf  ← {c | p(c) ≥ θ_C}
    4:  Ĉ_inf  ← Ĉ_inf ∩ 𝒞_K8s
    5:  𝒞_decl ← 𝒞_decl ∩ 𝒞_K8s
    6:  𝒞      ← 𝒞_decl ∪ Ĉ_inf
    7-13: π(c) = AUTHENTICATED if c ∈ 𝒞_decl, else INFERRED
    14: return (𝒞, π)

Lines 1-2 (the features Ω_I and the model) are ml/features.py and the trained model.
Taking the probabilities as input lets MLA-01 test this logic before any model exists.
With nothing declared, the result is Eq. (34) with a threshold: {c | p(c) ≥ θ_C} ∩ 𝒞_K8s.

Two points the draft leaves open are parameters, so both readings can be run side by side
(Test Plan §0, rule 1):
- `allowed=None` skips lines 4-5. Use it when 𝒞_K8s is known only per pod and the caller
  applies Eq. (34) later (Role 2 handoff §13, decision 4).
- `declared_origin`: the draft labels declared capabilities AUTHENTICATED. Fail point M9
  proposes CONFIGURED when they come from the pod spec rather than from signed evidence.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Mapping

AUTHENTICATED = "AUTHENTICATED"
INFERRED = "INFERRED"
CONFIGURED = "CONFIGURED"
THETA_C = 0.5                                   # Test Plan §4.4 default

# include/uapi/linux/capability.h: CAP_CHOWN (0) to CAP_CHECKPOINT_RESTORE (40, CAP_LAST_CAP).
ALL_CAPS = (
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
    "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK",
    "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG",
    "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
)

# What a container gets when its pod spec adds and drops nothing: containerd's
# defaultUnixCaps() and Docker's DefaultCapabilities() list the same 14.
RUNTIME_DEFAULT_CAPS = frozenset({
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW",
    "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE",
    "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE",
})


def normalise(name: str) -> str:
    """"net_raw", "NET_RAW" or "CAP_NET_RAW" -> "CAP_NET_RAW". Pod specs omit the prefix."""
    cap = name.strip().upper()
    if not cap.startswith("CAP_"):
        cap = "CAP_" + cap
    if cap not in ALL_CAPS:
        raise ValueError(f"unknown capability: {name!r}")
    return cap


def _normalised_set(names: Iterable[str]) -> set[str]:
    return {normalise(n) for n in names}


def effective_set(add: Iterable[str] = (), drop: Iterable[str] = (), privileged: bool = False,
                  base: Iterable[str] = RUNTIME_DEFAULT_CAPS) -> frozenset[str]:
    """𝒞_K8s for one container, as containerd's CRI plugin builds it from securityContext:
    a privileged container gets every capability; otherwise start from `base`, then apply
    add ALL, drop ALL, the individual adds and the individual drops, in that order. So
    drop: [ALL], add: [NET_BIND_SERVICE] leaves exactly CAP_NET_BIND_SERVICE."""
    if privileged:
        return frozenset(ALL_CAPS)
    add, drop = list(add), list(drop)
    caps = set(ALL_CAPS) if any(a.strip().upper() == "ALL" for a in add) else _normalised_set(base)
    if any(d.strip().upper() == "ALL" for d in drop):
        caps = set()
    caps |= {normalise(a) for a in add if a.strip().upper() != "ALL"}
    caps -= {normalise(d) for d in drop if d.strip().upper() != "ALL"}
    return frozenset(caps)


@dataclass(frozen=True)
class Capability:
    cap: str
    origin: str                          # AUTHENTICATED, INFERRED, or CONFIGURED (M9 variant)
    probability: float | None = None     # p_I(c); None for a declared capability with no score

    def to_envelope(self) -> dict:
        """The envelope's capability entry. `probability` is an extra field, which the
        contract allows and readers ignore (Role 2 handoff §8)."""
        entry = {"cap": self.cap, "origin": self.origin}
        if self.probability is not None:
            entry["probability"] = self.probability
        return entry


def infer(probabilities: Mapping[str, float], allowed: Iterable[str] | None,
          declared: Iterable[str] = (), theta: float = THETA_C,
          declared_origin: str = AUTHENTICATED) -> list[Capability]:
    """Algorithm 1, lines 3-14, sorted by capability name.

    probabilities: p_I(c) per capability, each in [0, 1].
    allowed: 𝒞_K8s, or None when it is applied later, per pod.
    declared: 𝒞_decl.
    """
    if not isinstance(theta, (int, float)) or math.isnan(theta) or not 0.0 <= theta <= 1.0:
        raise ValueError(f"theta must be in [0, 1], got {theta!r}")
    if declared_origin not in (AUTHENTICATED, CONFIGURED):
        raise ValueError(f"declared_origin must be AUTHENTICATED or CONFIGURED, got {declared_origin!r}")

    probs: dict[str, float] = {}
    for name, p in probabilities.items():
        cap, p = normalise(name), float(p)
        if math.isnan(p) or not 0.0 <= p <= 1.0:
            raise ValueError(f"probability for {name} must be in [0, 1], got {p!r}")
        if cap in probs:
            raise ValueError(f"{name!r} names {cap} twice")
        probs[cap] = p

    inferred = {c for c, p in probs.items() if p >= theta}                  # line 3
    declared_set = _normalised_set(declared)
    if allowed is not None:
        bound = _normalised_set(allowed)
        inferred &= bound                                                      # line 4
        declared_set &= bound                                                  # line 5
    result = declared_set | inferred                                           # line 6
    return [Capability(c, declared_origin if c in declared_set else INFERRED,  # lines 7-13
                       probs.get(c)) for c in sorted(result)]
