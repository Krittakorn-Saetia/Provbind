"""Phase 5 Step 2: the severity score (Sprint Handoff §8; Explanation §8, Eqs. 65-68).

    S = 0.4*s_type + 0.2*s_origin + 0.4*(0.5*rho + 0.5*kappa)        score = round(100*S)

- s_type per detection class. Sprint Handoff §8 gives the demo classes; Explanation §8 and Role 3's
  handoff (node/handoff/ROLE3-TO-ROLE4.md §2) add D_load, D_cap and D_net. The two weak classes
  (a declared exec or load outside the closure) are capped at Low (34).
- s_origin: AUTHENTICATED 1.0, anything else (INFERRED, CONFIGURED) 0.5.
- rho from the detection's context: not declared (the file is in no layer) 1.0; declared but owned
  by no package, or its depth unresolved, 0.5 (never scored like a dropped binary, M16);
  otherwise depth/(1+depth).
- kappa, the demo's stand-in for the capability class, from the container's binding: privileged
  1.0, root 0.5, non-root 0.2.
- binding failures score a fixed 60 (High).
- D_beh (ML-B) uses S_beh = 0.6*g_I + 0.4*s_c, capped at 59 (Medium), so a behavioural hint never
  outranks a signed contradiction (M2, MLB-07). g_I is read from the detection's detail.

Scores never change the detection set: every detection gets exactly one score (Eq. 68).
"""
from __future__ import annotations

import math
import re
from typing import Mapping

S_TYPE = {
    ("D_exec", "undeclared"): 1.00,
    ("D_hash", "modified"): 1.00,
    ("D_load", "undeclared"): 0.85,
    ("D_write", None): 0.80,                       # any D_write subclass
    ("D_hash", "relocated"): 0.70,
    ("D_cap", None): 0.60,
    ("D_net", None): 0.55,
    ("D_exec", "outside_closure"): 0.25,
    ("D_load", "outside_closure"): 0.25,
}
WEAK = {("D_exec", "outside_closure"), ("D_load", "outside_closure")}
WEAK_CAP = 34                                      # Low
BEH_CAP = 59                                       # Medium
BINDING_SCORE = 60                                 # High
UNKNOWN_S_TYPE = 0.50
BUCKETS = ((80, "critical"), (60, "high"), (35, "medium"), (0, "low"))
G_I = re.compile(r"g_I\s+([0-9]*\.?[0-9]+)")


def bucket_of(score: int) -> str:
    for floor, name in BUCKETS:
        if score >= floor:
            return name
    return "low"


def to_score(s: float) -> int:
    """100*S rounded half up, with S clamped to [0, 1]."""
    return int(math.floor(100 * min(1.0, max(0.0, s)) + 0.5 + 1e-9))


def s_type_of(cls: str, subclass: str | None) -> tuple[float, bool]:
    """(s_type, known). Unknown classes still get a score, so no detection is dropped."""
    if (cls, subclass) in S_TYPE:
        return S_TYPE[(cls, subclass)], True
    if (cls, None) in S_TYPE:
        return S_TYPE[(cls, None)], True
    return UNKNOWN_S_TYPE, False


def s_origin_of(origin: str | None) -> float:
    return 1.0 if origin == "AUTHENTICATED" else 0.5


def rho_of(context: Mapping | None) -> float:
    ctx = context or {}
    if ctx.get("declared") is False:
        return 1.0
    depth = ctx.get("depth")
    if ctx.get("package") is None or depth is None or not isinstance(depth, (int, float)) or depth < 0:
        return 0.5
    return depth / (1.0 + depth)


def kappa_of(binding: Mapping | None) -> float:
    """From bindings.json. With no binding the demo's default pod (root, not privileged) is assumed."""
    b = binding or {}
    if b.get("privileged"):
        return 1.0
    if b.get("run_as_root", True):
        return 0.5
    return 0.2


def g_of(detection: Mapping) -> float:
    """g_I from a D_beh detail ("... anomaly 0.1234, g_I 0.987 ..."); 1.0 if it cannot be read."""
    m = G_I.search(str((detection.get("clause") or {}).get("detail", "")))
    return min(1.0, max(0.0, float(m.group(1)))) if m else 1.0


def score_detection(detection: Mapping, binding: Mapping | None = None) -> tuple[int, str, dict]:
    """(score 0-100, bucket, the parts used) for one detection."""
    cls, sub = detection.get("class"), detection.get("subclass")
    if cls == "binding":
        return BINDING_SCORE, bucket_of(BINDING_SCORE), {"rule": "binding: fixed score"}

    rho, kappa = rho_of(detection.get("context")), kappa_of(binding)
    s_c = 0.5 * rho + 0.5 * kappa
    if cls == "D_beh":
        g = g_of(detection)
        score = min(to_score(0.6 * g + 0.4 * s_c), BEH_CAP)
        return score, bucket_of(score), {"rule": "S_beh", "g_I": g, "rho": rho, "kappa": kappa, "cap": BEH_CAP}

    s_type, known = s_type_of(cls, sub)
    s_origin = s_origin_of(detection.get("origin"))
    s = 0.4 * s_type + 0.2 * s_origin + 0.4 * s_c
    score = to_score(s)
    parts = {"rule": "S_det", "S": round(s, 6), "s_type": s_type, "s_origin": s_origin, "rho": rho, "kappa": kappa}
    if (cls, sub) in WEAK:
        score = min(score, WEAK_CAP)
        parts["cap"] = WEAK_CAP
    if not known:
        parts["unknown_class"] = True
    return score, bucket_of(score), parts


if __name__ == "__main__":
    # The Sprint Handoff §8 examples, for a root, non-privileged pod.
    for name, det, expected in (
            ("/tmp/.x9 executed", {"class": "D_exec", "subclass": "undeclared", "origin": "AUTHENTICATED",
                                   "context": {"declared": False}}, (90, "critical")),
            ("/etc/passwd written", {"class": "D_write", "subclass": "declared_file", "origin": "AUTHENTICATED",
                                     "context": {"declared": True, "package": None, "depth": None}}, (72, "high")),
            ("/usr/bin/ls executed", {"class": "D_exec", "subclass": "outside_closure", "origin": "AUTHENTICATED",
                                      "context": {"declared": True, "package": "pkg:deb/debian/coreutils@9.1-1",
                                                  "depth": None}}, (34, "low"))):
        got = score_detection(det)[:2]
        print(f"{name}: {got[0]} {got[1]} (expected {expected[0]} {expected[1]})")
        assert got == expected
