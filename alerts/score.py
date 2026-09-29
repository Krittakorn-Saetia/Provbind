#!/usr/bin/env python3
"""
alerts/score.py
Multi-factor severity scoring engine for PROVBIND runtime deviations.
Calculates severity score (0-100) and assigns severity buckets (Critical, High, Medium, Low).
Includes unit tests matching PROVBIND Sprint Handoff Section 8 specifications.
"""

def calculate_severity(detection_class, subclass, origin="AUTHENTICATED", depth=None, in_no_layer=True, is_root=True, privileged=False):
    """
    Calculates severity score (0-100) and bucket based on multi-factor formula:
    S = 0.4 * s_type + 0.2 * s_origin + 0.4 * (0.5 * rho + 0.5 * kappa)
    """
    if detection_class == "binding" and subclass == "unknown_container":
        return 60, "high"

    # 1. Deviation Type Weight (s_type)
    if detection_class == "D_exec" and subclass == "undeclared":
        s_type = 1.00
    elif detection_class == "D_hash" and subclass == "modified":
        s_type = 1.00
    elif detection_class in ["D_write", "D_write_immutable"]:
        s_type = 0.80
    elif detection_class == "D_hash" and subclass == "relocated":
        s_type = 0.70
    elif detection_class == "D_exec" and subclass == "outside_closure":
        s_type = 0.25
    else:
        s_type = 0.50

    # 2. Signature Origin (s_origin)
    s_origin = 1.0 if origin == "AUTHENTICATED" else 0.5

    # 3. Provenance Distance (rho)
    if in_no_layer:
        rho = 1.0  # Absent from image/SBOM entirely
    elif depth is None:
        rho = 0.5  # Declared but owned by no package or depth unknown
    else:
        rho = depth / (1.0 + depth)

    # 4. Privilege Context (kappa)
    if privileged:
        kappa = 1.0
    elif is_root:
        kappa = 0.5
    else:
        kappa = 0.2

    # Score calculation
    S = (0.4 * s_type) + (0.2 * s_origin) + (0.4 * (0.5 * rho + 0.5 * kappa))
    score = round(100 * S)

    # Cap outside_closure score at 34
    if detection_class == "D_exec" and subclass == "outside_closure":
        score = min(score, 34)

    # Bucket assignment
    if score >= 80:
        bucket = "critical"
    elif score >= 60:
        bucket = "high"
    elif score >= 35:
        bucket = "medium"
    else:
        bucket = "low"

    return score, bucket

def run_unit_tests():
    """Unit tests for expected scores from PROVBIND Sprint Handoff Section 8."""
    print("🧪 Running alerts/score.py unit tests...")

    # Test 1: /tmp/.x9 executed (D_exec, undeclared, root, non-privileged)
    score1, bucket1 = calculate_severity("D_exec", "undeclared", origin="AUTHENTICATED", depth=None, in_no_layer=True, is_root=True, privileged=False)
    assert score1 == 90 and bucket1 == "critical", f"Test 1 Failed: got score {score1}, bucket {bucket1} (expected 90, critical)"
    print("  ✅ Test 1 Passed: /tmp/.x9 exec -> Score 90 (critical)")

    # Test 2: /etc/passwd written (D_write, declared_file, root, non-privileged)
    score2, bucket2 = calculate_severity("D_write", "declared_file", origin="AUTHENTICATED", depth=None, in_no_layer=False, is_root=True, privileged=False)
    assert score2 == 72 and bucket2 == "high", f"Test 2 Failed: got score {score2}, bucket {bucket2} (expected 72, high)"
    print("  ✅ Test 2 Passed: /etc/passwd write -> Score 72 (high)")

    # Test 3: /usr/bin/ls executed (D_exec, outside_closure, root, non-privileged)
    score3, bucket3 = calculate_severity("D_exec", "outside_closure", origin="AUTHENTICATED", depth=None, in_no_layer=False, is_root=True, privileged=False)
    assert score3 == 34 and bucket3 == "low", f"Test 3 Failed: got score {score3}, bucket {bucket3} (expected 34, low)"
    print("  ✅ Test 3 Passed: /usr/bin/ls exec (outside_closure) -> Score 34 (low)")

    print("🎉 All scoring unit tests passed successfully!\n")

if __name__ == "__main__":
    run_unit_tests()
