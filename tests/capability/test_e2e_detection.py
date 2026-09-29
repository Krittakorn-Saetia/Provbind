"""E2E-01, E2E-02, E2E-03: the three P0 end-to-end scenarios (Test Plan §3.10, owner R1).

Each reads the integrated run folder produced on the demo PC. In a cloud sandbox the artifacts
are absent, so each records `not_run`. The scenario payloads are harmless test code and run only
inside throwaway demo containers (Test Plan §7).
"""
from .e2e_helpers import DETERMINISTIC, alerts_in, classes, load_run, rows_for


def _blocked_reason(data, scenario):
    if not data["alerts_present"]:
        return f"needs run/alerts.jsonl from the demo PC ({scenario})"
    if not rows_for(data["gt"], scenario):
        return f"no {scenario} row in run/ground_truth.csv (run the scenario first)"
    return None


def test_e2e_01_undeclared_exec_and_write(record_result):
    """attack-1: D_exec undeclared (Critical, 90) and D_write (High, 72) in one chain."""
    data = load_run()
    reason = _blocked_reason(data, "attack-1")
    if reason:
        record_result("E2E-01", "not_run", notes=reason)
        return

    matched = [a for row in rows_for(data["gt"], "attack-1") for a in alerts_in(row, data["alerts"])]
    cls = classes(matched)
    chains = {a.get("chain_id") for a in matched if a.get("class") in ("D_exec", "D_write") and a.get("chain_id")}
    ok = "D_exec/undeclared" in cls and any(c.startswith("D_write") for c in cls) and len(chains) == 1
    record_result("E2E-01", "pass" if ok else "fail",
                  metrics={"alerts": len(matched), "chains": len(chains), "falco_recorded": data["falco_present"]},
                  notes="D_exec undeclared + D_write in one chain" if ok
                        else f"expected D_exec/undeclared + D_write in one chain; got {sorted(cls)}, chains={chains}")
    assert ok


def test_e2e_02_benign(record_result):
    """benign-1: nothing above Low."""
    data = load_run()
    reason = _blocked_reason(data, "benign-1")
    if reason:
        record_result("E2E-02", "not_run", notes=reason)
        return

    matched = [a for row in rows_for(data["gt"], "benign-1") for a in alerts_in(row, data["alerts"])]
    above_low = [a for a in matched if (a.get("bucket", "").lower() != "low")]
    ok = not above_low
    record_result("E2E-02", "pass" if ok else "fail",
                  metrics={"alerts": len(matched), "above_low": len(above_low),
                           "falco_recorded": data["falco_present"]},
                  notes="nothing above Low" if ok
                        else f"{len(above_low)} alert(s) above Low: {sorted(classes(above_low))}")
    assert ok


def test_e2e_03_in_envelope_burst(record_result):
    """attack-2: D_beh only, no deterministic detection."""
    data = load_run()
    reason = _blocked_reason(data, "attack-2")
    if reason:
        record_result("E2E-03", "not_run", notes=reason)
        return

    matched = [a for row in rows_for(data["gt"], "attack-2") for a in alerts_in(row, data["alerts"])]
    cls = classes(matched)
    det = {c for c in cls if c.split("/")[0] in DETERMINISTIC}
    has_beh = any(c.split("/")[0] == "D_beh" for c in cls)
    ok = has_beh and not det
    record_result("E2E-03", "pass" if ok else "fail",
                  metrics={"alerts": len(matched), "deterministic": len(det),
                           "falco_recorded": data["falco_present"]},
                  notes="D_beh only" if ok else f"expected D_beh only; got {sorted(cls)}")
    assert ok
