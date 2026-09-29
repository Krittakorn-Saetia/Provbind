"""E2E-11 (trust withdrawal) and E2E-12 (log tampering): P0 end-to-end, owner R1 (§3.10).

Both need integrated artifacts from the demo PC: E2E-11 needs the trust alert Role 4 writes when
`requestz-helper` is marked malicious (scenario trust-1), and E2E-12 needs Role 4's hash-chained
log and its `verify_log`. In a cloud sandbox these are absent, so both record `not_run` with the
check they perform on the PC. Scenario triggers are harmless (edit a local advisory / one log
character); see Test Plan §7.
"""
import os

from .e2e_helpers import DETERMINISTIC, alerts_in, load_run, rows_for


def _is_trust_alert(a):
    """A trust alert (Phase 6), tolerant of Role 4's exact field: a class/kind of 'trust',
    or a top-level trust reason (key/builder/comp/trans)."""
    for key in ("class", "kind", "type"):
        if str(a.get(key, "")).lower().startswith("trust"):
            return True
    return bool(a.get("trust_reason") or a.get("trust"))


def test_e2e_11_trust_withdrawal(record_result):
    """trust-1: one trust alert appears while the runtime state stays conforming."""
    data = load_run()
    if not data["alerts_present"] or not rows_for(data["gt"], "trust-1"):
        record_result("E2E-11", "not_run",
                      notes="needs run/alerts.jsonl and a trust-1 row: mark requestz-helper malicious "
                            "in the local advisory (Role 4 trust loop), runtime stays conforming")
        return

    matched = [a for row in rows_for(data["gt"], "trust-1") for a in alerts_in(row, data["alerts"])]
    trust_alerts = [a for a in matched if _is_trust_alert(a)]
    runtime_dets = [a for a in matched if a.get("class") in DETERMINISTIC]
    ok = len(trust_alerts) >= 1 and not runtime_dets
    record_result("E2E-11", "pass" if ok else "fail",
                  metrics={"trust_alerts": len(trust_alerts), "runtime_detections": len(runtime_dets)},
                  notes="one trust alert; runtime still conforming" if ok
                        else f"trust_alerts={len(trust_alerts)}, runtime_detections={len(runtime_dets)}")
    assert ok


def test_e2e_12_log_tampering(record_result):
    """tamper-1: after one character is changed in the log, verify_log fails at that record."""
    run = os.environ.get("PROVBIND_RUN", "./run")
    log = os.path.join(run, "log", "violations.jsonl")

    # verify_log is Role 4's (alerts/verify_log.py); it may not exist in a Role 1 checkout.
    try:
        from alerts import verify_log  # noqa: F401
        have_verify = True
    except Exception:
        have_verify = False

    if not have_verify or not os.path.isfile(log):
        record_result("E2E-12", "not_run",
                      notes="needs Role 4's alerts.verify_log and run/log/violations.jsonl; on the PC, "
                            "edit one character (scenario tamper-1) and verify_log reports the first bad k")
        return

    # On the PC: recompute the chain and confirm a broken record is reported. verify_log's exact
    # API is Role 4's; this asserts only that it flags a tampered record.
    result = verify_log.verify(run) if hasattr(verify_log, "verify") else None
    ok = bool(result) and not getattr(result, "ok", True)
    record_result("E2E-12", "pass" if ok else "fail",
                  metrics={"broken_k": getattr(result, "first_bad", None)},
                  notes="verify_log reported the edited record" if ok
                        else "verify_log did not flag a tampered record (check tamper-1 ran)")
    assert ok
