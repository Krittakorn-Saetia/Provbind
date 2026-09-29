"""E2E-11 (trust withdrawal) and E2E-12 (log tampering): P0 end-to-end, owner R1 (§3.10).

Both need integrated artifacts from the demo PC: E2E-11 needs the trust alert Role 4 writes when
`requestz-helper` is marked malicious (scenario trust-1), and E2E-12 needs Role 4's hash-chained
log and its `verify_log`. In a cloud sandbox these are absent, so both record `not_run` with the
check they perform on the PC. Scenario triggers are harmless (edit a local advisory / one log
character); see Test Plan §7.
"""
import os
import re

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
    """tamper-1: after one character is changed in the log, verify_log fails at that record.

    tamper.sh records the edited record in its ground-truth row ("... at record k=N"), so the test
    checks verify_log's first broken record is exactly N, not merely that the chain is broken.
    """
    run = os.environ.get("PROVBIND_RUN", "./run")
    log = os.path.join(run, "log", "violations.jsonl")

    # verify_log is Role 4's (alerts/verify_log.py); it may not exist in a Role 1 checkout.
    try:
        from alerts import verify_log
    except Exception:
        verify_log = None

    rows = rows_for(load_run()["gt"], "tamper-1")
    if verify_log is None or not os.path.isfile(log) or not rows:
        record_result("E2E-12", "not_run",
                      notes="needs Role 4's alerts.verify_log, run/log/violations.jsonl and a tamper-1 row: "
                            "make tamper edits one character and records the edited k")
        return

    m = re.search(r"k=(\d+)", rows[-1].get("expected", ""))
    edited = int(m.group(1)) if m else None
    result = verify_log.verify(run)
    ok = (not result.ok) and result.first_bad is not None and (edited is None or result.first_bad == edited)
    record_result("E2E-12", "pass" if ok else "fail",
                  metrics={"edited_k": edited, "first_bad": result.first_bad, "records": result.records},
                  notes=f"verify_log fails at the edited record k={result.first_bad}" if ok
                        else f"expected verify_log to fail at k={edited}; got ok={result.ok}, "
                             f"first_bad={result.first_bad} ({result.reason})")
    assert ok
