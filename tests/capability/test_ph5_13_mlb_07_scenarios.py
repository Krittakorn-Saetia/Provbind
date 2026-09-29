"""PH5-13 (R4, P1): attack-1 forms one chain (M7). MLB-07 (R4, P1): behavioural scores never outrank
contradictions (M2). Test Plan §3.8 and §3.7.

- PH5-13 pass: attack-1's detections (the undeclared exec and the write) share one `chain_id`.
- MLB-07: the ordering of attack-1's and attack-2's alerts is reported; pass when no D_beh alert
  scores above a contradiction (S_beh is capped at 59, alerts.score).

Real input: the run folder's alerts.jsonl and ground_truth.csv (the demo PC, after `make demo`),
matched to the scenario rows as Role 1's E2E tests do. Otherwise the alert engine runs on Role
3-shaped synthetic detections (tests/alerts/helpers.py; for MLB-07, a D_beh at g_I = 1.0, the
most anomalous window possible) and the results are not_run.
"""
from alerts.attribute import Attributor
from alerts.run import AlertEngine

from tests.alerts.helpers import attack_and_benign, detection, golden, read_jsonl, write_detections, write_run
from tests.capability import e2e_helpers

def is_contradiction(a):
    """attack-1's signed contradictions: the undeclared exec and the write."""
    return a.get("class") == "D_write" or (a.get("class"), a.get("subclass")) == ("D_exec", "undeclared")


def real_alerts(scenario):
    data = e2e_helpers.load_run()
    rows = e2e_helpers.rows_for(data["gt"], scenario)
    if not data["alerts_present"] or not rows:
        return None
    return [a for row in rows for a in e2e_helpers.alerts_in(row, data["alerts"])]


def synthetic(tmp_path, with_beh=False):
    env = golden()
    run = write_run(tmp_path, env)
    dets = attack_and_benign(env)[2:]                                        # attack-1: det-0003, det-0004
    if with_beh:
        dets.append(detection(env, 5, "D_beh", "window", "/usr/local/bin/python3.11", pid=4402, ppid=4100,
                              time="2026-09-29T10:10:00.000Z", origin="INFERRED", kind="behaviour",
                              detail="window anomaly 0.93 above theta_A 0.61, g_I 1.0"))
    write_detections(run, dets)
    AlertEngine(run, attributor=Attributor(use_neo4j=False)).run_loop(once=True)
    return read_jsonl(run / "alerts.jsonl")


def test_ph5_13_attack_1_is_one_chain(tmp_path, record_result):
    alerts = real_alerts("attack-1")
    real = alerts is not None
    source = "the run folder's attack-1 alerts" if real else "synthetic attack-1 detections through the alert engine"
    alerts = alerts if real else synthetic(tmp_path)
    x9 = [a for a in alerts if a.get("class") == "D_exec" and a.get("subclass") == "undeclared"]
    wr = [a for a in alerts if a.get("class") == "D_write"]
    chains = sorted({a.get("chain_id") for a in x9 + wr})
    ok = bool(x9) and bool(wr) and len(chains) == 1
    notes = f"{source}: {len(x9)} undeclared exec(s) and {len(wr)} write(s) in chain(s) {chains}"
    status = ("pass" if ok else "fail") if real else ("not_run" if ok else "fail")
    if not real:
        notes += "; synthetic, so run attack-1 on the demo PC (make demo)"
    record_result("PH5-13", status, metrics={"chains": chains, "exec": len(x9), "write": len(wr)}, notes=notes)
    assert ok, notes


def test_mlb_07_behaviour_never_outranks_a_contradiction(tmp_path, record_result):
    a1, a2 = real_alerts("attack-1"), real_alerts("attack-2")
    real = a1 is not None and a2 is not None
    alerts = (a1 + a2) if real else synthetic(tmp_path, with_beh=True)
    source = "the run folder's attack-1 and attack-2 alerts" if real else "synthetic attack-1 and a D_beh at g_I 1.0"
    beh = [a for a in alerts if a.get("class") == "D_beh"]
    contra = [a for a in alerts if is_contradiction(a)]
    order = [f"{a.get('class')}/{a.get('subclass')} {a.get('score')}"
             for a in sorted(alerts, key=lambda a: (-a.get("score", 0), a.get("time") or ""))]
    ok = bool(beh) and bool(contra) and max(a["score"] for a in beh) < min(a["score"] for a in contra)
    notes = f"{source}: ordering {order}" + ("" if beh else "; no D_beh alert (attack-2 needs ML-B, MLB-05)")
    status = ("pass" if ok else "fail") if real else ("not_run" if ok else "fail")
    if real and not beh:
        status = "blocked"
    if not real:
        notes += "; synthetic, so run attack-1 and attack-2 on the demo PC with MLB=--mlb"
    record_result("MLB-07", status, metrics={"ordering": order, "beh_max": max((a["score"] for a in beh), default=None),
                                             "contradiction_min": min((a["score"] for a in contra), default=None)},
                  notes=notes)
    assert ok or (real and not beh), notes
