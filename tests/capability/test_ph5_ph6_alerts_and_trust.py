"""PH5-06, PH5-08, PH5-09 (attribution and alert fields) and PH6-06 (alert once): Role 4, §3.8-3.9.

PH5-06/08/09 run the alert engine on an envelope with Role 3-shaped detections. With
PROVBIND_ENVELOPE set to a real envelope (the stand-in's or the demo's) they record pass or fail;
with the golden synthetic envelope they record not_run. PH5-09 checks the run folder's real
alerts.jsonl instead when one exists (the demo PC, after `make demo`).
PH6-06 is a property of the trust loop (alert only on the 1 -> 0 flip), recorded anywhere.
"""
import json
import os
import shutil
from pathlib import Path

from alerts.attribute import Attributor
from alerts.run import AlertEngine
from alerts.trust import cycle, set_key

from tests.alerts.helpers import ROOT, detection, golden, read_jsonl, write_run

ALERT_KEYS = ["alert_id", "detection_id", "time", "image_digest", "container", "class", "subclass", "violated_clause",
              "origin", "score", "bucket", "attribution", "signing_identity", "chain_id", "log_k"]


def envelope():
    path = os.environ.get("PROVBIND_ENVELOPE")
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8")), path, True
    return golden(), "the golden envelope of compiler/tests/golden", False


def known_file(env):
    """A declared file with a layer, preferring /usr/bin/ls (every Debian-based image has it)."""
    files = env["files"]
    if "/usr/bin/ls" in files:
        return "/usr/bin/ls"
    return next(p for p, m in sorted(files.items()) if m.get("layer") is not None)


def run_engine(tmp_path, env):
    run = write_run(tmp_path, env)
    path = known_file(env)
    dets = [detection(env, 1, "D_exec", "outside_closure", path, pid=900, ppid=880, kind="closure", detail="not reachable"),
            detection(env, 2, "D_exec", "undeclared", "/tmp/.x9"),
            detection(env, 3, "D_write", "declared_file", "/etc/passwd", exe="/tmp/.x9", detail="write to a declared file")]
    with open(run / "detections.jsonl", "w", encoding="utf-8") as f:
        f.writelines(json.dumps(d) + "\n" for d in dets)
    AlertEngine(run, attributor=Attributor(use_neo4j=False)).run_loop(once=True)
    return {a["detection_id"]: a for a in read_jsonl(run / "alerts.jsonl")}, path


def status(ok, real):
    return ("pass" if ok else "fail") if real else "not_run"


def test_ph5_06_and_08_layer_paths(tmp_path, record_result):
    env, source, real = envelope()
    alerts, path = run_engine(tmp_path, env)
    meta = env["files"][path]
    want = next(l["digest"] for l in env["layers"] if l["index"] == meta["layer"])
    got = alerts["det-0001"]["attribution"]["layer"]
    ok6 = got == want
    note = "" if real else "; synthetic, so set PROVBIND_ENVELOPE to a real envelope for the real test"
    record_result("PH5-06", status(ok6, real), metrics={"file": path, "layer_index": meta["layer"], "layer": got},
                  notes=f"{source}: {path} attributed to layer {meta['layer']} ({str(got)[:19]}), as the envelope says{note}")
    x9 = alerts["det-0002"]["attribution"]
    ok8 = x9["layer"] is None and x9["package"] is None and x9["depth"] is None
    record_result("PH5-08", status(ok8, real), metrics={"attribution": x9},
                  notes=f"{source}: /tmp/.x9 is introduced by no layer and owned by no package{note}")
    assert ok6 and ok8


def test_ph5_09_alert_fields(tmp_path, record_result):
    run_alerts = Path(os.environ.get("PROVBIND_RUN", "./run")) / "alerts.jsonl"
    if run_alerts.exists() and run_alerts.stat().st_size:
        alerts, source, real = read_jsonl(run_alerts), f"{run_alerts}", True
    else:
        env, source, real = envelope()
        alerts = list(run_engine(tmp_path, env)[0].values())
    detection_alerts = [a for a in alerts if a.get("class") != "trust"]
    missing = [a.get("alert_id") for a in alerts if any(k not in a for k in ALERT_KEYS)]
    unsigned = [a.get("alert_id") for a in detection_alerts
                if not (a.get("signing_identity") or {}).get("builder_id") or not a.get("violated_clause") or not a.get("origin")]
    ok = bool(alerts) and not missing and not unsigned
    record_result("PH5-09", status(ok, real), metrics={"alerts": len(alerts), "missing_fields": len(missing),
                                                        "without_signing_identity": len(unsigned)},
                  notes=f"{source}: {len(alerts)} alerts; clause, origin, score, attribution and signing identity "
                        f"{'present in every one' if ok else f'missing in {missing[:3] + unsigned[:3]}'}"
                        + ("" if real else "; synthetic, so run on a real envelope or after make demo"))
    assert ok


def test_ph6_06_alert_only_on_the_flip(tmp_path, record_result):
    env = golden()
    run = write_run(tmp_path, env)
    key = ROOT / "pipeline" / "keys" / "cosign.pub"
    from alerts.trust import key_id_of
    (run / "contexts").mkdir()
    (run / "contexts" / f"{env['image']['digest'].split(':')[1]}.json").write_text(json.dumps(
        {"digest": env["image"]["digest"], "t0": "2026-09-29T08:00:00Z", "key": {"key_id": key_id_of(key)}}))
    cycle(run)
    set_key(run, str(key), "revoked", None)
    per_cycle = [len(cycle(run)) for _ in range(5)]
    ok = per_cycle == [1, 0, 0, 0, 0]
    record_result("PH6-06", "pass" if ok else "fail", metrics={"alerts_per_cycle": per_cycle},
                  notes="untrusted for 5 cycles after the key is revoked: exactly one trust alert, on the 1 -> 0 flip")
    assert ok
    shutil.rmtree(run)
