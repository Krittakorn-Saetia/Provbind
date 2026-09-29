"""PH6-07 (R4, P1): runtime and trust states are independent (Eqs. 95-96). PH6-09 (R4, P1): trust-alert
latency. Test Plan §3.9.

- PH6-07: two images in one run folder. One is conforming at runtime but untrusted (its builder is
  on the denylist); the other is deviating (a High detection alert) but trusted. Pass: one trust
  alert, for the first image, saying "conforming"; none for the second, whose runtime alert stays.
- PH6-09: `python -m alerts.trust` runs as it does in the demo (ΔR = 300 s, --poll 2); the key is
  then marked revoked. Pass: the trust alert is written within ΔR plus processing time. The
  alert's own `latency_s` (from the input file's change to the alert) is recorded too.

Both are properties of the trust loop on Role 2's golden envelope; they are recorded anywhere.
"""
import copy
import json
import subprocess
import sys
import time

from alerts.log import ViolationLog
from alerts.trust import cycle, key_id_of, runtime_state, set_key

from tests.alerts.helpers import CID, ROOT, golden, read_jsonl, write_run

KEY = ROOT / "pipeline" / "keys" / "cosign.pub"
DELTA_R = 300
PROCESSING_S = 10


def two_images(tmp_path):
    a = golden()
    b = copy.deepcopy(a)
    b["image"]["digest"] = "sha256:" + "b" * 64
    b["image"]["builder_id"] = "https://github.com/sf9-26/provbind/builders/trusted@v1"
    run = write_run(tmp_path, a)
    (run / "envelopes" / f"{'b' * 64}.json").write_text(json.dumps(b))
    bindings = json.loads((run / "bindings.json").read_text())
    other = "containerd://" + "5e7a" * 16
    bindings[other] = {**bindings[CID], "pod": "other-app-1", "image_digest": b["image"]["digest"]}
    (run / "bindings.json").write_text(json.dumps(bindings))
    return run, a, b


def test_ph6_07_runtime_and_trust_are_independent(tmp_path, record_result):
    run, a, b = two_images(tmp_path)
    ViolationLog(run).append({"detection_id": "det-0001", "time": "2026-09-29T10:05:00.000Z",
                              "image_digest": b["image"]["digest"], "container": "demo/other-app-1/app",
                              "class": "D_write", "subclass": "declared_file", "score": 72, "bucket": "high"})
    (run / "builder_denylist.json").write_text(json.dumps([a["image"]["builder_id"]]))
    got = cycle(run)
    state = {d: json.loads((run / "trust" / f"{d.split(':')[1]}.json").read_text())["trusted"]
             for d in (a["image"]["digest"], b["image"]["digest"])}
    alerts = read_jsonl(run / "alerts.jsonl")
    t = got[0] if got else {}
    ok = (len(got) == 1 and t["image_digest"] == a["image"]["digest"] and t["runtime_state"] == "conforming"
          and state == {a["image"]["digest"]: False, b["image"]["digest"]: True}
          and runtime_state(run, b["image"]["digest"]) == "deviating"
          and [x["class"] for x in alerts] == ["D_write", "trust"])
    record_result("PH6-07", "pass" if ok else "fail", metrics={"trusted": state, "trust_alerts": len(got),
                                                                "runtime_of_untrusted": t.get("runtime_state")},
                  notes="conforming but untrusted (builder denied): one trust alert, runtime_state "
                        f"{t.get('runtime_state')}; deviating but trusted (a High D_write): trusted "
                        f"{state[b['image']['digest']]}, no trust alert, its runtime alert kept")
    assert ok


def test_ph6_09_trust_alert_latency(tmp_path, record_result):
    env = golden()
    run = write_run(tmp_path, env)
    hex_ = env["image"]["digest"].split(":")[1]
    (run / "contexts").mkdir()
    (run / "contexts" / f"{hex_}.json").write_text(json.dumps(
        {"digest": env["image"]["digest"], "t0": "2026-09-29T09:00:00Z", "key": {"key_id": key_id_of(KEY)}}))
    loop = subprocess.Popen([sys.executable, "-m", "alerts.trust", "--run", str(run), "--interval", str(DELTA_R),
                             "--poll", "2"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 30
        while not (run / "trust" / f"{hex_}.json").exists() and time.time() < deadline:
            time.sleep(0.1)                                              # the first cycle has run
        changed = time.time()
        set_key(run, str(KEY), "revoked", None)
        alert = None
        while time.time() < changed + DELTA_R + PROCESSING_S:
            lines = read_jsonl(run / "alerts.jsonl") if (run / "alerts.jsonl").exists() else []
            alert = next((x for x in lines if x.get("class") == "trust"), None)
            if alert:
                break
            time.sleep(0.1)
        seen = round(time.time() - changed, 3)
    finally:
        loop.terminate()
        loop.wait(timeout=10)
    ok = alert is not None and seen <= DELTA_R + PROCESSING_S
    record_result("PH6-09", "pass" if ok else "fail",
                  metrics={"observed_s": seen if alert else None, "latency_s": (alert or {}).get("latency_s"),
                           "delta_r_s": DELTA_R, "poll_s": 2},
                  notes=(f"key marked revoked; the trust alert appeared after {seen} s (its latency_s "
                         f"{alert.get('latency_s')}), within ΔR = {DELTA_R} s: the loop also re-evaluates within "
                         f"--poll 2 s of an input change" if alert else
                         f"no trust alert within ΔR + {PROCESSING_S} s"))
    assert ok
