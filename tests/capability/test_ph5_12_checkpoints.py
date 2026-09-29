"""PH5-12 (R4, P1): rewriting the chain from storage (M6). Test Plan §3.8.

Rewrite record k and recompute every later hash. Pass: the plain chain still verifies (the
weakness), and the same log with signed checkpoints fails.

Real cosign signatures (`cosign sign-blob`, offline) with a throwaway log key made for the test in
its temp folder, with an empty password; nothing leaves the machine. Needs cosign; without it the
result is blocked.
"""
import json
import shutil
import subprocess

from alerts import verify_log
from alerts.log import ZERO, Checkpointer, ViolationLog, chain_hash, read_checkpoints

K = 3
N = 6
EVERY = 2


def alert(i):
    return {"detection_id": f"det-{i:04d}", "class": "D_write", "subclass": "declared_file", "score": 72, "bucket": "high"}


def test_ph5_12_signed_checkpoints_catch_a_recomputed_rewrite(tmp_path, record_result, monkeypatch):
    if shutil.which("cosign") is None:
        record_result("PH5-12", "blocked", notes="cosign is not installed: the checkpoints are cosign signatures")
        return
    keys = tmp_path / "keys"
    keys.mkdir()
    monkeypatch.setenv("COSIGN_PASSWORD", "")
    made = subprocess.run(["cosign", "generate-key-pair", "--output-key-prefix", "log"], cwd=keys,
                          capture_output=True, text=True, timeout=60)
    assert made.returncode == 0, made.stderr[-300:]
    run = tmp_path / "run"
    log = ViolationLog(run, Checkpointer(str(keys / "log.key"), EVERY))
    for i in range(1, N + 1):
        log.append(alert(i))
    signed = [c["k"] for c in read_checkpoints(run / "log" / "checkpoints.jsonl")]
    pub = str(keys / "log.pub")
    before = verify_log.verify(run, pub=pub, every=EVERY)

    path = run / "log" / "violations.jsonl"
    entries = [json.loads(line) for line in path.read_text().splitlines()]
    entries[K - 1]["record"]["score"] = 5                           # hide an alert: High -> Low
    prev = entries[K - 2]["hash"] if K > 1 else ZERO
    for e in entries[K - 1:]:
        e["prev"], e["hash"] = prev, chain_hash(prev, e["record"])
        prev = e["hash"]
    path.write_text("".join(json.dumps(e) + "\n" for e in entries))

    plain = verify_log.verify(run)
    checked = verify_log.verify(run, pub=pub, every=EVERY)
    ok = before.ok and plain.ok and not checked.ok and checked.first_bad == K
    record_result("PH5-12", "pass" if ok else "fail",
                  metrics={"records": N, "checkpoints": signed, "rewritten": K, "plain_chain_ok": plain.ok,
                           "checkpointed_ok": checked.ok, "first_bad": checked.first_bad},
                  notes=f"{N} records, signed every {EVERY} (checkpoints at {signed}) with a throwaway log key; record "
                        f"{K} rewritten and every later hash recomputed: the plain chain {'verifies' if plain.ok else 'fails'} "
                        f"(the weakness, M6); with the signed checkpoints: {checked.reason}")
    assert ok, checked
