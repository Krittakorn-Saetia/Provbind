"""alerts/log.py and alerts/verify_log.py: the §4.6 hash chain (PH5-10, PH5-11, E2E-12) and its signed
checkpoints (PH5-12; a keyed hash stands in for cosign here, the real signature is in the PH5-12 test)."""
import hashlib
import json
import re
import threading

import pytest

from alerts import verify_log
from alerts.log import ZERO, Checkpointer, ViolationLog, chain_hash, read_checkpoints

from .helpers import read_jsonl


def alert(i):
    return {"detection_id": f"det-{i:04d}", "class": "D_exec", "subclass": "undeclared", "score": 90, "bucket": "critical"}


@pytest.fixture
def run(tmp_path):
    log = ViolationLog(tmp_path)
    for i in range(1, 101):
        log.append(alert(i))
    return tmp_path


def lines(run):
    return (run / "log" / "violations.jsonl").read_text(encoding="utf-8").splitlines()


def write(run, ls):
    (run / "log" / "violations.jsonl").write_text("\n".join(ls) + "\n", encoding="utf-8")


def test_100_records_append_and_verify(run):
    result = verify_log.verify(run)
    assert (result.ok, result.first_bad, result.records) == (True, None, 100)
    entries = [json.loads(ln) for ln in lines(run)]
    assert [e["k"] for e in entries] == list(range(1, 101)) and entries[0]["prev"] == ZERO
    assert entries[0]["hash"] == chain_hash(ZERO, entries[0]["record"])


def test_the_logged_record_is_the_alert(run):
    alerts = read_jsonl(run / "alerts.jsonl")
    assert [e["record"] for e in map(json.loads, lines(run))] == alerts
    assert [a["alert_id"] for a in alerts][:2] == ["alr-0001", "alr-0002"] and alerts[4]["log_k"] == 5


@pytest.mark.parametrize("k", [1, 37, 100])
def test_one_changed_character_is_reported_at_its_record(run, k):
    ls = lines(run)
    ls[k - 1] = ls[k - 1].replace('"score": 90', '"score": 91', 1)
    write(run, ls)
    result = verify_log.verify(run)
    assert (result.ok, result.first_bad) == (False, k)


def test_role_1s_tamper_edit_is_caught(run):
    """testbed/scenarios/tamper.sh flips the first lowercase letter of the middle line: the "k" key."""
    ls = lines(run)
    target = len(ls) // 2
    i = re.search(r"[a-z]", ls[target]).start()
    ls[target] = ls[target][:i] + ("b" if ls[target][i] != "b" else "c") + ls[target][i + 1:]
    write(run, ls)
    result = verify_log.verify(run)
    assert (result.ok, result.first_bad) == (False, target + 1)


def test_an_edit_that_breaks_the_json_is_reported_not_raised(run):
    ls = lines(run)
    ls[9] = ls[9].replace('"k": 10', '"k" 10', 1)
    write(run, ls)
    assert verify_log.verify(run).first_bad == 10


def test_a_deleted_record_is_reported(run):
    ls = lines(run)
    del ls[50]
    write(run, ls)
    assert verify_log.verify(run).first_bad == 51


def test_no_log_is_not_a_pass(tmp_path):
    result = verify_log.verify(tmp_path)
    assert result.ok is False and result.first_bad is None


def test_the_cli(run, capsys):
    assert verify_log.main(["--run", str(run)]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    ls = lines(run)
    ls[3] = ls[3].replace("critical", "cr1tical", 1)
    write(run, ls)
    assert verify_log.main(["--run", str(run)]) == 1
    assert json.loads(capsys.readouterr().out)["first_bad"] == 4
    assert verify_log.main([str(run)]) == 1                               # the old positional form
    assert verify_log.main(["--run", str(run / "missing")]) == 2


def test_role_1s_e2e_12_interface(run):
    """tests/capability/test_e2e_trust_tamper.py: bool(result) and not result.ok on a tampered log."""
    ls = lines(run)
    ls[5] = ls[5].replace("undeclared", "undeclarex", 1)
    write(run, ls)
    result = verify_log.verify(run)
    assert bool(result) and not result.ok and result.first_bad == 6


def test_two_writers_never_break_the_chain_or_reuse_an_id(tmp_path):
    def writer(n):
        log = ViolationLog(tmp_path)
        for i in range(50):
            log.append({"detection_id": f"{n}-{i}", "class": "x"})
    threads = [threading.Thread(target=writer, args=(n,)) for n in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert verify_log.verify(tmp_path).ok
    ids = [a["alert_id"] for a in read_jsonl(tmp_path / "alerts.jsonl")]
    assert len(ids) == 100 == len(set(ids))


def test_detection_ids_are_read_back(run):
    assert ViolationLog(run).detection_ids() == {f"det-{i:04d}" for i in range(1, 101)}


# --- signed checkpoints (PH5-12) ------------------------------------------------------------------------

class FakeSigner:
    """sign(key, message) and verify(pub, message, bundle), with key == pub: cosign's interface."""

    def __init__(self, fail=False):
        self.fail = fail

    def sign(self, key, message):
        if self.fail:
            raise RuntimeError("cosign: wrong password")
        return {"mac": hashlib.sha256(key.encode() + message).hexdigest()}

    def verify(self, pub, message, bundle):
        return bundle.get("mac") == hashlib.sha256(pub.encode() + message).hexdigest()


def signed_run(tmp_path, n=5, every=2, signer=None):
    log = ViolationLog(tmp_path, Checkpointer("log-key", every, signer or FakeSigner()))
    for i in range(1, n + 1):
        log.append(alert(i))
    return tmp_path, log


def check(run, every=2):
    return verify_log.verify(run, pub="log-key", every=every, verifier=FakeSigner())


def rewrite(run, k, **change):
    """Change record k and recompute every later hash: what someone who can write the file can do."""
    entries = [json.loads(line) for line in lines(run)]
    entries[k - 1]["record"].update(change)
    prev = entries[k - 2]["hash"] if k > 1 else ZERO
    for e in entries[k - 1:]:
        e["prev"], e["hash"] = prev, chain_hash(prev, e["record"])
        prev = e["hash"]
    write(run, [json.dumps(e) for e in entries])


def test_every_nth_record_is_signed(tmp_path):
    run, _ = signed_run(tmp_path)
    assert [c["k"] for c in read_checkpoints(run / "log" / "checkpoints.jsonl")] == [2, 4]
    r = check(run)
    assert r.ok and r.checkpoints == 2 and "records 5-5 are not signed yet" in r.reason


def test_a_recomputed_rewrite_passes_the_plain_chain_but_not_the_checkpoints(tmp_path):     # M6
    run, _ = signed_run(tmp_path)
    rewrite(run, 3, score=10)
    assert verify_log.verify(run).ok                                       # the weakness
    r = check(run)
    assert not r.ok and r.first_bad == 3 and "from 3 to 4 was rewritten" in r.reason


def test_deleting_the_checkpoints_does_not_help(tmp_path):
    run, _ = signed_run(tmp_path)
    (run / "log" / "checkpoints.jsonl").unlink()
    r = check(run)
    assert not r.ok and r.first_bad == 1 and "no signed checkpoint for record 2" in r.reason


def test_a_forged_checkpoint_fails(tmp_path):
    run, _ = signed_run(tmp_path)
    rewrite(run, 3, score=10)
    cps = read_checkpoints(run / "log" / "checkpoints.jsonl")
    cps[1]["hash"] = json.loads(lines(run)[3])["hash"]                     # without the key: no valid signature
    (run / "log" / "checkpoints.jsonl").write_text("".join(json.dumps(c) + "\n" for c in cps))
    r = check(run)
    assert not r.ok and "no valid signature" in r.reason


def test_removing_signed_records_fails(tmp_path):
    run, _ = signed_run(tmp_path)
    write(run, lines(run)[:3])
    r = check(run)
    assert not r.ok and "records were removed" in r.reason


def test_a_failed_signature_never_loses_an_alert(tmp_path):
    run, _ = signed_run(tmp_path, n=4, signer=FakeSigner(fail=True))
    assert len(read_jsonl(run / "alerts.jsonl")) == 4 and verify_log.verify(run).ok
    assert not (run / "log" / "checkpoints.jsonl").exists()


def test_checkpoint_now_signs_the_head_once(tmp_path):
    run, log = signed_run(tmp_path, n=5)
    assert log.checkpoint()["k"] == 5
    assert log.checkpoint()["k"] == 5
    assert [c["k"] for c in read_checkpoints(run / "log" / "checkpoints.jsonl")] == [2, 4, 5]
    assert check(run).reason.endswith("3 signed checkpoint(s) verify")


def test_without_a_log_key_nothing_is_signed(tmp_path, monkeypatch):
    monkeypatch.delenv("PROVBIND_LOG_KEY", raising=False)
    log = ViolationLog(tmp_path)
    log.append(alert(1))
    assert log.checkpointer is None and not (tmp_path / "log" / "checkpoints.jsonl").exists()
