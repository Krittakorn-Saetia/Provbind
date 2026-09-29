"""alerts/log.py and alerts/verify_log.py: the §4.6 hash chain (PH5-10, PH5-11, E2E-12)."""
import json
import re
import threading

import pytest

from alerts import verify_log
from alerts.log import ZERO, ViolationLog, chain_hash

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
