"""eval/policy_update.py: Her et al.'s policy enforcement benchmark for Falco and PROVBIND (no VM needed)."""
import json

from eval import policy_update as pu


def test_node_window_takes_the_longest_container():
    s = {"cold_start_s": {"c1": 3.2, "c2": 4.1}, "held": {"held": 40, "released": 40, "lost": 0}}
    assert pu.node_window(s) == {"seconds": 4.1, "containers": 2, "held": 40, "released": 40, "lost": 0}
    assert pu.node_window({})["seconds"] is None


def test_rows_report_and_her_et_al(tmp_path, capsys):
    rows = tmp_path / "policy.jsonl"
    summary = tmp_path / "node-summary.json"
    summary.write_text(json.dumps({"cold_start_s": {"c": 5.0}, "held": {"held": 12, "released": 12, "lost": 0}}))
    for k, secs in ((1, "17.2"), (2, "18.4"), (3, "timeout")):
        assert pu.main(["falco-row", "--rep", str(k), "--seconds", secs, "--out", str(rows)]) == 0
    for k in (1, 2):
        assert pu.main(["provbind-row", "--rep", str(k), "--summary", str(summary), "--ready-s", "9.5",
                        "--out", str(rows)]) == 0
    assert pu.main(["report", "--rows", str(rows), "--out", str(tmp_path)]) == 0
    doc = json.loads((tmp_path / "POLICY-UPDATE.json").read_text())
    assert doc["falco"]["median"] == 17.8 and doc["falco"]["n"] == 2 and doc["falco"]["timeouts"] == 1
    assert doc["provbind"]["median"] == 5.0 and doc["provbind"]["ready_s"]["median"] == 9.5
    assert doc["provbind"]["lost"] == 0 and doc["her_et_al"]["Falco"] == 18.15
    md = (tmp_path / "POLICY-UPDATE.md").read_text()
    assert "| Falco (rule added, Falco restarted) | 17.80 s" in md and "18.15 s" in md and "timed out" in md
    assert "Time for a new policy to act" in capsys.readouterr().out


def test_missing_summary_gives_an_empty_provbind_row(tmp_path):
    rows = tmp_path / "policy.jsonl"
    assert pu.main(["provbind-row", "--rep", "1", "--summary", str(tmp_path / "nope.json"), "--out", str(rows)]) == 0
    doc = pu.build(pu.load(rows))
    assert doc["provbind"]["n"] == 0 and doc["provbind"]["no_window"] == 1
    assert "no cold-start window" in pu.render(doc)


def test_report_without_rows_fails(tmp_path, capsys):
    (tmp_path / "empty.jsonl").write_text("")
    assert pu.main(["report", "--rows", str(tmp_path / "empty.jsonl"), "--out", str(tmp_path)]) == 1
