"""alerts/run.py: detections -> alerts on Role 2's golden envelope, with Role 3-shaped detections."""
import json

import pytest

from alerts import verify_log
from alerts.attribute import Attributor
from alerts.run import AlertEngine, main

from .helpers import CID, attack_and_benign, detection, golden, read_jsonl, write_detections, write_run


def engine(run):
    return AlertEngine(run, attributor=Attributor(use_neo4j=False))


def run_once(run):
    e = engine(run)
    e.run_loop(once=True)
    return read_jsonl(run / "alerts.jsonl") if (run / "alerts.jsonl").exists() else []


@pytest.fixture
def env():
    return golden()


@pytest.fixture
def run(tmp_path, env):
    r = write_run(tmp_path, env)
    write_detections(r, attack_and_benign(env))
    return r


def by_det(alerts):
    return {a["detection_id"]: a for a in alerts}


def test_the_demo_scores_and_chains(run):
    a = by_det(run_once(run))
    assert [(a[d]["score"], a[d]["bucket"]) for d in ("det-0001", "det-0002", "det-0003", "det-0004")] == \
        [(34, "low"), (34, "low"), (90, "critical"), (72, "high")]
    assert a["det-0003"]["chain_id"] == a["det-0004"]["chain_id"]           # attack-1: one chain (PH5-13)
    assert a["det-0001"]["chain_id"] == a["det-0002"]["chain_id"] != a["det-0003"]["chain_id"]


def test_attribution_is_for_the_file_the_clause_names(run, env):
    a = by_det(run_once(run))
    layer0 = env["layers"][0]["digest"]
    assert a["det-0004"]["attribution"]["layer"] == layer0                   # /etc/passwd, not the writer /tmp/.x9
    assert a["det-0003"]["attribution"] == {"layer": None, "package": None, "depth": None,     # PH5-08
                                            "process_chain": ["/usr/local/bin/python3.11", "/tmp/.x9"]}
    ls = a["det-0002"]["attribution"]
    assert (ls["layer"], ls["package"], ls["depth"]) == (layer0, env["files"]["/usr/bin/ls"]["package"], 1)


def test_the_signing_identity_comes_from_the_envelope(run, env):
    for alert in run_once(run):
        assert alert["signing_identity"] == {k: env["image"][k] for k in ("builder_id", "source_commit", "rekor_log_index")}


def test_without_an_envelope_nothing_is_invented(tmp_path, env):
    r = write_run(tmp_path, env)
    (r / "envelopes" / f"{env['image']['digest'].split(':')[1]}.json").unlink()
    write_detections(r, attack_and_benign(env)[2:3])
    (a,) = run_once(r)
    assert a["signing_identity"] == {"builder_id": None, "source_commit": None, "rekor_log_index": None}
    assert a["attribution"]["layer"] is None


def test_every_section_4_5_field_is_present(run):
    keys = {"alert_id", "detection_id", "time", "image_digest", "container", "class", "subclass", "violated_clause",
            "origin", "score", "bucket", "attribution", "signing_identity", "chain_id", "log_k"}
    alerts = run_once(run)
    assert all(keys <= set(a) for a in alerts)
    assert alerts[2]["container"] == "demo/demo-app-7d9f/app"
    assert alerts[2]["violated_clause"] == "file_set: /tmp/.x9: path is in no layer of the attested image"


def test_a_second_run_alerts_nothing_twice(run):
    first = run_once(run)
    second = run_once(run)
    assert len(first) == len(second) == 4
    assert verify_log.verify(run).ok


def test_a_restart_keeps_the_chain(run, env):
    run_once(run)
    write_detections(run, [detection(env, 5, "D_write", "declared_file", "/usr/bin/ls", exe="/tmp/.x9",
                                     time="2026-09-29T10:05:10.000Z")])
    a = by_det(run_once(run))
    assert a["det-0005"]["chain_id"] == a["det-0003"]["chain_id"]


def test_a_half_written_line_waits_for_its_newline(tmp_path, env):
    r = write_run(tmp_path, env)
    line = json.dumps(attack_and_benign(env)[2])
    (r / "detections.jsonl").write_text(line[:40], encoding="utf-8")
    assert run_once(r) == []
    (r / "detections.jsonl").write_text(line + "\n", encoding="utf-8")
    assert [a["detection_id"] for a in run_once(r)] == ["det-0003"]


def test_siblings_of_the_app_do_not_join_an_attack_chain(tmp_path, env):
    r = write_run(tmp_path, env)
    x9 = attack_and_benign(env)[2]                               # pid 4471, ppid 4402 (python)
    other = detection(env, 7, "D_exec", "outside_closure", "/usr/bin/ls", pid=5000, ppid=4402,
                      time="2026-09-29T10:05:10.000Z", kind="closure", detail="not reachable")
    write_detections(r, [x9, other])
    a = by_det(run_once(r))
    assert a["det-0003"]["chain_id"] != a["det-0007"]["chain_id"]


def test_chains_stay_within_a_container_and_a_60_s_window(tmp_path, env):
    r = write_run(tmp_path, env)
    x9 = attack_and_benign(env)[2]
    elsewhere = detection(env, 8, "D_write", "declared_file", "/etc/passwd", exe="/tmp/.x9", cid="containerd://" + "9" * 64,
                          time="2026-09-29T10:05:01.000Z")
    late = detection(env, 9, "D_write", "declared_file", "/etc/passwd", exe="/tmp/.x9", time="2026-09-29T10:06:30.000Z")
    write_detections(r, [x9, elsewhere, late])
    a = by_det(run_once(r))
    assert len({a["det-0003"]["chain_id"], a["det-0008"]["chain_id"], a["det-0009"]["chain_id"]}) == 3


def test_the_pods_privilege_changes_the_score(tmp_path, env):
    r = write_run(tmp_path, env, binding={"privileged": True})
    write_detections(r, attack_and_benign(env)[3:4])
    (a,) = run_once(r)
    assert a["score"] == 82 and a["score_parts"]["kappa"] == 1.0            # 0.32 + 0.2 + 0.4 * 0.75


def test_the_cli(run, capsys):
    assert main(["--run", str(run), "--once"]) == 0
    assert json.loads(capsys.readouterr().out) == {"alerts_written": 4, "detections_seen": 4}
    assert main(["--run", str(run), "--once"]) == 0
    assert json.loads(capsys.readouterr().out)["alerts_written"] == 0


def test_the_binding_is_found_by_container_id(run):
    assert json.loads((run / "bindings.json").read_text())[CID]["run_as_root"] is True
