"""node/mlb.py: ML-B's gate, windows, features Ψ_I, model, g_I, θ_A and D_beh (Algorithm 2)."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from node.mlb import (FEATURES, NS, Behaviour, Model, ModelCache, evaluate, model_path, read_windows, split,
                      train, write_model, write_windows)
from node.normalize import Event, format_time, parse_time
from node.scenarios import replay
from node.store import Binding, Envelope, Store
from node.synth import DEMO_CID, DIGEST, benign_session, demo_bindings, demo_envelope, library
from node.verify import SUPPRESSED

ROOT = Path(__file__).resolve().parents[2]
T0 = parse_time("2026-09-28T10:00:00Z")
PY = "/usr/local/bin/python3.11"


@pytest.fixture(scope="module")
def env():
    return Envelope.prepare(demo_envelope())


@pytest.fixture(scope="module")
def b():
    return Binding.parse(DEMO_CID, demo_bindings()[DEMO_CID])


def ev(sec, kind="write", pid=4402, ppid=4100, exe=PY, **kw):
    t = T0 + int(round(sec * NS))
    return Event(time=format_time(t), t=t, kind=kind, container_id=DEMO_CID, namespace="demo", pod="demo-app-7d9f",
                 container="app", pid=pid, ppid=ppid, exe=exe, parent_exe=None, **kw)


def feed(stage, env, b, events, det=None):
    out = []
    for e in events:
        out += stage.observe(e, det, env, b)
    return out


def needs_sklearn():
    """Training needs numpy and scikit-learn (requirements.txt); skip cleanly without them, as
    Role 2's ML tests do. Everything else here runs with requirements-role2.txt alone."""
    pytest.importorskip("numpy")
    pytest.importorskip("sklearn")


@pytest.fixture(scope="module")
def d2():
    """Synthetic D2: four hours of benign windows, split, and an hour held out, an hour later."""
    needs_sklearn()
    lib = library()

    def windows(lines):
        out = []
        replay(lines, Store.static([lib.envelope], lib.bindings), behaviour=Behaviour(on_window=out.append),
               keep=lambda e: False)
        return out
    train_w, validation_w = split(windows(benign_session(4 * 3600, seed=0)))
    heldout = windows(benign_session(3600, seed=100, start="2026-09-28T16:00:00Z"))
    return train_w, validation_w, heldout


@pytest.fixture(scope="module")
def model(d2):
    needs_sklearn()
    return Model(train(d2[0], d2[1], DIGEST))


# windows ------------------------------------------------------------------------------------------

def test_time_windows_are_30_seconds_and_the_open_one_is_dropped_at_the_end(env, b):
    windows = []
    stage = Behaviour(on_window=windows.append)
    feed(stage, env, b, [ev(s, path="/tmp/cache.json") for s in range(70)])
    stage.close(T0 + 70 * NS)
    assert [(w["start"], w["end"], w["events"], w["closed_by"]) for w in windows] == [
        (format_time(T0), format_time(T0 + 30 * NS), 30, "time"),
        (format_time(T0 + 30 * NS), format_time(T0 + 60 * NS), 30, "time")]
    assert windows[0]["features"]["write"] == 30 and windows[0]["features"]["write_per_s"] == 1.0
    assert stage.stats["dropped_at_end"] == 1


def test_a_quiet_process_window_is_closed_by_the_clock(env, b):
    windows = []
    stage = Behaviour(on_window=windows.append)
    feed(stage, env, b, [ev(0, path="/tmp/a"), ev(12, path="/tmp/a")])
    feed(stage, env, b, [ev(45, pid=5000, path="/tmp/b")])            # another process moves the clock
    assert [w["pid"] for w in windows] == [4402] and windows[0]["events"] == 2


def test_count_windows_close_at_200_events_with_rates_over_their_span(env, b):
    windows = []
    stage = Behaviour(on_window=windows.append)
    feed(stage, env, b, [ev(0, kind="exec")])                         # first seen at 0
    feed(stage, env, b, [ev(20 + i * 0.02, path=f"/tmp/.cache/f{i}") for i in range(250)])
    w = windows[0]
    assert (w["events"], w["closed_by"], w["features"]["new_files"], w["features"]["dirs_written"]) == \
           (200, "count", 200, 1)
    assert w["features"]["write_per_s"] == pytest.approx(200 / 3.98, rel=1e-3)


def test_windows_of_young_processes_are_dropped(env, b):
    windows = []
    stage = Behaviour(on_window=windows.append)
    feed(stage, env, b, [ev(i * 0.01, path=f"/tmp/f{i}") for i in range(200)])
    assert windows == [] and stage.stats["young"] == 1


def test_the_gate_keeps_every_contradiction_out(env, b):
    entered, windows = [], []
    stage = Behaviour(on_window=windows.append, entered=entered)
    feed(stage, env, b, [ev(0, path="/tmp/a")])
    bad = [ev(1, path="/etc/passwd"), ev(2, kind="exec", pid=4471, ppid=4402, exe="/tmp/.x9")]
    feed(stage, env, b, bad, det={"class": "D_write"})
    feed(stage, env, b, [ev(3, kind="load", path="/usr/lib/x86_64-linux-gnu/libnss_dns.so.2")], det=SUPPRESSED)
    feed(stage, env, b, [ev(40, path="/tmp/b")])
    assert [e.path for e in entered] == ["/tmp/a", "/tmp/b"] and stage.stats["gated"] == 3
    assert windows[0]["events"] == 1


def test_an_exec_counts_in_its_parents_window(env, b):
    windows = []
    stage = Behaviour(on_window=windows.append)
    feed(stage, env, b, [ev(0, path="/tmp/a")])
    feed(stage, env, b, [ev(5, kind="exec", pid=5001, ppid=4402, exe="/usr/bin/ls"),
                         ev(6, kind="exec", pid=5002, ppid=4402, exe="/usr/bin/ls"),
                         ev(7, kind="exec", pid=5003, ppid=4402, exe="/usr/bin/cat"),
                         ev(8, kind="exec", pid=5004, ppid=9999, exe="/usr/bin/cat")])     # parent unseen
    stage.tick(T0 + 31 * NS)
    f = windows[0]["features"]
    assert (windows[0]["pid"], f["exec"], f["distinct_exes"]) == (4402, 3, 2)


def test_capability_and_connection_features(env, b):
    windows = []
    stage = Behaviour(on_window=windows.append)
    feed(stage, env, b, [ev(0, kind="cap", cap="CAP_CHOWN", granted=True), ev(1, kind="cap", cap="CAP_KILL", granted=False),
                         ev(2, kind="cap", cap="CAP_KILL", granted=None),
                         ev(3, kind="connect", daddr="10.96.0.10", dport=53), ev(4, kind="connect", daddr="10.96.0.10", dport=5432),
                         ev(5, kind="connect", daddr="10.96.0.11", dport=53)])
    stage.tick(T0 + 31 * NS)
    f = windows[0]["features"]
    assert (f["cap"], f["connect"], f["distinct_daddrs"], f["distinct_dports"]) == (2, 3, 2, 2)


def test_declared_files_are_writes_but_not_new_files(env, b):
    windows = []
    stage = Behaviour(on_window=windows.append)
    feed(stage, env, b, [ev(0, path="/app/data/seed.json"), ev(1, path="/tmp/new"), ev(2, path="/tmp/new")])
    stage.tick(T0 + 31 * NS)
    f = windows[0]["features"]
    assert (f["write"], f["new_files"], f["dirs_written"]) == (3, 1, 2)


def test_exit_and_a_new_exec_drop_the_open_window(env, b):
    windows = []
    stage = Behaviour(on_window=windows.append)
    feed(stage, env, b, [ev(0, path="/tmp/a"), ev(15, path="/tmp/a"), ev(20, kind="exit")])
    feed(stage, env, b, [ev(21, pid=4500, path="/tmp/a"), ev(22, kind="exec", pid=4500)])
    stage.close(T0 + 100 * NS)
    assert windows == [] and stage.stats["dropped_at_exit"] == 1 and stage.stats["dropped_at_exec"] == 1


def test_features_are_the_documented_twenty():
    assert len(FEATURES) == 20 and FEATURES[:10] == ("exec", "write", "load", "cap", "connect", "new_files",
                                                     "dirs_written", "distinct_exes", "distinct_daddrs",
                                                     "distinct_dports")
    assert all(f"{k}_per_s" in FEATURES for k in FEATURES[:10])


def test_the_same_events_give_the_same_windows(env, b):
    events = [ev(s * 0.7, path=f"/tmp/f{s % 7}") for s in range(400)]
    runs = []
    for _ in range(2):
        out = []
        stage = Behaviour(on_window=out.append)
        feed(stage, env, b, events)
        stage.close(T0 + 400 * NS)
        runs.append(out)
    assert runs[0] == runs[1] and len(runs[0]) > 5


# model -------------------------------------------------------------------------------------------

def test_split_is_chronological():
    ws = [{"start": format_time(T0 + i * NS), "features": {}} for i in (5, 1, 3, 2, 4, 0, 9, 8, 7, 6)]
    train_w, validation_w = split(ws)
    assert len(train_w) == 7 and max(w["start"] for w in train_w) < min(w["start"] for w in validation_w)


def test_training_sets_theta_at_the_99th_percentile_with_enough_windows(d2, model):
    train_w, validation_w, _ = d2
    assert len(validation_w) >= 100 and model.doc["percentile"] == 99 and model.doc["percentile_note"] == ""
    assert model.theta == pytest.approx(sorted(model.validation)[int(0.99 * (len(model.validation) - 1))], rel=0.05)
    assert model.doc["windows"] == {"train": len(train_w), "validation": len(validation_w)}
    assert model.doc["params"]["n_estimators"] == 100 and model.doc["params"]["max_samples"] == 256


def test_training_with_few_validation_windows_uses_the_95th_and_says_so(d2):
    doc = train(d2[0], d2[1][:60], DIGEST)
    assert doc["percentile"] == 95 and "95th" in doc["percentile_note"]


def test_training_needs_windows(d2):
    with pytest.raises(ValueError):
        train(d2[0][:1], d2[1], DIGEST)
    with pytest.raises(ValueError):
        train(d2[0], [], DIGEST)


def test_heldout_benign_false_positive_rate(d2, model):
    result = evaluate(model, d2[2])
    assert result["windows"] >= 80 and result["fpr"] <= 0.01


def attack_windows():
    lib = library()
    out = []
    replay(lib.lines, Store.static([lib.envelope], lib.bindings), behaviour=Behaviour(on_window=out.append))
    return out


def test_attack_2_burst_saturates_the_forest_and_the_guard_catches_it(model):
    """The finding behind the range guard: 200 writes to new files score like the most extreme
    benign window (15 writes), because the burst follows the same path through every tree."""
    burst = next(w for w in attack_windows() if w["closed_by"] == "count")
    v = model.decide(burst["features"])
    assert burst["features"]["write"] == 200 and not v["forest"] and v["anomaly"] <= model.theta
    assert v["guard"] and v["anomalous"]
    assert {f for f, _, _ in v["beyond"]} >= {"write", "new_files", "write_per_s"}


def test_guard_off_is_the_forest_alone(d2):
    m = Model(train(d2[0], d2[1], DIGEST, guard=None))
    burst = next(w for w in attack_windows() if w["closed_by"] == "count")
    assert m.doc["guard"] is None and m.beyond(burst["features"]) == [] and not m.decide(burst["features"])["anomalous"]


def test_guard_maximum_covers_training_and_validation(d2, model):
    everything = d2[0] + d2[1]
    assert model.guard_factor == 2.0
    assert model.guard_max["write"] == max(w["features"]["write"] for w in everything)
    assert model.guard_max["exec"] == 0.0                     # the app never starts a child here


def test_evaluate_reports_the_forest_alone_and_with_the_guard(d2, model):
    r = evaluate(model, d2[2])
    assert r["false_positives"] >= r["forest_false_positives"] and r["guard_false_positives"] == 0


def test_normaliser_is_the_validation_percentile_rank(model):
    lo, hi = model.validation[0], model.validation[-1]
    assert model.normalise(lo - 1) == 0.0 and model.normalise(hi) == 1.0
    assert 0 < model.normalise(model.theta) < 1


def test_unusual_names_the_features_furthest_above_training(model):
    feats = {f: 0.0 for f in FEATURES}
    feats.update(write=200, write_per_s=50.0, new_files=200)
    names = [f for f, _, _ in model.unusual(feats)]
    assert set(names) <= {"write", "write_per_s", "new_files", "new_files_per_s"} and len(names) == 3


@pytest.mark.parametrize("change", [lambda d: d.update(schema="x"), lambda d: d["forest"]["features"].reverse(),
                                    lambda d: d.pop("theta_a")])
def test_bad_models_are_refused(d2, change):
    doc = json.loads(json.dumps(train(d2[0], d2[1], DIGEST)))
    change(doc)
    with pytest.raises((ValueError, KeyError)):
        Model(doc)


def test_model_is_stored_beside_the_envelope_and_reloaded(tmp_path, d2):
    cache = ModelCache(tmp_path)
    assert cache(DIGEST) is None and cache(None) is None
    doc = train(d2[0], d2[1], DIGEST)
    path = write_model(tmp_path, doc)
    assert path == tmp_path / "envelopes" / f"{DIGEST[7:]}.mlb" / "model.json" == model_path(tmp_path, DIGEST)
    first = cache(DIGEST)
    assert first is not None and cache(DIGEST) is first
    doc["theta_a"] = 0.99
    write_model(tmp_path, doc)
    os.utime(path, ns=(1, 1))
    assert cache(DIGEST).theta == 0.99
    path.write_text("{broken")
    assert cache(DIGEST) is None


def test_windows_file_round_trip(tmp_path):
    ws = [{"start": "2026-09-28T10:00:00.000Z", "features": {"write": 1}}]
    write_windows(tmp_path / "w" / "x.jsonl", ws)
    assert read_windows(tmp_path / "w" / "x.jsonl") == ws


# D_beh --------------------------------------------------------------------------------------------

def test_d_beh_is_one_valid_inferred_detection(env, b, model):
    from jsonschema import Draft202012Validator
    schema = json.loads((ROOT / "node" / "detection.schema.json").read_text())
    stage = Behaviour(model_for=lambda d: model)
    feed(stage, env, b, [ev(0, kind="exec")])
    dets = feed(stage, env, b, [ev(20 + i * 0.05, path=f"/tmp/.cache/f{i}") for i in range(200)])
    assert len(dets) == 1
    d = dets[0]
    d["id"] = "det-0001"
    assert not list(Draft202012Validator(schema).iter_errors(d))
    assert (d["class"], d["subclass"], d["origin"], d["pid"], d["exe"]) == ("D_beh", "anomalous_window", "INFERRED",
                                                                            4402, PY)
    assert d["clause"]["kind"] == "behaviour" and "most unusual" in d["clause"]["detail"]
    assert "beyond 2x the benign maximum: write=200" in d["clause"]["detail"]
    assert d["time"] == format_time(T0 + int(round((20 + 199 * 0.05) * NS)))
    assert d["context"]["declared"] is True


def test_windows_without_a_model_are_recorded_not_scored(env, b):
    windows = []
    stage = Behaviour(on_window=windows.append)
    feed(stage, env, b, [ev(0, kind="exec")])
    assert feed(stage, env, b, [ev(20 + i * 0.05, path=f"/tmp/f{i}") for i in range(200)]) == []
    assert len(windows) == 1 and stage.stats["scored"] == 0


# CLIs ---------------------------------------------------------------------------------------------

@pytest.fixture
def run(tmp_path):
    lib = library()
    (tmp_path / "envelopes").mkdir()
    (tmp_path / "envelopes" / f"{DIGEST[7:]}.json").write_text(json.dumps(lib.envelope))
    (tmp_path / "bindings.json").write_text(json.dumps(lib.bindings))
    (tmp_path / "benign.jsonl").write_text("\n".join(benign_session(4 * 3600, seed=0)) + "\n")
    (tmp_path / "heldout.jsonl").write_text("\n".join(benign_session(3600, seed=100, start="2026-09-28T16:00:00Z")) + "\n")
    (tmp_path / "attack.jsonl").write_text("\n".join(lib.lines) + "\n")
    return tmp_path


def cli(*args):
    proc = subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_d2_and_model_from_the_command_line(run):
    needs_sklearn()
    data = run / "mlb" / DIGEST[7:]
    cli("-m", "node.mlb", "windows", "--run", str(run), "--replay", str(run / "benign.jsonl"), "--out", str(run / "w.jsonl"))
    split_out = json.loads(cli("-m", "node.mlb", "split", "--windows", str(run / "w.jsonl"), "--out-dir", str(data)))
    cli("-m", "node.mlb", "windows", "--run", str(run), "--replay", str(run / "heldout.jsonl"),
        "--out", str(data / "heldout.jsonl"), "--digest", DIGEST)
    trained = json.loads(cli("-m", "node.mlb", "train", "--data", str(data), "--run", str(run)))
    assert trained["digest"] == DIGEST and trained["percentile"] == 99 and trained["guard"] == 2.0
    assert trained["windows"] == {"train": split_out["train"], "validation": split_out["validation"]}
    assert Path(trained["model"]) == model_path(run, DIGEST)
    held = json.loads(cli("-m", "node.mlb", "evaluate", "--data", str(data), "--run", str(run)))
    assert held["fpr"] <= 0.01
    out = json.loads(cli("-m", "node.run", "--run", str(run), "--replay", str(run / "attack.jsonl"), "--mlb",
                         "--no-events", "--windows-out", str(run / "live-windows.jsonl")))
    dets = [json.loads(line) for line in (run / "detections.jsonl").read_text().splitlines()]
    assert any(d["class"] == "D_beh" for d in dets) and out["mlb"]["anomalous"] >= 1
    assert len(read_windows(run / "live-windows.jsonl")) == out["mlb"]["windows"]
