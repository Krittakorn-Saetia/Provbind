"""eval/live_demo.py and scripts/live-demo.sh: the presenter's side of the live demo (docs/LIVE-DEMO.md)."""
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from alerts import trust as tr
from eval import live_demo as ld

ROOT = Path(__file__).resolve().parents[2]
HEX = "cd" * 32
DIGEST = "sha256:" + HEX
UNSIGNED = "sha256:" + "ef" * 32


def alert(cls, sub, bucket, score=50, chain="chain-1", **attr):
    return {"class": cls, "subclass": sub, "bucket": bucket, "score": score, "chain_id": chain,
            "attribution": attr}


def make_run(tmp_path, alerts=(), falco=()):
    run = tmp_path / "run-demo"
    for d in ("contexts", "envelopes"):
        (run / d).mkdir(parents=True)
    (run / "bindings.json").write_text(json.dumps({
        "c1": {"namespace": "demo", "pod": "demo-app-6f7c9", "image_digest": DIGEST, "verified": True,
               "envelope_ready": True, "reason": "signature and both attestations verified"},
        "c2": {"namespace": "demo", "pod": "demo-app-unsigned-55d4", "image_digest": UNSIGNED, "verified": False,
               "envelope_ready": False, "reason": "v_sig: no signatures found"}}))
    (run / "contexts" / f"{HEX}.json").write_text(json.dumps(
        {"checks": {"v_sig": True, "v_B": True, "v_P": True, "v_trans": True, "v_trust": None}, "verify_ms": 1830.0}))
    (run / "contexts" / f"{'ef' * 32}.json").write_text(json.dumps(
        {"checks": {"v_sig": False, "v_B": False, "v_P": False, "v_trans": None, "v_trust": None}}))
    (run / "envelopes" / f"{HEX}.json").write_text(json.dumps({
        "image": {"builder_id": "https://example.test/builders/local@v1", "source_commit": "9f31ab2c4d5e6f70",
                  "rekor_log_index": 123},
        "layers": [{"index": i} for i in range(6)], "files": {f"/f{i}": {} for i in range(5695)},
        "packages": {f"p{i}": {} for i in range(109)}, "closure": ["/a", "/b", "/c", "/d"],
        "timings_ms": {"evidence": 2300, "union": 700, "caps": 100, "other": 1280}}))
    (run / "alerts.jsonl").write_text("".join(json.dumps(a) + "\n" for a in alerts) + "broken line\n")
    if falco:
        (run / "falco.jsonl").write_text("".join(json.dumps(f) + "\n" for f in falco))
    return run


def test_counts_split_alerts_from_low_records(tmp_path):
    run = make_run(tmp_path, [alert("D_exec", "outside_closure", "low", 30),
                              alert("D_exec", "outside_closure", "low", 30),
                              alert("D_exec", "undeclared", "critical", 90),
                              {"class": "trust", "subclass": "comp", "bucket": "high"}])
    assert ld.count(run, "D_exec", "outside_closure", "low") == 2
    assert ld.count(run, "D_exec", which="alerts") == 1
    assert ld.count(run, which="alerts") == 2
    assert ld.count(run) == 4
    assert ld.count(tmp_path / "missing") == 0


def test_envelope_card_shows_the_checks_and_the_compile_time(tmp_path):
    out = "\n".join(ld.envelope_summary(make_run(tmp_path)))
    assert "signature ok, SBOM ok, provenance ok, transparency log ok" in out
    assert "verified in 1.8 s" in out
    assert "envelope compiled in 4.4 s, from the signed evidence alone" in out
    assert "6 layers · 5,695 files · 109 packages · 4 programs" in out
    assert "commit 9f31ab2c" in out and "Rekor entry 123" in out


def test_the_unsigned_pod_is_not_taken_for_the_demo_app_and_shows_why_it_failed(tmp_path):
    run = make_run(tmp_path)
    assert ld.binding_for(run, "demo-app")["pod"] == "demo-app-6f7c9"
    out = "\n".join(ld.binding_summary(run, "demo-app-unsigned"))
    assert "demo-app-unsigned-55d4: NOT VERIFIED: v_sig: no signatures found" in out
    assert "signature FAILED" in out and "envelope: none" in out


def test_incident_summary_says_one_incident_and_where_the_file_comes_from(tmp_path):
    run = make_run(tmp_path, [alert("D_exec", "undeclared", "critical", 90),
                              alert("D_write", "declared_file", "high", 72, layer="sha256:" + "11" * 32,
                                    package="pkg:deb/debian/base-passwd@3.6.1", depth=0)])
    out = "\n".join(ld.incident_summary(run))
    assert "CRITICAL 90: D_exec/undeclared -> no layer or package: not part of the signed image" in out
    assert "HIGH 72: D_write/declared_file -> layer 111111111111, package pkg:deb/debian/base-passwd@3.6.1" in out
    assert "one incident (chain-1)" in out


def test_trust_summary_gives_the_delay_and_the_unchanged_runtime_state(tmp_path):
    run = make_run(tmp_path, [{"class": "trust", "subclass": "comp", "bucket": "high", "trust_reason": ["comp"],
                               "latency_s": 1.684, "runtime_state": "conforming",
                               "attribution": {"package": "pkg:pypi/requestz-helper@0.1.0", "depth": 2}}])
    out = "\n".join(ld.trust_summary(run))
    assert "trust withdrawn: component advisory; package pkg:pypi/requestz-helper@0.1.0, depth 2" in out
    assert "raised 1.7 s after the advisory appeared" in out and "CONFORMING" in out


def with_clause(a, clause):
    return {**a, "violated_clause": clause}


def test_since_lists_the_new_alerts_one_line_each_and_counts_the_low_records(tmp_path):
    run = make_run(tmp_path, [
        alert("D_exec", "outside_closure", "low", 30),                                  # before the mark
        with_clause(alert("D_exec", "undeclared", "critical", 90),
                    "file_set: /tmp/.x9: path is in no layer of the attested image"),
        alert("D_exec", "outside_closure", "low", 30),
        with_clause(alert("D_write", "declared_file", "high", 72, layer="sha256:" + "11" * 32,
                          package="pkg:deb/debian/base-passwd@3.6.1", depth=0),
                    "file_set: /etc/passwd: write to a file declared in layer 1; not under a mount")])
    assert ld.since_summary(run, since=1) == [
        "CRITICAL 90  Undeclared program executed: /tmp/.x9 -> no layer or package: not part of the signed image",
        "HIGH 72  Signed image file modified: /etc/passwd -> layer 111111111111, "
        "package pkg:deb/debian/base-passwd@3.6.1, depth 0  (same incident)",
        "(and 1 Low record: logged, not alerts)"]
    assert ld.since_summary(run, since=4) == ["no alert"]


def test_trust_summary_for_a_revoked_key_names_no_package(tmp_path):
    run = make_run(tmp_path, [{"class": "trust", "subclass": "key", "bucket": "high", "trust_reason": ["key"],
                               "latency_s": 1.2, "runtime_state": "conforming",
                               "attribution": {"layer": None, "package": None, "depth": None}}])
    out = ld.trust_summary(run)
    assert out[:2] == ["trust withdrawn: signing key revoked", "raised 1.2 s after the change"]


def envelope_with(purl):
    return {"packages": {purl: {"depth": 2}}, "files": {"/app/x.py": {"package": purl, "layer": 3}},
            "layers": [{"index": 3, "digest": "sha256:" + "33" * 32}]}


def test_the_demo_advisory_withdraws_trust_in_the_real_trust_check(tmp_path):
    path = ld.write_advisory(tmp_path, "MAL-2026-9001", "PyPI", "requestz-helper", "0.1.0")
    assert path == tmp_path / "advisories" / "requestz-helper.json"
    assert [p.name for p in (tmp_path / "advisories").iterdir()] == ["requestz-helper.json"]   # no temp file left
    ok, _, findings, _ = tr.comp_check(envelope_with("pkg:pypi/requestz-helper@0.1.0"), tr.load_advisories(tmp_path))
    assert ok is False
    assert findings[0]["advisory"] == "MAL-2026-9001" and findings[0]["depth"] == 2
    assert findings[0]["layers"] == ["sha256:" + "33" * 32]


def test_the_advisory_settings_version_id_and_package_name(tmp_path):
    env = envelope_with("pkg:pypi/requestz-helper@0.1.0")
    ld.write_advisory(tmp_path / "other", "MAL-1", "PyPI", "requestz-helper", "9.9.9")     # another version
    assert tr.comp_check(env, tr.load_advisories(tmp_path / "other"))[0] is True
    ld.write_advisory(tmp_path / "all", "MAL-1", "PyPI", "requestz-helper", None)          # every version
    assert tr.comp_check(env, tr.load_advisories(tmp_path / "all"))[0] is False
    ld.write_advisory(tmp_path / "cve", "CVE-2026-0001", "PyPI", "requestz-helper", "0.1.0")
    ok, _, findings, reported = tr.comp_check(env, tr.load_advisories(tmp_path / "cve"))
    assert ok is True and not findings and reported[0]["advisory"] == "CVE-2026-0001"    # reported only
    assert ld.write_advisory(tmp_path / "npm", "MAL-2", "npm", "@scope/pkg", "1.0.0").name == "scope_pkg.json"


def test_the_advisory_command_prints_the_path_and_needs_an_id(tmp_path, capsys):
    assert ld.main(["advisory", "--run", str(tmp_path), "--id", "MAL-3", "--package", "requestz-helper"]) == 0
    assert capsys.readouterr().out.strip() == str(tmp_path / "advisories" / "requestz-helper.json")
    with pytest.raises(SystemExit):
        ld.main(["advisory", "--run", str(tmp_path), "--package", "requestz-helper"])


def test_falco_summary_reads_only_the_new_lines(tmp_path):
    run = make_run(tmp_path, falco=[{"rule": "Old rule", "priority": "Notice"},
                                    {"rule": "Terminal shell in container", "priority": "Notice"},
                                    {"rule": "Terminal shell in container", "priority": "Notice"}])
    assert ld.lines_in(run / "falco.jsonl") == 3
    out = ld.falco_summary(run, since=1)
    assert out == ["Falco: Terminal shell in container (Notice)", "Falco: 2 alerts in all"]
    assert ld.falco_summary(run, since=3) == ["Falco: no alert"]


def falco_event(rule, ns=None, pod=None):
    return {"rule": rule, "priority": "Notice",
            "output_fields": {"k8s.ns.name": ns, "k8s.pod.name": pod, "container.id": "host" if ns is None else "abc"}}


def test_falco_summary_leaves_out_the_machines_own_programs(tmp_path):
    run = make_run(tmp_path, falco=[falco_event("Read sensitive file untrusted"),             # the VM's desktop
                                    falco_event("Terminal shell in container", "demo", "demo-app-6f7c9"),
                                    falco_event("Launch Privileged Container", "kube-system", "tetragon-x"),
                                    falco_event("Read sensitive file untrusted")])
    assert ld.falco_summary(run, namespace="demo", pod_prefix="demo-app") == [
        "Falco: Terminal shell in container (Notice)", "Falco: 1 alert in all"]
    assert ld.falco_summary(run, since=2, namespace="demo", pod_prefix="demo-app") == ["Falco: no alert"]
    assert ld.falco_summary(run)[-1] == "Falco: 4 alerts in all"            # unfiltered without a namespace


def test_summaries_say_when_there_is_nothing_yet(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert ld.envelope_summary(empty) == ["no binding yet for a pod named demo-app*"]
    assert ld.incident_summary(empty) == ["no attack alert yet"]
    assert ld.trust_summary(empty) == ["no trust alert yet"]


SETTINGS = ("ACTS PAUSE CAPTIONS ATTACK TRUST ADVISORY_PACKAGE ADVISORY_VERSION ADVISORY_ECOSYSTEM ADVISORY_ID "
            "SHELL_CMD FRESH REDEPLOY WAIT_S KEEP_RUNS FALCO POLICY_SET DEMO_REF NAMESPACE DEPLOY").split()
SCRIPT = ROOT / "scripts" / "live-demo.sh"
CONF = ROOT / "testbed" / "live-demo.conf"


def run_script(tmp_path, *args, conf="", **env):
    """A dry run (commands printed, not run) with the built-in defaults, or with CONF's text as the settings."""
    conf_file = tmp_path / "live-demo.conf"
    conf_file.write_text(conf)
    full = {k: v for k, v in os.environ.items() if k not in SETTINGS}
    full.update({"DRY_RUN": "1", "AUTO": "1", "PROVBIND_RUN": str(tmp_path / "run-demo"), "DEMO_CONF": str(conf_file),
                 "DEMO_REF": "localhost:5001/demo-app@sha256:" + HEX, **env})
    return subprocess.run(["bash", str(SCRIPT), *args], cwd=ROOT, env=full, capture_output=True, text=True, timeout=120)


def test_the_script_parses():
    assert subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0


def test_the_settings_file_names_every_setting_and_is_valid(tmp_path):
    text = CONF.read_text()
    for name in SETTINGS:
        assert f"\n{name}=" in text, f"{name} is not in {CONF.name}"
    r = run_script(tmp_path, "settings", DEMO_CONF=str(CONF))
    assert r.returncode == 0, r.stderr
    assert "ATTACK              update" in r.stdout


def test_one_command_restarts_provbind_on_a_fresh_folder_and_runs_five_acts(tmp_path):
    r = run_script(tmp_path)                                  # no command: the demo
    assert r.returncode == 0, r.stderr
    out = r.stdout
    assert f"+ mv {tmp_path / 'run-demo'} " in out           # the last run is moved aside
    assert "kubectl apply -f node/tetragon/opt/write.yaml" in out
    assert "kubectl delete --ignore-not-found -f node/tetragon/write.yaml" in out
    for service in ("controller.watch", "node.run", "alerts.run", "alerts.trust", "capture_falco.sh"):
        assert service in out
    heads = ["[1/5] envelope", "[2/5] shell", "[3/5] attack", "[4/5] trust", "[5/5] log"]
    assert all(h in out for h in heads)
    assert [out.index(h) for h in heads] == sorted(out.index(h) for h in heads)
    assert "+ curl_app /update" in out and "--id MAL-2026-9001" in out and "tamper.sh" in out
    assert "unsigned" not in out.split("[1/5]", 1)[1] and "watch:" not in out
    assert "done in" in out


def test_acts_run_in_the_order_given(tmp_path):
    r = run_script(tmp_path, ACTS="trust attack")
    assert r.returncode == 0, r.stderr
    assert r.stdout.index("[1/2] trust") < r.stdout.index("[2/2] attack")
    assert "] envelope" not in r.stdout and "waits up to 90 s for the app's envelope" in r.stdout
    r = run_script(tmp_path, ACTS="unsigned", CAPTIONS="long")
    assert r.returncode == 0, r.stderr
    assert "[1/1] unsigned" in r.stdout and "docker build" in r.stdout and "teardown_temp demo-app-unsigned" in r.stdout
    assert "watch:" in r.stdout and "built outside the pipeline" in r.stdout


@pytest.mark.parametrize("attack,endpoint", [("update", "/update"), ("overwrite", "/ru4"), ("inject", "/rk3"),
                                             ("egress", "/ru3")])
def test_each_attack_sends_its_request(tmp_path, attack, endpoint):
    r = run_script(tmp_path, ACTS="attack", ATTACK=attack)
    assert r.returncode == 0, r.stderr
    assert f"+ curl_app {endpoint}\n" in r.stdout


def test_trust_by_key_or_by_an_advisory_that_only_reports(tmp_path):
    r = run_script(tmp_path, ACTS="trust", TRUST="key")
    assert r.returncode == 0, r.stderr
    assert "alerts.trust set-key" in r.stdout and "--state revoked" in r.stdout and "advisory --run" not in r.stdout
    r = run_script(tmp_path, ACTS="trust", ADVISORY_ID="CVE-2026-1234", ADVISORY_VERSION="")
    assert r.returncode == 0, r.stderr
    assert "names requestz-helper (every version)" in r.stdout
    assert "--id CVE-2026-1234" in r.stdout and "so it is reported and trust stays" in r.stdout


def test_the_command_line_beats_the_settings_file_which_beats_the_defaults(tmp_path):
    r = run_script(tmp_path, "settings", conf="ATTACK=inject\nPAUSE=enter\n", ATTACK="egress")
    assert r.returncode == 0, r.stderr
    lines = {line.split()[0]: line.split() for line in r.stdout.splitlines()[1:]}
    assert lines["ATTACK"][1:] == ["egress", "command", "line"]
    assert lines["PAUSE"][1:] == ["enter", "conf"]
    assert lines["CAPTIONS"][1:] == ["short", "default"]


def test_bad_settings_stop_the_demo_before_anything_runs(tmp_path):
    r = run_script(tmp_path, ATTACK="bogus", ACTS="envelope demo", PAUSE="soon")
    assert r.returncode == 2
    for bad in ("ATTACK=bogus", "no act named 'demo'", "PAUSE=soon"):
        assert bad in r.stderr
    assert "+ " not in r.stdout
    r = run_script(tmp_path, ADVISORY_ECOSYSTEM="pip")
    assert r.returncode == 2 and "ADVISORY_ECOSYSTEM=pip" in r.stderr
    assert run_script(tmp_path, "settings", ADVISORY_ECOSYSTEM="Debian:12").returncode == 0
    r = run_script(tmp_path, DEMO_CONF=str(tmp_path / "missing.conf"))
    assert r.returncode == 2 and "no settings file" in r.stderr


def test_one_act_keeps_the_folder(tmp_path):
    (tmp_path / "run-demo").mkdir()
    r = run_script(tmp_path, "act", "trust")
    assert r.returncode == 0, r.stderr
    assert "[1/1] trust" in r.stdout and "+ mv " not in r.stdout
    assert "controller.watch" in r.stdout                    # no services were running, so they start
    assert run_script(tmp_path, "act", "nine").returncode == 2


def test_acts_may_span_lines_in_the_settings_file(tmp_path):
    r = run_script(tmp_path, conf='ACTS="trust\n      log"\n')
    assert r.returncode == 0, r.stderr
    assert "[1/2] trust" in r.stdout and "[2/2] log" in r.stdout


def test_redeploy_without_the_envelope_act_still_deploys_the_app(tmp_path):
    r = run_script(tmp_path, ACTS="attack", REDEPLOY="1")
    assert r.returncode == 0, r.stderr
    out = r.stdout
    assert out.index("delete deployment demo-app") < out.index("create deployment 'demo-app'") < out.index("[1/1] attack")


def test_redeploy_policy_set_and_falco_settings(tmp_path):
    r = run_script(tmp_path, ACTS="envelope", REDEPLOY="1", POLICY_SET="orig", FALCO="off")
    assert r.returncode == 0, r.stderr
    assert "delete deployment demo-app" in r.stdout and "create deployment 'demo-app'" in r.stdout
    assert "kubectl apply -f node/tetragon/write.yaml" in r.stdout
    assert "delete --ignore-not-found -f node/tetragon/opt/write.yaml" in r.stdout
    assert "capture_falco" not in r.stdout
    assert "deployed by its digest" in r.stdout


def test_help_and_unknown_commands(tmp_path):
    r = run_script(tmp_path, "help")
    assert r.returncode == 0 and "make live-demo ATTACK=overwrite PAUSE=enter" in r.stdout
    assert "set -euo" not in r.stdout
    assert run_script(tmp_path, "dance").returncode == 2


def source_and_run(tmp_path, body, **env):
    """Source the script (no command runs) and run BODY with its functions, for real (no dry run)."""
    conf_file = tmp_path / "live-demo.conf"
    conf_file.write_text("")
    full = {k: v for k, v in os.environ.items() if k not in SETTINGS}
    full.update({"PROVBIND_RUN": str(tmp_path / "run-demo"), "DEMO_CONF": str(conf_file), **env})
    return subprocess.run(["bash", "-c", f'source "{SCRIPT}" && {body}'], cwd=ROOT, env=full,
                          capture_output=True, text=True, timeout=60)


def test_each_run_moves_the_last_folder_aside_and_keeps_keep_runs_of_them(tmp_path):
    run = tmp_path / "run-demo"
    (run / "logs").mkdir(parents=True)
    (run / "alerts.jsonl").write_text("{}\n")
    for day in ("20200101", "20200102", "20200103"):
        (tmp_path / f"run-demo.{day}-000000").mkdir()
    for stamp in ("run-demo.overwrite.at", "run-demo.unsigned.ref"):
        (tmp_path / stamp).write_text("x\n")
    r = source_and_run(tmp_path, "new_run_folder", KEEP_RUNS="2")
    assert r.returncode == 0, r.stderr
    assert sorted(os.listdir(run)) == ["logs"]                              # a fresh, empty folder
    kept = sorted(p.name for p in tmp_path.iterdir() if p.name.startswith("run-demo.2"))
    assert len(kept) == 2 and kept[0] == "run-demo.20200103-000000"         # the newest older run stays
    assert (tmp_path / kept[1] / "alerts.jsonl").exists()                   # the run just moved aside
    assert (tmp_path / "run-demo.overwrite.at").exists() and (tmp_path / "run-demo.unsigned.ref").exists()


def test_a_repeated_overwrite_waits_out_the_sensors_rate_limit(tmp_path):
    (tmp_path / "run-demo.overwrite.at").write_text("%d\n" % (time.time() - 20))
    r = source_and_run(tmp_path, "rate_limit_wait", ATTACK="overwrite", DRY_RUN="1")
    assert r.returncode == 0, r.stderr
    left = int(r.stdout.split("(waiting ")[1].split(" s")[0])
    assert 40 <= left <= 42
    for env in ({"ATTACK": "update"}, {"ATTACK": "overwrite", "POLICY_SET": "orig"}):
        r = source_and_run(tmp_path, "rate_limit_wait", DRY_RUN="1", **env)
        assert r.returncode == 0 and "waiting" not in r.stdout
