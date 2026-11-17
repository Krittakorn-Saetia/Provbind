"""eval/live_demo.py and scripts/live-demo.sh: the presenter's side of the live demo (docs/LIVE-DEMO.md)."""
import json
import os
import subprocess
from pathlib import Path

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
    assert "envelope compiled in 4.4 s" in out
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


def test_falco_summary_reads_only_the_new_lines(tmp_path):
    run = make_run(tmp_path, falco=[{"rule": "Old rule", "priority": "Notice"},
                                    {"rule": "Terminal shell in container", "priority": "Notice"},
                                    {"rule": "Terminal shell in container", "priority": "Notice"}])
    assert ld.lines_in(run / "falco.jsonl") == 3
    out = ld.falco_summary(run, since=1)
    assert out == ["Falco: Terminal shell in container (Notice)", "Falco: 2 alerts in all"]
    assert ld.falco_summary(run, since=3) == ["Falco: no alert"]


def test_summaries_say_when_there_is_nothing_yet(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert ld.envelope_summary(empty) == ["no binding yet for a pod named demo-app*"]
    assert ld.incident_summary(empty) == ["no attack alert yet"]
    assert ld.trust_summary(empty) == ["no trust alert yet"]


def run_script(tmp_path, *args, **env):
    full = {**os.environ, "DRY_RUN": "1", "AUTO": "1", "PROVBIND_RUN": str(tmp_path / "run-demo"),
            "DEMO_REF": "localhost:5001/demo-app@sha256:" + HEX, **env}
    return subprocess.run(["bash", str(ROOT / "scripts" / "live-demo.sh"), *args], cwd=ROOT, env=full,
                          capture_output=True, text=True, timeout=60)


def test_the_script_parses():
    assert subprocess.run(["bash", "-n", str(ROOT / "scripts" / "live-demo.sh")]).returncode == 0


def test_a_dry_run_walks_through_all_six_acts(tmp_path):
    r = run_script(tmp_path, "run")
    assert r.returncode == 0, r.stderr
    for n in range(1, 7):
        assert f"ACT {n}" in r.stdout
    assert "kubectl" in r.stdout and "+ " in r.stdout          # commands are printed, not run


def test_a_dry_run_of_prep_applies_one_policy_set_and_starts_the_services(tmp_path):
    r = run_script(tmp_path, "prep")
    assert r.returncode == 0, r.stderr
    assert "node/tetragon/opt/write.yaml" in r.stdout
    for service in ("controller.watch", "node.run", "alerts.run", "alerts.trust"):
        assert service in r.stdout
    assert "eval.demo_view" in r.stdout


def test_skipped_acts_and_a_single_act(tmp_path):
    r = run_script(tmp_path, "run", SKIP="2 5")
    assert r.returncode == 0, r.stderr
    assert "ACT 2" not in r.stdout and "ACT 5" not in r.stdout and "ACT 3" in r.stdout
    r = run_script(tmp_path, "act", "4")
    assert r.returncode == 0, r.stderr
    assert "ACT 4" in r.stdout and "ACT 3" not in r.stdout
    assert run_script(tmp_path, "act", "9").returncode != 0
