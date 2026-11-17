"""eval/demo_view.py: the audience screen of the live demo (docs/LIVE-DEMO.md)."""
import io
import json
import os

from eval import demo_view as dv

HEX = "ab" * 32
DIGEST = "sha256:" + HEX
LAYERS = ["sha256:" + c * 32 for c in ("00", "11", "22", "33")]


def det(cls, sub, bucket, score, clause, t="2026-11-17T06:40:00Z", chain="chain-1", layer=None,
        package=None, depth=None, dep=None, proc=("/usr/local/bin/python3.11", "/tmp/.x9")):
    return {"time": t, "image_digest": DIGEST, "class": cls, "subclass": sub, "violated_clause": clause,
            "score": score, "bucket": bucket, "chain_id": chain, "pod": "demo-app-6f7c9",
            "attribution": {"layer": layer, "package": package, "depth": depth, "process_chain": list(proc),
                            "dependency_path": dep}}


def trust(t="2026-11-17T06:45:00Z"):
    return {"time": t, "image_digest": DIGEST, "class": "trust", "subclass": "comp", "score": 70,
            "bucket": "high", "chain_id": None, "trust_reason": ["comp"],
            "violated_clause": "comp: pkg:pypi/requestz-helper@0.1.0 has the malicious-package advisory MAL-2026-9001",
            "attribution": {"layer": LAYERS[3], "package": "pkg:pypi/requestz-helper@0.1.0", "depth": 2,
                            "process_chain": []},
            "latency_s": 1.684, "runtime_state": "conforming"}


def run_folder(tmp_path, alerts):
    (tmp_path / "envelopes").mkdir()
    layers = [{"index": i, "digest": d} for i, d in enumerate(LAYERS)]
    (tmp_path / "envelopes" / f"{HEX}.json").write_text(json.dumps({"layers": layers}))
    (tmp_path / "alerts.jsonl").write_text("".join(json.dumps(a) + "\n" for a in alerts) + "not json\n")
    return tmp_path


def text(lines):
    return "\n".join(lines)


def test_undeclared_exec_card_says_it_is_not_in_the_signed_image(tmp_path):
    a = det("D_exec", "undeclared", "critical", 90, "file_set: /tmp/.x9: path is in no layer of the attested image")
    out = text(dv.card(a, dv.Layers(run_folder(tmp_path, [a])), width=200))
    assert "CRITICAL  90  Undeclared program executed" in out
    assert "/tmp/.x9: path is in no layer of the attested image" in out
    assert "from: nothing in the signed image" in out
    assert "process python3.11 > .x9" in out and "incident chain-1" in out


def test_write_card_names_the_layer_package_and_depth(tmp_path):
    a = det("D_write", "declared_file", "high", 72,
            "file_set: /etc/passwd: write to a file declared in layer 1; not under a mount",
            layer=LAYERS[1], package="pkg:deb/debian/base-passwd@3.6.1?arch=amd64", depth=0)
    out = text(dv.card(a, dv.Layers(run_folder(tmp_path, [a])), width=200))
    assert "HIGH      72  Signed image file modified" in out
    assert "layer 1 of 4 (111111111111)" in out
    assert "package base-passwd 3.6.1" in out and "dependency depth 0" in out


def test_dependency_path_is_shown_from_the_root(tmp_path):
    dep = ["pkg:pypi/demo-app@1.0", "pkg:pypi/requests@2.32.3", "pkg:pypi/requestz-helper@0.1.0"]
    a = det("D_exec", "undeclared", "critical", 90, "file_set: /tmp/.x9: in no layer",
            package=dep[-1], depth=2, dep=dep)
    out = text(dv.card(a, dv.Layers(None), width=200))
    assert "via demo-app 1.0 > requests 2.32.3 > requestz-helper 0.1.0" in out


def test_trust_card_gives_the_reason_the_delay_and_the_runtime_state(tmp_path):
    out = text(dv.card(trust(), dv.Layers(run_folder(tmp_path, [])), width=200))
    assert "TRUST" in out and "Trust withdrawn: component advisory" in out
    assert "MAL-2026-9001" in out and "layer 3 of 4" in out and "package requestz-helper 0.1.0" in out
    assert "raised 1.7 s after the change" in out and "the pod still runs as CONFORMING" in out


def test_low_records_are_one_line_or_hidden():
    low = det("D_exec", "outside_closure", "low", 30,
              "closure: /usr/bin/ls: declared in layer 1, but not reachable from the entrypoint")
    shown, hidden = io.StringIO(), io.StringIO()
    dv.Screen(dv.Layers(None), False, 200, True, shown).show(low)
    dv.Screen(dv.Layers(None), False, 200, False, hidden).show(low)
    assert shown.getvalue().count("\n") == 1 and "logged, not an alert (Low 30): /usr/bin/ls" in shown.getvalue()
    assert hidden.getvalue() == ""


def test_a_second_alert_of_the_same_chain_is_marked_as_the_same_incident():
    out = io.StringIO()
    screen = dv.Screen(dv.Layers(None), False, 200, True, out)
    screen.show(det("D_exec", "undeclared", "critical", 90, "file_set: /tmp/.x9: in no layer"))
    screen.show(det("D_write", "declared_file", "high", 72, "file_set: /etc/passwd: declared"))
    screen.show(det("D_net", "not_allowed", "medium", 50, "egress: /x: 203.0.113.9:4444/tcp", chain="chain-2"))
    lines = out.getvalue().splitlines()
    assert sum("(same incident)" in l for l in lines) == 1
    assert "(same incident)" in next(l for l in lines if "Signed image file modified" in l)


def test_plain_output_has_no_escape_codes_and_colour_has_them():
    a = det("D_exec", "undeclared", "critical", 90, "file_set: /tmp/.x9: in no layer")
    assert "\033" not in text(dv.card(a, dv.Layers(None), colour=False))
    assert "\033[1;91m" in text(dv.card(a, dv.Layers(None), colour=True))


def test_unknown_classes_and_package_names_fall_back_gracefully():
    assert dv.title_of({"class": "D_new", "subclass": "x"}) == "D_new/x"
    assert dv.title_of({"class": "binding", "subclass": "unverified"}) == "Image failed verification"
    assert dv.package_name("requests") == "requests"
    assert dv.package_name(None) is None
    assert dv.clause_parts({"violated_clause": "plain text"}) == ("", "plain text")


def test_bursts_split_a_recording_into_scenarios():
    times = ["2026-11-17T06:40:00Z", "2026-11-17T06:40:02Z", "2026-11-17T06:40:30Z", "2026-11-17T06:40:31Z"]
    groups = dv.bursts([{"time": t} for t in times], gap_s=8)
    assert [len(g) for g in groups] == [2, 2]


def test_main_shows_the_run_once_and_skips_bad_lines(tmp_path, capsys):
    a = det("D_exec", "undeclared", "critical", 90, "file_set: /tmp/.x9: in no layer")
    assert dv.main(["--run", str(run_folder(tmp_path, [a, trust()]))]) == 0
    out = capsys.readouterr().out
    assert "PROVBIND · live alerts" in out
    assert "Undeclared program executed" in out and "Trust withdrawn" in out


def test_replay_says_it_is_not_live(tmp_path, capsys):
    a = det("D_exec", "undeclared", "critical", 90, "file_set: /tmp/.x9: in no layer")
    path = run_folder(tmp_path, [a, trust()]) / "alerts.jsonl"
    assert dv.main(["--replay", str(path), "--speed", "1000", "--max-gap", "0"]) == 0
    out = capsys.readouterr().out
    assert "REPLAY of a recorded run, not live" in out
    assert out.index("Undeclared program executed") < out.index("Trust withdrawn")


def test_a_replaced_alerts_file_is_noticed(tmp_path):
    path = tmp_path / "alerts.jsonl"
    path.write_text("")
    inode = os.stat(path).st_ino
    assert not dv.replaced(path, inode)
    (tmp_path / "new.jsonl").write_text("{}\n")
    os.replace(tmp_path / "new.jsonl", path)
    assert dv.replaced(path, inode)
    path.unlink()
    assert dv.replaced(path, inode)
