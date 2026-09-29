"""alerts/trust.py: Phase 6 checks, alert-once and the policy (PH6-01 to 08)."""
import copy
import json

import pytest

from alerts import trust, verify_log
from alerts.trust import (builder_check, comp_check, cycle, key_check, key_id_of, main, set_key, trans_check,
                          verify_inclusion)

from .helpers import BUNDLE, ROOT, golden, read_jsonl, write_run

KEY = ROOT / "pipeline" / "keys" / "cosign.pub"


@pytest.fixture
def env():
    return golden()


@pytest.fixture
def bundle():
    return json.loads(BUNDLE.read_text(encoding="utf-8"))


def context(env, t0="2026-09-29T08:00:00.000Z", bundle=None):
    return {"digest": env["image"]["digest"], "t0": t0, "verified": True,
            "key": {"path": str(KEY), "key_id": key_id_of(KEY)}, "signature_bundle": bundle}


@pytest.fixture
def run(tmp_path, env):
    r = write_run(tmp_path, env)
    (r / "contexts").mkdir()
    (r / "contexts" / f"{env['image']['digest'].split(':')[1]}.json").write_text(json.dumps(context(env)))
    return r


def advisory(run, name, aid, pkg, versions=None):
    (run / "advisories").mkdir(exist_ok=True)
    affected = {"package": pkg}
    if versions is not None:
        affected["versions"] = versions
    (run / "advisories" / name).write_text(json.dumps({"id": aid, "affected": [affected]}))


# --- the checks ---------------------------------------------------------------------------------------

def test_key_ids_ignore_line_endings(tmp_path):
    crlf = tmp_path / "k.pub"
    crlf.write_bytes(KEY.read_bytes().replace(b"\n", b"\r\n"))
    assert key_id_of(crlf) == key_id_of(KEY) and key_id_of(KEY).startswith("sha256:")


@pytest.mark.parametrize("state,since,expected", [
    (None, None, True), ("active", None, True), ("revoked", None, False), ("disabled", None, False),
    ("rotated", "2026-09-29T09:00:00Z", True),          # rotated after t0: signature kept
    ("rotated", "2026-09-29T07:00:00Z", False),         # rotated before t0
])
def test_key_check(env, state, since, expected):
    ks = {} if state is None else {"keys": {key_id_of(KEY): {"state": state, "since": since}}}
    assert key_check(context(env), ks)[0] is expected


def test_key_check_without_a_context_is_not_applicable():
    assert key_check(None, {})[0] is None


def test_the_real_rekor_proof_verifies(bundle):
    ok, why = verify_inclusion(bundle["verificationMaterial"]["tlogEntries"][0])
    assert ok, why


@pytest.mark.parametrize("corrupt", ["hash", "root", "checkpoint", "body"])
def test_a_corrupted_proof_fails(bundle, corrupt):                            # PH6-08
    e = copy.deepcopy(bundle["verificationMaterial"]["tlogEntries"][0])
    p = e["inclusionProof"]
    if corrupt == "hash":
        p["hashes"][3] = p["hashes"][4]
    elif corrupt == "root":
        p["rootHash"] = p["hashes"][0]
    elif corrupt == "checkpoint":
        p["checkpoint"]["envelope"] = p["checkpoint"]["envelope"].replace(p["treeSize"], str(int(p["treeSize"]) + 1), 1)
    else:
        e["canonicalizedBody"] = e["canonicalizedBody"][:-8] + "AAAAAAA="
    assert verify_inclusion(e)[0] is False


def test_without_a_stored_record_trans_is_not_applicable(env):
    assert trans_check(context(env, bundle=None))[0] is None


@pytest.mark.parametrize("denylist", [["https://github.com/sf9-26/provbind/builders/local@v1"],
                                      {"denied": ["https://github.com/sf9-26/provbind/builders/local@v1"]}])
def test_builder_denylist(env, denylist):
    assert builder_check(env, denylist)[0] is False
    assert builder_check(env, ["someone-else"])[0] is True


def test_a_mal_advisory_withdraws_with_package_depth_and_layer(env):
    adv = [("a.json", {"id": "MAL-2026-1", "affected": [{"package": {"ecosystem": "PyPI", "name": "Requests"},
                                                         "versions": ["2.32.3"]}]})]
    ok, why, findings, reported = comp_check(env, adv)
    assert ok is False and "pkg:pypi/requests@2.32.3" in why
    assert findings[0]["depth"] == 1 and findings[0]["layers"] == [env["layers"][2]["digest"]]


def test_an_advisory_for_another_version_does_not_match(env):
    adv = [("a.json", {"id": "MAL-2026-1", "affected": [{"package": {"purl": "pkg:pypi/requests"}, "versions": ["9.9"]}]})]
    assert comp_check(env, adv)[0] is True


def test_an_ordinary_cve_is_reported_not_withdrawn(env):                       # PH6-05
    adv = [("c.json", {"id": "CVE-2026-0001", "affected": [{"package": {"purl": "pkg:pypi/urllib3"}}]})]
    ok, _, findings, reported = comp_check(env, adv)
    assert ok is True and not findings and reported == [{"advisory": "CVE-2026-0001", "package": "pkg:pypi/urllib3@2.2.2"}]


# --- the cycle --------------------------------------------------------------------------------------------

def test_an_admitted_image_starts_trusted(run, env):                            # PH6-01
    assert cycle(run) == []
    state = json.loads((run / "trust" / f"{env['image']['digest'].split(':')[1]}.json").read_text())
    assert state["trusted"] is True and state["checks"]["key"] is True and state["checks"]["trans"] is None


def test_a_revoked_key_alerts_once_naming_key(run):                             # PH6-02, PH6-06
    cycle(run)
    set_key(run, str(KEY), "revoked", None)
    written = [len(cycle(run)) for _ in range(5)]
    assert written == [1, 0, 0, 0, 0]
    (a,) = read_jsonl(run / "alerts.jsonl")
    assert (a["class"], a["subclass"], a["trust_reason"]) == ("trust", "key", ["key"])
    assert a["runtime_state"] == "conforming" and a["container"] == "demo/demo-app-7d9f/app"
    assert verify_log.verify(run).ok


def test_trust_restored_then_lost_again_alerts_again(run):
    set_key(run, str(KEY), "revoked", None)
    cycle(run)
    set_key(run, str(KEY), "active", None)
    assert cycle(run) == []
    set_key(run, str(KEY), "revoked", None)
    assert len(cycle(run)) == 1


def test_trust_1_names_the_component_with_its_layer(run, env):                  # PH6-04
    advisory(run, "requests.json", "MAL-2026-9001", {"ecosystem": "PyPI", "name": "requests"}, ["2.32.3"])
    (a,) = cycle(run)
    assert a["trust_reason"] == ["comp"] and a["attribution"]["package"] == "pkg:pypi/requests@2.32.3"
    assert a["attribution"]["layer"] == env["layers"][2]["digest"] and a["attribution"]["depth"] == 1


def test_the_alert_says_the_runtime_state_separately(run, env):                 # PH6-07
    (run / "alerts.jsonl").write_text(json.dumps({"image_digest": env["image"]["digest"], "class": "D_exec",
                                                  "bucket": "critical"}) + "\n")
    (run / "log").mkdir()
    advisory(run, "requests.json", "MAL-2026-9001", {"purl": "pkg:pypi/requests"})
    (a,) = cycle(run)
    assert a["runtime_state"] == "deviating"


def test_a_denied_builder_names_builder(run, env):                              # PH6-03
    (run / "builder_denylist.json").write_text(json.dumps([env["image"]["builder_id"]]))
    (a,) = cycle(run)
    assert a["trust_reason"] == ["builder"]


def test_unverified_bindings_are_not_evaluated(tmp_path, env):
    r = write_run(tmp_path, env, binding={"verified": False})
    set_key(r, str(KEY), "revoked", None)
    assert cycle(r) == [] and not (r / "trust").exists()


def test_every_section_4_5_field_is_present(run):
    set_key(run, str(KEY), "revoked", None)
    (a,) = cycle(run)
    keys = {"alert_id", "detection_id", "time", "image_digest", "container", "class", "subclass", "violated_clause",
            "origin", "score", "bucket", "attribution", "signing_identity", "chain_id", "log_k"}
    assert keys <= set(a) and a["latency_s"] is not None


def test_the_cli(run, capsys):
    assert main(["key-id", "--key", str(KEY)]) == 0
    assert capsys.readouterr().out.strip() == key_id_of(KEY)
    assert main(["set-key", "--run", str(run), "--key", str(KEY), "--state", "revoked"]) == 0
    capsys.readouterr()
    assert main(["--run", str(run), "--once"]) == 0
    assert json.loads(capsys.readouterr().out) == {"trust_alerts_written": 1}


def test_trust_alert_score_is_a_documented_constant():
    assert trust.TRUST_SCORE == 70
