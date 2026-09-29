"""Admission and trust on the real stand-in (integration): PH2-01, PH2-09, PH6-01, PH6-02, PH6-04 (P0)
and PH2-02 to 05, PH2-08, PH6-03, PH6-05, PH6-08 (P1). Role 4, Test Plan §3.2 and §3.9.

The controller binds PROVBIND_STANDIN_REF with `--image` (no cluster: on the demo PC the same code
binds the deployed pod), verifying it with cosign and storing its context; the trust loop then
runs on that real context and envelope, with each scenario's input edited as the scenario does
(`keystatus.json` for trust-2, an advisory for trust-1). The stand-in has no requestz-helper, so
trust-1's advisory names `requests`, which it does have; the live scenario is Role 1's E2E-11.
PH2-02 copies the stand-in's image, without any evidence, into a new repository of the local
registry, provbind-ph2-02-<id>, which stays there. Needs cosign, crane and the registry.

PH2-03 to 05 and 08 bind the real stand-in with one thing changed each:
- PH2-03, a wrong key: the controller trusts a throwaway key made for the test (cosign
  generate-key-pair, in the test's temp folder), not the key that signed the stand-in. That is the
  plan's case seen from the other side: a valid signature, but not from the trusted key.
- PH2-04: the Rekor bundle cosign downloads is corrupted on the way (one inclusion-proof hash).
- PH2-05: our key marked revoked in the run folder's keystatus.json before admission.
- PH2-08: the pod's status names a tag that no longer points to the stand-in (a tag that does not
  exist in the registry at all), with the stand-in's digest as its imageID, as after a push to the
  same tag while the pod runs. The controller must bind and verify the running digest.
"""
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from alerts import verify_log
from alerts.trust import cycle, set_key
from compiler import evidence
from controller import watch

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
KEY = str(ROOT / "pipeline" / "keys" / "cosign.pub")


@pytest.fixture(scope="module")
def ref():
    value = os.environ.get("PROVBIND_STANDIN_REF")
    if not value:
        pytest.skip("export PROVBIND_STANDIN_REF=<ref@digest printed by build-and-attest.sh>")
    return value


def bind(tmp_path, ref, name="run", reuse_envelope=True):
    run = tmp_path / name
    (run / "envelopes").mkdir(parents=True)
    hex_ = ref.split("@sha256:")[1]
    env = os.environ.get("PROVBIND_ENVELOPE")
    if reuse_envelope and env and Path(env).name == f"{hex_}.json":
        shutil.copy(env, run / "envelopes" / f"{hex_}.json")          # skip the compile
    code = watch.main(["--run", str(run), "--image", ref, "--pod", "standin-app-1", "--key", KEY])
    return run, code, json.loads((run / "bindings.json").read_text()), json.loads((run / "contexts" / f"{hex_}.json").read_text())


def test_ph2_01_and_ph2_09_admission_and_context(tmp_path, ref, record_result):
    run, code, bindings, ctx = bind(tmp_path, ref)
    (b,) = bindings.values()
    ok1 = code == 0 and b["verified"] is True and b["envelope_ready"] is True
    record_result("PH2-01", "pass" if ok1 else "fail", metrics={"exit": code, "verified": b["verified"],
                                                                "envelope_ready": b["envelope_ready"]},
                  notes=f"controller --image {ref} (no cluster on this machine): binding verified {b['verified']}, "
                        f"envelope_ready {b['envelope_ready']}; {ctx['reason']}")
    entry = ((ctx.get("signature_bundle") or {}).get("verificationMaterial") or {}).get("tlogEntries") or []
    offline = ctx.get("offline")
    checks = ctx.get("checks") or {}
    fields = {"key": bool((ctx.get("key") or {}).get("key_id")),
              "signatures": all(checks.get(k) is True for k in ("v_sig", "v_B", "v_P"))
                            and all(checks.get(k) is not False for k in ("v_trans", "v_trust")),
              "rekor_entry": bool(entry) and ctx.get("rekor_log_index") is not None, "t0": bool(ctx.get("t0"))}
    ok9 = all(fields.values()) or (offline and all(v for k, v in fields.items() if k != "rekor_entry"))
    record_result("PH2-09", "pass" if ok9 else "fail", metrics=fields,
                  notes=f"contexts/<hex>.json holds the key id, the checks {checks}, the Rekor entry (log index "
                        f"{ctx.get('rekor_log_index')}) with its inclusion proof, and t0 {ctx.get('t0')}"
                        + ("; offline: no Rekor entry by design" if offline else ""))
    assert ok1 and ok9


def test_ph2_02_an_unsigned_image_is_not_verified(tmp_path, ref, record_result):
    repo = ref.split("@")[0].rsplit("/", 1)[0] + f"/provbind-ph2-02-{uuid.uuid4().hex[:8]}"
    copy = subprocess.run(["crane", "copy", ref, f"{repo}:unsigned"], capture_output=True, text=True, timeout=300)
    if copy.returncode != 0:
        record_result("PH2-02", "blocked", notes=f"crane copy failed: {copy.stderr.strip()[-200:]}")
        pytest.skip("crane copy failed")
    unsigned = f"{repo}@{ref.split('@')[1]}"
    run, code, bindings, ctx = bind(tmp_path, unsigned, "unsigned", reuse_envelope=False)
    (b,) = bindings.values()
    ok = code == 2 and b["verified"] is False and not list((run / "envelopes").glob("*.json"))
    record_result("PH2-02", "pass" if ok else "fail", metrics={"exit": code, "verified": b["verified"]},
                  notes=f"{unsigned}, copied without any evidence: binding verified {b['verified']} ({b['reason']}); "
                        f"no envelope compiled; the copy stays in the registry")
    assert ok


def test_ph6_trust_on_the_real_context(tmp_path, ref, record_result):
    run, code, _, ctx = bind(tmp_path, ref)
    hex_ = ref.split("@sha256:")[1]
    state = lambda: json.loads((run / "trust" / f"{hex_}.json").read_text())   # noqa: E731

    first = cycle(run)
    s = state()
    ok1 = not first and s["trusted"] is True
    record_result("PH6-01", "pass" if ok1 else "fail", metrics={"trusted": s["trusted"], "checks": s["checks"]},
                  notes=f"right after admission: trusted {s['trusted']}; {s['reasons']}")

    set_key(run, KEY, "revoked", None)
    per_cycle = [len(cycle(run)) for _ in range(3)]
    alerts = [json.loads(l) for l in (run / "alerts.jsonl").read_text().splitlines()]
    ok2 = per_cycle == [1, 0, 0] and alerts[-1]["trust_reason"] == ["key"]
    record_result("PH6-02", "pass" if ok2 else "fail", metrics={"alerts_per_cycle": per_cycle},
                  notes=f"trust-2's edit (our key marked revoked in keystatus.json): {alerts[-1]['violated_clause']}; "
                        f"one alert over {len(per_cycle)} cycles")
    set_key(run, KEY, "active", None)
    cycle(run)

    (run / "advisories").mkdir()
    (run / "advisories" / "requests.json").write_text(json.dumps(
        {"id": "MAL-2026-9001", "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"}}]}))
    got = cycle(run)
    a = got[0] if got else {}
    ok4 = len(got) == 1 and a["trust_reason"] == ["comp"] and a["attribution"]["package"] and a["attribution"]["layer"]
    record_result("PH6-04", "pass" if ok4 else "fail", metrics={"alerts": len(got), "attribution": a.get("attribution")},
                  notes=f"trust-1's edit with an advisory for requests (the stand-in has no requestz-helper): "
                        f"{a.get('violated_clause')}; package {a.get('attribution', {}).get('package')}, layer "
                        f"{str(a.get('attribution', {}).get('layer'))[:19]}, runtime {a.get('runtime_state')}")
    (run / "advisories" / "requests.json").unlink()
    cycle(run)

    (run / "advisories" / "urllib3.json").write_text(json.dumps(
        {"id": "CVE-2026-0001", "affected": [{"package": {"ecosystem": "PyPI", "name": "urllib3"}}]}))
    got5 = cycle(run)
    ok5 = not got5 and state()["trusted"] and state()["advisories_reported"]
    record_result("PH6-05", "pass" if ok5 else "fail", metrics={"alerts": len(got5), "reported": state()["advisories_reported"]},
                  notes="an ordinary CVE for urllib3: no withdrawal; the advisory is reported in the trust state")
    (run / "advisories" / "urllib3.json").unlink()

    envelope = json.loads((run / "envelopes" / f"{hex_}.json").read_text())
    (run / "builder_denylist.json").write_text(json.dumps([envelope["image"]["builder_id"]]))
    got3 = cycle(run)
    ok3 = len(got3) == 1 and got3[0]["trust_reason"] == ["builder"]
    record_result("PH6-03", "pass" if ok3 else "fail", metrics={"alerts": len(got3)},
                  notes=f"the image's builder_id on the denylist: {got3[0]['violated_clause'] if got3 else 'no alert'}")
    (run / "builder_denylist.json").unlink()
    cycle(run)

    if ctx.get("offline"):
        record_result("PH6-08", "blocked", notes="offline signing: no transparency record to corrupt, by design")
        ok8 = True
    else:
        path = run / "contexts" / f"{hex_}.json"
        c = json.loads(path.read_text())
        proof = c["signature_bundle"]["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
        proof["hashes"][0] = proof["hashes"][1]
        path.write_text(json.dumps(c))
        got8 = cycle(run)
        ok8 = len(got8) == 1 and got8[0]["trust_reason"] == ["trans"]
        record_result("PH6-08", "pass" if ok8 else "fail", metrics={"alerts": len(got8)},
                      notes=f"one hash of the stored inclusion proof replaced: "
                            f"{got8[0]['violated_clause'] if got8 else 'no alert'}")
    assert verify_log.verify(run).ok
    assert ok1 and ok2 and ok4 and ok5 and ok3 and ok8


def offline():
    return os.environ.get("PROVBIND_OFFLINE") == "1"


def run_folder(tmp_path, ref, name):
    run = tmp_path / name
    (run / "envelopes").mkdir(parents=True)
    hex_ = ref.split("@sha256:")[1]
    env = os.environ.get("PROVBIND_ENVELOPE")
    if env and Path(env).name == f"{hex_}.json":
        shutil.copy(env, run / "envelopes" / f"{hex_}.json")
    return run


def test_ph2_03_a_signature_from_the_wrong_key_fails_v_sig(tmp_path, ref, record_result):
    keys = tmp_path / "keys"
    keys.mkdir()
    made = subprocess.run(["cosign", "generate-key-pair", "--output-key-prefix", "wrong"], cwd=keys,
                          env={**os.environ, "COSIGN_PASSWORD": ""}, capture_output=True, text=True, timeout=60)
    if made.returncode != 0:
        record_result("PH2-03", "blocked", notes=f"cosign generate-key-pair failed: {made.stderr.strip()[-200:]}")
        pytest.skip("no throwaway key")
    run = run_folder(tmp_path, ref, "wrong-key")
    code = watch.main(["--run", str(run), "--image", ref, "--pod", "standin-app-1", "--key", str(keys / "wrong.pub")])
    (b,) = json.loads((run / "bindings.json").read_text()).values()
    ok = code == 2 and b["verified"] is False and b["reason"].startswith("v_sig")
    record_result("PH2-03", "pass" if ok else "fail", metrics={"exit": code, "verified": b["verified"]},
                  notes=f"the stand-in (signed with pipeline/keys/cosign.key) checked against a throwaway key made "
                        f"for the test: binding verified {b['verified']}, reason: {b['reason'][:160]}")
    assert ok


class CorruptedBundle(evidence.Cosign):
    """cosign as usual, except that the downloaded signature bundle has one proof hash replaced."""

    def download_signature(self, ref):
        values = []
        for v in evidence.json_values(super().download_signature(ref)):
            for entry in ((v.get("verificationMaterial") or {}).get("tlogEntries") or []) if isinstance(v, dict) else []:
                hashes = (entry.get("inclusionProof") or {}).get("hashes") or []
                if len(hashes) > 1:
                    hashes[0] = hashes[1]
            values.append(json.dumps(v))
        return "\n".join(values)


def test_ph2_04_a_broken_transparency_record_fails_v_trans(tmp_path, ref, record_result):
    if offline():
        record_result("PH2-04", "blocked", notes="offline signing: the stand-in has no Rekor entry to corrupt, by design")
        pytest.skip("offline")
    clean_run, code, _, clean = bind(tmp_path, ref, "clean")
    run = run_folder(tmp_path, ref, "corrupted")
    verifier = watch.Verifier(KEY, cosign=CorruptedBundle(KEY), run=run)
    b = watch.Controller(run, KEY, verifier=verifier).bind("containerd://ph2-04", "demo", "standin-app-1", "app", ref)
    ok = clean["checks"].get("v_trans") is True and b["verified"] is False and b["reason"].startswith("v_trans")
    record_result("PH2-04", "pass" if ok else "fail",
                  metrics={"clean_v_trans": clean["checks"].get("v_trans"), "corrupted_verified": b["verified"]},
                  notes=f"the stand-in's own bundle: {clean['reason'][-60:]}; the same bundle with one inclusion-proof "
                        f"hash replaced: binding verified {b['verified']}, reason: {b['reason']}")
    assert ok


def test_ph2_05_a_revoked_key_fails_admission(tmp_path, ref, record_result):
    run = run_folder(tmp_path, ref, "revoked")
    set_key(run, KEY, "revoked", None)
    code = watch.main(["--run", str(run), "--image", ref, "--pod", "standin-app-1", "--key", KEY])
    (b,) = json.loads((run / "bindings.json").read_text()).values()
    set_key(run, KEY, "active", None)
    code2 = watch.main(["--run", str(run), "--image", ref, "--pod", "standin-app-2", "--key", KEY,
                        "--container-id", "containerd://ph2-05-after"])
    after = json.loads((run / "bindings.json").read_text())["containerd://ph2-05-after"]
    ok = code == 2 and b["verified"] is False and b["reason"].startswith("key: ") and after["verified"] is True
    record_result("PH2-05", "pass" if ok else "fail", metrics={"exit": code, "verified": b["verified"],
                                                                "after_reactivation": after["verified"], "exit_after": code2},
                  notes=f"our key marked revoked in keystatus.json: binding verified {b['verified']}, reason: "
                        f"{b['reason']}; marked active again, the next admission verifies")
    assert ok


def test_ph2_08_a_moved_tag_cannot_redirect_evidence(tmp_path, ref, record_result):
    run = run_folder(tmp_path, ref, "moved-tag")
    repo, digest = ref.split("@")
    tag = f"{repo}:ph2-08-moved-{uuid.uuid4().hex[:8]}"
    refs = []
    verifier = watch.Verifier(KEY, offline=offline(), run=run)
    real_verify = verifier.verify
    verifier.verify = lambda r: refs.append(r) or real_verify(r)            # noqa: E731
    pod = {"metadata": {"namespace": "demo", "name": "standin-app-1"},
           "spec": {"containers": [{"name": "app"}]},
           "status": {"container_statuses": [{"name": "app", "container_id": "containerd://ph2-08",
                                              "image": tag, "image_id": ref}]}}
    watch.Controller(run, KEY, verifier=verifier).handle_pod("ADDED", pod)
    b = json.loads((run / "bindings.json").read_text())["containerd://ph2-08"]
    ctx = json.loads((run / "contexts" / f"{digest.split(':')[1]}.json").read_text())
    ok = b["image_digest"] == digest and b["verified"] is True and ctx["digest"] == digest and refs == [ref]
    record_result("PH2-08", "pass" if ok else "fail", metrics={"verified": b["verified"], "refs_verified": refs},
                  notes=f"pod status image {tag} (no such tag: it moved), imageID {ref}: bound to {digest[:19]}..., "
                        f"verified {b['verified']}; the controller verified only the digest reference, never the tag")
    assert ok
