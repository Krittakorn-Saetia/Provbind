"""controller/watch.py: fail-closed verification, bindings from the pod spec, contexts (PH2-01, 02, 09)."""
import json
import sys

import pytest

from compiler.evidence import Cosign
from compiler.tests.helpers import FakeCosign
from compiler.tests.test_compile import PROVENANCE, SBOM
from controller import watch
from controller.watch import Controller, Verifier, digest_ref, main, mounts_of, security

from tests.alerts.helpers import ROOT

KEY = str(ROOT / "pipeline" / "keys" / "cosign.pub")
HEX = "ab" * 32
DIGEST = "sha256:" + HEX
REF = f"localhost:5001/demo-app@{DIGEST}"


def pod(**over):
    p = {"metadata": {"namespace": "demo", "name": "demo-app-7d9f"},
         "spec": {"security_context": {}, "containers": [
             {"name": "app", "security_context": {}, "volume_mounts": [{"mount_path": "/data/"}]}]},
         "status": {"container_statuses": [{"name": "app", "container_id": "containerd://c1",
                                            "image": "localhost:5001/demo-app:latest",
                                            "image_id": f"localhost:5001/demo-app@{DIGEST}"}]}}
    p.update(over)
    return p


def controller(tmp_path, cosign=None, compile_ok=True):
    calls = []

    def compile_fn(ref):
        calls.append(ref)
        if compile_ok:
            (tmp_path / "run" / "envelopes" / f"{HEX}.json").write_text("{}")
        return compile_ok
    ctl = Controller(tmp_path / "run", KEY, verifier=Verifier(KEY, cosign=cosign or FakeCosign(DIGEST, SBOM, PROVENANCE)),
                     compile_fn=compile_fn)
    return ctl, calls


def bindings(tmp_path):
    return json.loads((tmp_path / "run" / "bindings.json").read_text())


@pytest.mark.parametrize("image,image_id,expected", [
    ("localhost:5001/demo-app:latest", f"localhost:5001/demo-app@{DIGEST}", REF),
    ("localhost:5001/demo-app:latest", f"docker-pullable://localhost:5001/demo-app@{DIGEST}", REF),
    ("localhost:5001/demo-app:v2", DIGEST, REF),                              # runtime reports only the digest
    (REF, "", REF),
    ("localhost:5001/demo-app:latest", "", None),                             # a tag alone is never trusted
])
def test_the_running_digest_not_the_tag(image, image_id, expected):          # PH2-08
    assert digest_ref(image, image_id) == expected


def test_a_signed_image_is_verified_and_its_context_stored(tmp_path):       # PH2-01, PH2-09
    ctl, calls = controller(tmp_path)
    b = ctl.bind("containerd://c1", "demo", "p", "app", REF)
    assert b["verified"] is True and b["envelope_ready"] is True and calls == [REF]
    ctx = json.loads((tmp_path / "run" / "contexts" / f"{HEX}.json").read_text())
    assert ctx["verified"] and ctx["checks"] == {"v_sig": True, "v_B": True, "v_P": True}
    assert ctx["key"]["key_id"].startswith("sha256:") and ctx["t0"] and ctx["rekor_log_index"] == 123456789


def test_an_attested_but_unsigned_image_is_not_verified(tmp_path):          # PH2-02
    ctl, calls = controller(tmp_path, cosign=FakeCosign(DIGEST, SBOM, PROVENANCE, signed=False))
    b = ctl.bind("containerd://c1", "demo", "p", "app", REF)
    assert b["verified"] is False and "v_sig" in b["reason"] and calls == []    # nothing compiled for it


def test_a_bad_signature_is_not_verified(tmp_path):                         # PH2-03
    ctl, _ = controller(tmp_path, cosign=FakeCosign(DIGEST, SBOM, PROVENANCE, fail="v_sig: no matching signatures"))
    assert ctl.bind("containerd://c1", "demo", "p", "app", REF)["verified"] is False


def test_a_missing_cosign_fails_closed(tmp_path):
    ctl, _ = controller(tmp_path, cosign=Cosign(KEY, binary="no-such-cosign-binary"))
    b = ctl.bind("containerd://c1", "demo", "p", "app", REF)
    assert b["verified"] is False and "not found" in b["reason"]


def test_an_unreadable_key_fails_closed(tmp_path):
    v = Verifier(str(tmp_path / "missing.pub"), cosign=FakeCosign(DIGEST, SBOM, PROVENANCE))
    assert v.verify(REF)["verified"] is False


def test_envelope_ready_only_when_the_file_exists(tmp_path):
    ctl, _ = controller(tmp_path, compile_ok=False)
    assert ctl.bind("containerd://c1", "demo", "p", "app", REF)["envelope_ready"] is False


def test_bindings_come_from_the_pod_spec(tmp_path):
    ctl, _ = controller(tmp_path)
    p = pod()
    p["spec"]["security_context"] = {"run_as_user": 1000}
    p["spec"]["containers"][0]["security_context"] = {"privileged": True}
    ctl.handle_pod("ADDED", p)
    b = bindings(tmp_path)["containerd://c1"]
    assert (b["run_as_root"], b["privileged"]) == (False, True)
    assert "/data" in b["mounts"] and "/etc/resolv.conf" in b["mounts"]
    assert (b["namespace"], b["pod"], b["container"], b["image_digest"]) == ("demo", "demo-app-7d9f", "app", DIGEST)


@pytest.mark.parametrize("csc,psc,expected", [
    ({}, {}, (True, False)), ({"run_as_user": 0}, {"run_as_user": 1000}, (True, False)),
    ({}, {"run_as_non_root": True}, (False, False)), ({"privileged": True}, {}, (True, True)),
])
def test_security(csc, psc, expected):
    p = {"spec": {"security_context": psc}}
    assert security(p, {"security_context": csc}) == expected


def test_mounts_always_include_what_kubernetes_manages():
    assert set(watch.K8S_MANAGED) <= set(mounts_of({}))


def test_a_restarted_container_replaces_its_old_id_and_deleted_pods_go(tmp_path):
    ctl, _ = controller(tmp_path)
    ctl.handle_pod("ADDED", pod())
    restarted = pod()
    restarted["status"]["container_statuses"][0]["container_id"] = "containerd://c2"
    ctl.handle_pod("MODIFIED", restarted)
    assert list(bindings(tmp_path)) == ["containerd://c2"]
    ctl.handle_pod("DELETED", restarted)
    assert bindings(tmp_path) == {}


def test_a_container_not_started_yet_is_bound_later(tmp_path):
    ctl, _ = controller(tmp_path)
    p = pod()
    p["status"]["container_statuses"][0]["container_id"] = None
    ctl.handle_pod("ADDED", p)
    assert not (tmp_path / "run" / "bindings.json").exists() or bindings(tmp_path) == {}


def test_verification_runs_once_per_digest(tmp_path):
    fake = FakeCosign(DIGEST, SBOM, PROVENANCE)
    ctl, _ = controller(tmp_path, cosign=fake)
    ctl.handle_pod("ADDED", pod())
    ctl.handle_pod("MODIFIED", pod())
    assert fake.refs.count(REF) == 4           # verify + two verify-attestation + download, once


def test_no_kubernetes_client_exits_3_and_invents_nothing(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "kubernetes", None)
    ctl, _ = controller(tmp_path)
    assert ctl.watch("demo") == 3
    assert not (tmp_path / "run" / "bindings.json").exists()


def test_image_mode_rejects_a_tag(tmp_path):
    assert main(["--run", str(tmp_path / "run"), "--image", "localhost:5001/demo-app:latest"]) == 3
