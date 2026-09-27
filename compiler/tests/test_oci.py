"""T4: image fetch against a fake registry (no crane, no network)."""
import json
import os
import subprocess

import pytest

from compiler.oci import (BadInput, Crane, IntegrityError, fetch, parse_ref, preflight, sha256_file,
                          with_registry)

from .helpers import DOCKER_LAYER, FakeRegistry, Tar, digest_of, image_config

REPO = "localhost:5001/standin-app"
AMD64 = {"os": "linux", "architecture": "amd64"}
ARM64 = {"os": "linux", "architecture": "arm64"}
ATTESTATION = {"vnd.docker.reference.type": "attestation-manifest"}


@pytest.fixture
def reg():
    return FakeRegistry()


@pytest.fixture
def cache(tmp_path):
    return str(tmp_path / "cache" / "blobs")


def four_layers():
    return [Tar().file("etc/os-release", b"debian"), Tar().file("usr/local/bin/python3.11", b"py", 0o755),
            Tar().file("app/requirements.txt", b"requests==2.32.3\n"), Tar().file("app/app.py", b"print()\n")]


# --- references ------------------------------------------------------------------------------

def test_parse_ref():
    d = "sha256:" + "ab" * 32
    assert parse_ref(f"{REPO}@{d}") == (REPO, d)
    assert parse_ref(f"{REPO}:latest@{d}") == (REPO, d)


@pytest.mark.parametrize("ref", [f"{REPO}:latest", f"{REPO}@sha256:{'AB' * 32}", f"{REPO}@sha256:abc", ""])
def test_reference_not_by_digest_is_bad_input(ref):
    with pytest.raises(BadInput):
        parse_ref(ref)


@pytest.mark.parametrize("repo,expected", [
    ("localhost:5001/standin-app", "kind-registry:5000/standin-app"),
    ("registry.example.com/team/app", "kind-registry:5000/team/app"),
    ("library/python", "kind-registry:5000/library/python"),
])
def test_registry_name_replaces_the_host(repo, expected):
    assert with_registry(repo, "kind-registry:5000") == expected
    assert with_registry(repo, None) == repo


# --- a single manifest -------------------------------------------------------------------------

def test_fetch_single_manifest(reg, cache):
    d = reg.push_image(four_layers(), image_config(ExposedPorts={"8080/tcp": {}}, User="app"))
    img = fetch(f"{REPO}@{d}", cache, reg)
    assert [(l.index, l.digest) for l in img.layers] == [(i, l["digest"]) for i, l in
                                                         enumerate(json.loads(reg.manifests[d])["layers"])]
    assert all(os.path.basename(l.path) == l.digest.split(":")[1] and sha256_file(l.path) == l.digest.split(":")[1]
               for l in img.layers)
    assert img.config.cmd == ["python", "app.py"]
    assert img.config.working_dir == "/app" and img.config.user == "app"
    assert img.config.exposed_ports == {"8080/tcp": {}}
    assert img.digest == img.manifest_digest == d
    assert img.verification == {"v_M": True, "v_C": True}


def test_docker_media_types(reg, cache):
    d = reg.push_image(four_layers(), docker=True)
    img = fetch(f"{REPO}@{d}", cache, reg)
    assert {l.media_type for l in img.layers} == {DOCKER_LAYER}


def test_preflight_bytes_are_reused(reg, cache):
    d = reg.push_image(four_layers())
    raw = preflight(f"{REPO}@{d}", reg)
    reg.calls.clear()
    fetch(f"{REPO}@{d}", cache, reg, raw_manifest=raw)
    assert not [c for c in reg.calls if c[0] == "manifest"]


# --- an image index ---------------------------------------------------------------------------

def test_index_selection_skips_attestation_manifests(reg, cache):
    amd = reg.push_image(four_layers())
    arm = reg.push_image([Tar().file("arm", b"arm")], image_config(arch="arm64"))
    fake_att = reg.push_image([Tar().file("att.json", b"{}")])
    idx = reg.push_index([(fake_att, AMD64, ATTESTATION), (arm, ARM64, None), (amd, AMD64, None)])
    img = fetch(f"{REPO}@{idx}", cache, reg)
    assert img.digest == idx and img.manifest_digest == amd
    assert len(img.layers) == 4


def test_index_without_amd64_is_bad_input(reg, cache):
    arm = reg.push_image([Tar().file("arm", b"arm")], image_config(arch="arm64"))
    idx = reg.push_index([(arm, ARM64, None)])
    with pytest.raises(BadInput, match="linux/amd64"):
        fetch(f"{REPO}@{idx}", cache, reg)


def test_manifest_list_without_media_type_is_detected(reg, cache):
    amd = reg.push_image(four_layers())
    idx = reg.push_manifest({"schemaVersion": 2, "manifests": [{"digest": amd, "platform": AMD64}]})
    assert fetch(f"{REPO}@{idx}", cache, reg).manifest_digest == amd


# --- digests (v_M, v_C, blobs) -------------------------------------------------------------------

def test_manifest_hash_mismatch_raises(reg, cache):
    d = reg.push_image(four_layers())
    reg.manifests[d] = reg.manifests[d] + b" "
    with pytest.raises(IntegrityError, match="v_M"):
        fetch(f"{REPO}@{d}", cache, reg)


def test_platform_manifest_hash_mismatch_raises(reg, cache):
    amd = reg.push_image(four_layers())
    idx = reg.push_index([(amd, AMD64, None)])
    reg.manifests[amd] = reg.manifests[amd].replace(b'"schemaVersion": 2', b'"schemaVersion":2')
    with pytest.raises(IntegrityError, match="v_M: platform manifest"):
        fetch(f"{REPO}@{idx}", cache, reg)


def test_config_hash_mismatch_raises(reg, cache):
    d = reg.push_image(four_layers())
    config_digest = json.loads(reg.manifests[d])["config"]["digest"]
    reg.blobs[config_digest] = json.dumps(image_config(Cmd=["sh"])).encode()
    with pytest.raises(IntegrityError, match="v_C"):
        fetch(f"{REPO}@{d}", cache, reg)


def test_layer_hash_mismatch_raises_and_leaves_nothing_in_the_cache(reg, cache):
    d = reg.push_image(four_layers())
    bad = json.loads(reg.manifests[d])["layers"][2]["digest"]
    reg.blobs[bad] = b"tampered"
    with pytest.raises(IntegrityError, match="layer 2"):
        fetch(f"{REPO}@{d}", cache, reg)
    assert bad.split(":")[1] not in os.listdir(cache)
    assert not [f for f in os.listdir(cache) if f.endswith(".tmp")]


# --- the blob cache -----------------------------------------------------------------------------

def test_cached_blobs_are_reused(reg, cache):
    d = reg.push_image(four_layers())
    fetch(f"{REPO}@{d}", cache, reg)
    reg.calls.clear()
    fetch(f"{REPO}@{d}", cache, reg)
    assert [c for c in reg.calls if c[0] == "blob"] == []


def test_corrupt_cached_blob_is_downloaded_again(reg, cache, caplog):
    d = reg.push_image(four_layers())
    img = fetch(f"{REPO}@{d}", cache, reg)
    with open(img.layers[1].path, "wb") as f:
        f.write(b"bit rot")
    reg.calls.clear()
    img = fetch(f"{REPO}@{d}", cache, reg)
    assert [c[1] for c in reg.calls if c[0] == "blob"] == [f"{REPO}@{img.layers[1].digest}"]
    assert sha256_file(img.layers[1].path) == img.layers[1].digest.split(":")[1]
    assert "downloading it again" in caplog.text


# --- inputs the demo cannot use ------------------------------------------------------------------

def test_non_amd64_single_manifest_is_bad_input(reg, cache):
    d = reg.push_image(four_layers(), image_config(arch="arm64"))
    with pytest.raises(BadInput, match="linux/arm64"):
        fetch(f"{REPO}@{d}", cache, reg)


def test_image_without_layers_is_bad_input(reg, cache):
    d = reg.push_image([])
    with pytest.raises(BadInput, match="no layers"):
        fetch(f"{REPO}@{d}", cache, reg)


def test_missing_image_is_bad_input(reg, cache):
    with pytest.raises(BadInput, match="MANIFEST_UNKNOWN"):
        preflight(f"{REPO}@sha256:{'cd' * 32}", reg)


def test_registry_name_is_used_for_every_call(reg, cache):
    d = reg.push_image(four_layers())
    img = fetch(f"{REPO}@{d}", cache, reg, registry_name="192.168.1.20:5001")
    assert all(ref.startswith("192.168.1.20:5001/standin-app@") for _, ref in reg.calls)
    assert img.ref == f"{REPO}@{d}"


# --- the real Crane wrapper, with a fake subprocess.run -----------------------------------------------

def test_crane_commands_and_blob_to_file(tmp_path):
    calls = []

    def run(cmd, stdout=None, stderr=None, timeout=None):
        calls.append(cmd)
        if cmd[1] == "blob":
            stdout.write(b"blob-bytes")
            return subprocess.CompletedProcess(cmd, 0, None, b"")
        return subprocess.CompletedProcess(cmd, 0, b'{"schemaVersion":2}', b"")

    crane = Crane(run=run)
    assert crane.manifest("r@sha256:x") == b'{"schemaVersion":2}'
    crane.blob("r@sha256:y", str(tmp_path / "b"))
    assert (tmp_path / "b").read_bytes() == b"blob-bytes"
    assert calls == [["crane", "manifest", "r@sha256:x"], ["crane", "blob", "r@sha256:y"]]


def test_crane_failure_is_bad_input():
    def run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, b"", b"Error: GET http://localhost:5001/v2/: dial tcp: connection refused\n")
    with pytest.raises(BadInput, match="connection refused"):
        Crane(run=run).manifest("localhost:5001/x@sha256:" + "ab" * 32)


def test_crane_timeout_is_bad_input():
    def run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])
    with pytest.raises(BadInput, match="timed out"):
        Crane(run=run).manifest("r@sha256:x")


def test_missing_crane_binary_is_not_bad_input():
    def run(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])
    with pytest.raises(RuntimeError, match="not found on PATH"):
        Crane(run=run).manifest("r@sha256:x")


def test_digest_helper():
    assert digest_of(b"") == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
