"""T4: fetch an image with crane (handoff T4).

The manifest, config and every layer blob are checked against their digests: v_M for the
manifest (and the platform manifest, for an index), v_C for the config, and each blob as
it lands in the content-addressed cache. crane subcommands only; no OCI-layout parsing.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Callable

from .layers import LayerBlob

log = logging.getLogger("provbind.oci")

INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
PLATFORM = ("linux", "amd64")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REF_BY_DIGEST = re.compile(r"^(?P<repo>[^@\s]+)@(?P<digest>sha256:[0-9a-f]{64})$")
MAX_INDEX_DEPTH = 3
TIMEOUT_S = 600
CHUNK = 1 << 20


class BadInput(Exception):
    """Exit 3: not a reference by digest, registry unreachable, image missing, or not
    linux/amd64."""


class IntegrityError(Exception):
    """Exit 2: a manifest, config or blob does not hash to its digest (v_M, v_C)."""


class Crane:
    """Runs the crane commands T4 needs. Tests pass a fake `run`."""

    def __init__(self, binary: str = "crane", run: Callable[..., subprocess.CompletedProcess] = subprocess.run):
        self.binary, self._run = binary, run

    def _crane(self, args: list[str], stdout) -> subprocess.CompletedProcess:
        cmd = [self.binary, *args]
        try:
            out = self._run(cmd, stdout=stdout, stderr=subprocess.PIPE, timeout=TIMEOUT_S)
        except FileNotFoundError:
            raise RuntimeError(f"{self.binary} not found on PATH") from None
        except subprocess.TimeoutExpired:
            raise BadInput(f"crane {' '.join(args)} timed out; is the registry reachable?") from None
        if out.returncode != 0:
            lines = (out.stderr or b"").decode(errors="replace").strip().splitlines()
            raise BadInput(f"crane {' '.join(args)} failed: {lines[-1] if lines else 'no error message'}")
        return out

    def manifest(self, ref: str) -> bytes:
        """The raw manifest bytes, exactly as the registry stores them."""
        return self._crane(["manifest", ref], subprocess.PIPE).stdout

    def blob(self, ref: str, dest: str) -> None:
        with open(dest, "wb") as f:
            self._crane(["blob", ref], f)


@dataclass
class ImageConfig:
    entrypoint: list[str]
    cmd: list[str]
    env: list[str]
    exposed_ports: dict
    user: str
    working_dir: str
    os: str | None
    architecture: str | None


@dataclass
class Image:
    ref: str                        # as given; written to the envelope unchanged
    digest: str                     # the reference's digest: an index or a manifest
    manifest_digest: str            # the image manifest actually used
    layers: list[LayerBlob]
    config: ImageConfig
    verification: dict = field(default_factory=lambda: {"v_M": True, "v_C": True})


def parse_ref(ref: str) -> tuple[str, str]:
    """(repository, digest) of a reference by digest, dropping a tag if there is one."""
    m = REF_BY_DIGEST.match(ref.strip())
    if not m:
        raise BadInput(f"not a reference by digest (<repo>@sha256:<64 hex>): {ref}")
    repo = m["repo"]
    if ":" in repo.rsplit("/", 1)[-1]:              # repo:tag@sha256:... -> repo
        repo = repo[:repo.rfind(":")]
    return repo, m["digest"]


def with_registry(repo: str, registry: str | None) -> str:
    """`repo` with its registry host replaced by `registry` (--registry-name, decision D4)."""
    if not registry:
        return repo
    first, _, rest = repo.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        return f"{registry}/{rest}"
    return f"{registry}/{repo}"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _check(data: bytes, digest: str, what: str) -> None:
    got = "sha256:" + hashlib.sha256(data).hexdigest()
    if got != digest:
        raise IntegrityError(f"{what}: content hashes to {got}, not {digest}")


def _json(raw: bytes, what: str) -> dict:
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise BadInput(f"{what} is not JSON: {e}") from None
    if not isinstance(doc, dict):
        raise BadInput(f"{what} is not a JSON object")
    return doc


def is_index(doc: dict) -> bool:
    media_type = doc.get("mediaType")
    if media_type:
        return media_type in INDEX_TYPES
    return "manifests" in doc and "layers" not in doc   # older manifests omit mediaType


def select_platform(index: dict) -> str:
    """The digest of the linux/amd64 entry, skipping buildx attestation manifests."""
    for entry in index.get("manifests") or ():
        if (entry.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest":
            continue
        platform = entry.get("platform") or {}
        if (platform.get("os"), platform.get("architecture")) == PLATFORM and DIGEST.match(entry.get("digest") or ""):
            return entry["digest"]
    raise BadInput("the image index has no linux/amd64 image")


def parse_config(doc: dict) -> ImageConfig:
    c = doc.get("config") or {}
    return ImageConfig(entrypoint=list(c.get("Entrypoint") or ()), cmd=list(c.get("Cmd") or ()),
                       env=list(c.get("Env") or ()), exposed_ports=dict(c.get("ExposedPorts") or {}),
                       user=c.get("User") or "", working_dir=c.get("WorkingDir") or "",
                       os=doc.get("os"), architecture=doc.get("architecture"))


def cached_blob(crane: Crane, repo: str, digest: str, cache_dir: str, what: str) -> str:
    """Path of the blob in the cache: reused if its hash matches, else downloaded to a temp
    file, verified, and renamed into place."""
    hex_digest = digest.split(":", 1)[1]
    os.makedirs(cache_dir, exist_ok=True)
    path = os.path.join(cache_dir, hex_digest)
    if os.path.exists(path):
        if sha256_file(path) == hex_digest:
            return path
        log.warning("cached blob %s does not match its digest; downloading it again", hex_digest[:12])
    fd, tmp = tempfile.mkstemp(dir=cache_dir, prefix=f".{hex_digest[:12]}.", suffix=".tmp")
    os.close(fd)
    try:
        crane.blob(f"{repo}@{digest}", tmp)
        got = sha256_file(tmp)
        if got != hex_digest:
            raise IntegrityError(f"{what} {digest}: downloaded content hashes to sha256:{got}")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return path


def preflight(ref: str, crane: Crane, registry_name: str | None = None) -> bytes:
    """Fetch the manifest and nothing else (decision D3): BadInput, so exit 3, if the
    registry cannot serve it. The bytes can be passed on to fetch()."""
    repo, digest = parse_ref(ref)
    return crane.manifest(f"{with_registry(repo, registry_name)}@{digest}")


def fetch(ref: str, cache_dir: str, crane: Crane, registry_name: str | None = None,
          raw_manifest: bytes | None = None) -> Image:
    """Manifest (v_M), platform manifest for an index (v_M), config (v_C), and layers in
    manifest order, each verified into the blob cache."""
    repo, digest = parse_ref(ref)
    src = with_registry(repo, registry_name)
    raw = crane.manifest(f"{src}@{digest}") if raw_manifest is None else raw_manifest
    _check(raw, digest, "v_M: manifest")
    manifest_digest, doc = digest, _json(raw, "manifest")
    for _ in range(MAX_INDEX_DEPTH):
        if not is_index(doc):
            break
        child = select_platform(doc)
        raw = crane.manifest(f"{src}@{child}")
        _check(raw, child, "v_M: platform manifest")
        manifest_digest, doc = child, _json(raw, "platform manifest")
    if is_index(doc):
        raise BadInput(f"image indexes nested deeper than {MAX_INDEX_DEPTH}")

    config_digest = (doc.get("config") or {}).get("digest") or ""
    if not DIGEST.match(config_digest):
        raise BadInput(f"manifest {manifest_digest} has no sha256 config digest")
    config_path = cached_blob(crane, src, config_digest, cache_dir, "v_C: config")
    with open(config_path, "rb") as f:
        config_raw = f.read()
    _check(config_raw, config_digest, "v_C: config")
    config = parse_config(_json(config_raw, "config"))
    if (config.os, config.architecture) != PLATFORM:
        raise BadInput(f"image is {config.os}/{config.architecture}; the demo needs linux/amd64")

    layers = []
    for i, desc in enumerate(doc.get("layers") or ()):
        layer_digest = desc.get("digest") or ""
        if not DIGEST.match(layer_digest):
            raise BadInput(f"layer {i} has no sha256 digest")
        path = cached_blob(crane, src, layer_digest, cache_dir, f"layer {i}")
        layers.append(LayerBlob(i, layer_digest, desc.get("mediaType"), path))
    if not layers:
        raise BadInput(f"manifest {manifest_digest} has no layers")
    return Image(ref, digest, manifest_digest, layers, config)
