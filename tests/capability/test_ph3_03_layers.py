"""PH3-03: layer attribution Λ_I (Eq. 26) (Test Plan §3.3). Compare the envelope's `layer` for 5 known
files with a manual inspection of the image's layers. Pass: all 5 match.

The inspection doesn't use the compiler's code. It fetches the manifest and every layer blob with
crane, checks each blob's sha256 against the manifest, and lists each layer tar's members. A file's
layer is the last one whose tar holds it, and a whiteout for it (or an opaque marker above it) in a
later layer means the file is gone.

Files: the stand-in's five, one from each kind of layer (Debian base, Python, the copied
requirements, the pip install, the app), when the envelope has them. Otherwise it fills up to five
with the first file of each layer not yet covered, so another image works too. The envelope is
PROVBIND_ENVELOPE, and the image is its image.ref. An integration test: it needs crane and the
registry, and skips without an envelope.
"""
import hashlib
import json
import os
import posixpath
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
import zstandard

pytestmark = pytest.mark.integration

KNOWN = ("/usr/bin/ls", "/usr/local/bin/python3.11", "/app/requirements.txt",
         "/usr/local/lib/python3.11/site-packages/requests/__init__.py", "/app/app.py")
WANT = 5
PLATFORM = ("linux", "amd64")
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def choose(files: dict) -> list[str]:
    """Up to five files: the known ones the envelope has, then one from each layer not yet covered."""
    chosen = [p for p in KNOWN if p in files]
    covered = {files[p]["layer"] for p in chosen}
    for p in sorted(files):
        if len(chosen) >= WANT:
            break
        if files[p]["layer"] not in covered:
            chosen.append(p)
            covered.add(files[p]["layer"])
    return chosen[:WANT]


def crane(*args: str, stdout=subprocess.PIPE) -> subprocess.CompletedProcess:
    return subprocess.run(["crane", *args], stdout=stdout, stderr=subprocess.PIPE, timeout=600, check=True)


def layer_digests(ref: str) -> list[str]:
    """The layer digests of the image's linux/amd64 manifest, in order."""
    repo, digest = ref.rsplit("@", 1)
    doc = json.loads(crane("manifest", ref).stdout)
    if "manifests" in doc and "layers" not in doc:                      # an image index
        entry = next(m for m in doc["manifests"]
                     if ((m.get("platform") or {}).get("os"), (m.get("platform") or {}).get("architecture")) == PLATFORM)
        doc = json.loads(crane("manifest", f"{repo}@{entry['digest']}").stdout)
    return [layer["digest"] for layer in doc["layers"]]


def members(path: Path) -> tuple[set[str], set[str], set[str]]:
    """(paths, whited-out paths, opaque directories) in one layer tar, as absolute paths."""
    paths, gone, opaque = set(), set(), set()
    with open(path, "rb") as f:
        zstd = f.read(4) == ZSTD_MAGIC
    with open(path, "rb") as raw:
        if zstd:
            stream = zstandard.ZstdDecompressor().stream_reader(raw, read_across_frames=True)
            tf = tarfile.open(fileobj=stream, mode="r|")
        else:
            tf = tarfile.open(fileobj=raw, mode="r|*")                  # gzip or plain tar
        with tf:
            for m in tf:
                name = posixpath.normpath("/" + m.name)
                d, base = posixpath.split(name)
                if base == ".wh..wh..opq":
                    opaque.add(d)
                elif base.startswith(".wh."):
                    gone.add(posixpath.join(d, base[len(".wh."):]))
                else:
                    paths.add(name)
    return paths, gone, opaque


def hidden_by(path: str, gone: set[str], opaque: set[str]) -> bool:
    if path in gone:
        return True
    parent = posixpath.dirname(path)
    while True:
        if parent in gone or parent in opaque:
            return True
        if parent == "/":
            return False
        parent = posixpath.dirname(parent)


def inspect(ref: str, workdir: Path) -> list[tuple[set, set, set]]:
    """Every layer of the image, fetched and hash-checked: (paths, whiteouts, opaque dirs) per layer."""
    repo = ref.rsplit("@", 1)[0]
    layers = []
    for i, digest in enumerate(layer_digests(ref)):
        blob = workdir / f"layer{i}"
        with open(blob, "wb") as f:
            crane("blob", f"{repo}@{digest}", stdout=f)
        got = "sha256:" + hashlib.sha256(blob.read_bytes()).hexdigest()
        assert got == digest, f"layer {i}: blob hashes to {got}, not {digest}"
        layers.append(members(blob))
        blob.unlink()
    return layers


def layer_of(path: str, layers: list[tuple[set, set, set]]) -> int | None:
    """The last layer that holds `path`, or None if no layer does or a later layer removes it."""
    found = None
    for i, (paths, gone, opaque) in enumerate(layers):
        if found is not None and hidden_by(path, gone, opaque):
            found = None
        if path in paths:
            found = i
    return found


def test_ph3_03_layer_attribution(tmp_path, record_result):
    path = os.environ.get("PROVBIND_ENVELOPE")
    if not path:
        pytest.skip("export PROVBIND_ENVELOPE=run/envelopes/<hex>.json (the stand-in's)")
    if shutil.which("crane") is None:
        pytest.skip("crane is not on PATH")
    env = json.loads(Path(path).read_text(encoding="utf-8"))
    ref, files = env["image"]["ref"], env["files"]
    chosen = choose(files)
    layers = inspect(ref, tmp_path)
    per_file = {p: {"envelope": files[p]["layer"], "inspection": layer_of(p, layers)} for p in chosen}
    wrong = [p for p, v in per_file.items() if v["envelope"] != v["inspection"]]
    same_layers = [entry["digest"] for entry in env["layers"]] == layer_digests(ref)
    ok = len(chosen) == WANT and not wrong and same_layers
    notes = (f"envelope {path} ({ref}): " + "; ".join(f"{p} layer {v['envelope']} (inspection {v['inspection']})"
                                                     for p, v in per_file.items()))
    if len(chosen) < WANT:
        notes += f"; only {len(chosen)} files to check"
    if wrong:
        notes += "; mismatches: " + ", ".join(wrong)
    if not same_layers:
        notes += "; the envelope's layer list differs from the image manifest's"
    record_result("PH3-03", "pass" if ok else "fail",
                  metrics={"files_checked": len(chosen), "matches": len(chosen) - len(wrong), "layers": len(layers),
                           "same_layers_as_manifest": same_layers, "per_file": per_file},
                  notes=notes, artifacts=[path])
    assert ok, notes
