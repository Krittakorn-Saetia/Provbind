"""Fixtures built in code: small layer tars, compressed blobs and minimal ELF files."""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import struct
import tarfile

import zstandard

from compiler.evidence import CYCLONEDX, SLSA_V1, EvidenceError
from compiler.layers import FileEntry, LayerBlob
from compiler.oci import BadInput, ImageConfig

MEDIA_TYPES = {
    "gzip": "application/vnd.oci.image.layer.v1.tar+gzip",
    "zstd": "application/vnd.oci.image.layer.v1.tar+zstd",
    "tar": "application/vnd.oci.image.layer.v1.tar",
}
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_LAYER = "application/vnd.docker.image.rootfs.diff.tar.gzip"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_of(data: bytes) -> str:
    return "sha256:" + sha(data)


class Tar:
    """A layer tar built in memory; entries keep the order of the calls."""

    def __init__(self):
        self._buf = io.BytesIO()
        self._tf = tarfile.open(fileobj=self._buf, mode="w", format=tarfile.PAX_FORMAT)

    def _add(self, name, kind, mode, data=b"", linkname=""):
        ti = tarfile.TarInfo(name)
        ti.type, ti.mode, ti.linkname, ti.size, ti.mtime = kind, mode, linkname, len(data), 0
        self._tf.addfile(ti, io.BytesIO(data) if data else None)
        return self

    def file(self, name, data=b"", mode=0o644):
        return self._add(name, tarfile.REGTYPE, mode, data)

    def dir(self, name, mode=0o755):
        return self._add(name, tarfile.DIRTYPE, mode)

    def symlink(self, name, target):
        return self._add(name, tarfile.SYMTYPE, 0o777, linkname=target)

    def hardlink(self, name, target):
        return self._add(name, tarfile.LNKTYPE, 0o644, linkname=target)

    def whiteout(self, name):
        return self.file(name)

    def fifo(self, name):
        return self._add(name, tarfile.FIFOTYPE, 0o644)

    def extend(self, other: "Tar") -> "Tar":
        """Append another Tar's entries, in order (e.g. two pip installs in one layer)."""
        with tarfile.open(fileobj=io.BytesIO(other.bytes())) as tf:
            for m in tf:
                self._tf.addfile(m, tf.extractfile(m) if m.isfile() else None)
        return self

    def bytes(self) -> bytes:
        self._tf.close()
        return self._buf.getvalue()


def compress(data: bytes, kind: str) -> bytes:
    if kind == "gzip":
        return gzip.compress(data, mtime=0)
    if kind == "zstd":
        return zstandard.ZstdCompressor().compress(data)
    return data


def make_layer(directory, index: int, tar, kind: str = "gzip", media_type: str | None = "") -> LayerBlob:
    """Write one layer blob. media_type "" means the usual OCI type for `kind`."""
    raw = compress(tar if isinstance(tar, bytes) else tar.bytes(), kind)
    path = directory / f"layer-{index}-{kind}-{sha(raw)[:12]}"
    path.write_bytes(raw)
    return LayerBlob(index, "sha256:" + sha(raw), MEDIA_TYPES[kind] if media_type == "" else media_type,
                     str(path))


def image_config(os_="linux", arch="amd64", **config) -> dict:
    """An image config document; keyword arguments go into its `config` object."""
    body = {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "Cmd": ["python", "app.py"], "WorkingDir": "/app"}
    body.update(config)
    return {"architecture": arch, "os": os_, "config": body, "rootfs": {"type": "layers", "diff_ids": []}}


class FakeRegistry:
    """Manifests and blobs by digest, served through crane's interface (manifest, blob)."""

    def __init__(self):
        self.manifests: dict[str, bytes] = {}
        self.blobs: dict[str, bytes] = {}
        self.calls: list[tuple[str, str]] = []

    def push_image(self, layer_tars, config: dict | None = None, kind: str = "gzip", docker: bool = False) -> str:
        cfg = json.dumps(config or image_config()).encode()
        self.blobs[digest_of(cfg)] = cfg
        layers = []
        for t in layer_tars:
            raw = compress(t if isinstance(t, bytes) else t.bytes(), kind)
            self.blobs[digest_of(raw)] = raw
            layers.append({"mediaType": DOCKER_LAYER if docker else MEDIA_TYPES[kind],
                           "digest": digest_of(raw), "size": len(raw)})
        return self.push_manifest({
            "schemaVersion": 2, "mediaType": DOCKER_MANIFEST if docker else OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": digest_of(cfg), "size": len(cfg)},
            "layers": layers})

    def push_manifest(self, doc: dict) -> str:
        raw = json.dumps(doc).encode()
        self.manifests[digest_of(raw)] = raw
        return digest_of(raw)

    def push_index(self, entries) -> str:
        """entries: (digest, platform or None, annotations or None)."""
        manifests = []
        for d, platform, notes in entries:
            m = {"mediaType": OCI_MANIFEST, "digest": d, "size": len(self.manifests.get(d, b""))}
            if platform:
                m["platform"] = platform
            if notes:
                m["annotations"] = notes
            manifests.append(m)
        return self.push_manifest({"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests})

    def manifest(self, ref: str) -> bytes:
        self.calls.append(("manifest", ref))
        d = ref.rsplit("@", 1)[1]
        if d not in self.manifests:
            raise BadInput(f"crane manifest {ref} failed: MANIFEST_UNKNOWN")
        return self.manifests[d]

    def blob(self, ref: str, dest: str) -> None:
        self.calls.append(("blob", ref))
        d = ref.rsplit("@", 1)[1]
        if d not in self.blobs:
            raise BadInput(f"crane blob {ref} failed: BLOB_UNKNOWN")
        with open(dest, "wb") as f:
            f.write(self.blobs[d])


class FakeCosign:
    """cosign's interface (verify, verify_attestation) serving DSSE envelopes bound to
    `digest`. `fail` makes verify raise, as a bad signature would."""

    def __init__(self, digest: str, sbom: dict, provenance: dict, log_index: int | None = 123456789,
                 fail: str | None = None):
        def envelope(predicate_type, predicate):
            stmt = {"_type": "https://in-toto.io/Statement/v1",
                    "subject": [{"name": "localhost:5001/x", "digest": {"sha256": digest.split(":")[1]}}],
                    "predicateType": predicate_type, "predicate": predicate}
            return json.dumps({"payloadType": "application/vnd.in-toto+json",
                               "payload": base64.b64encode(json.dumps(stmt).encode()).decode(),
                               "signatures": [{"keyid": "", "sig": "MEUC"}]}) + "\n"
        optional = {"Bundle": {"Payload": {"logIndex": log_index}}} if log_index is not None else None
        self.out = {"verify": json.dumps([{"critical": {"image": {"docker-manifest-digest": digest}},
                                           "optional": optional}]),
                    "cyclonedx": envelope(CYCLONEDX, sbom), "slsaprovenance1": envelope(SLSA_V1, provenance)}
        self.fail = fail
        self.refs: list[str] = []

    def verify(self, ref: str) -> str:
        self.refs.append(ref)
        if self.fail:
            raise EvidenceError(self.fail)
        return self.out["verify"]

    def verify_attestation(self, ref: str, predicate: str) -> str:
        self.refs.append(ref)
        return self.out[predicate]


class MemFS:
    """An image filesystem in memory, with the interface closure() uses on a Union."""

    def __init__(self, contents: dict[str, bytes], links: dict[str, str] | None = None,
                 modes: dict[str, str] | None = None):
        self.data = contents
        self.links = links or {}
        self.files = {p: FileEntry(sha(b), 0, (modes or {}).get(p, "0755"), len(b), 0, 0)
                      for p, b in contents.items()}

    def read(self, path, n=None):
        data = self.data.get(path)
        return None if data is None else (data if n is None else data[:n])

    def open(self, path):
        return io.BytesIO(self.data[path])


def config(entrypoint=(), cmd=(), env=(), working_dir="", exposed_ports=None) -> ImageConfig:
    return ImageConfig(list(entrypoint), list(cmd), list(env), exposed_ports or {}, "", working_dir,
                       "linux", "amd64")


EM_X86_64 = 62
EM_AARCH64 = 183


def make_elf(*, interp: str | None = None, needed=(), rpath: str | None = None,
             runpath: str | None = None, machine: int = EM_X86_64, imports=(), exports=()) -> bytes:
    """A minimal little-endian ELF64 with PT_LOAD, optional PT_INTERP and PT_DYNAMIC.

    Virtual addresses equal file offsets, so DT_STRTAB points straight at .dynstr.
    There are no section headers, like a stripped binary. `imports` become undefined
    dynamic symbols and `exports` defined ones, in a DT_SYMTAB with a DT_HASH table (which
    pyelftools uses to count them); with neither, the bytes are as before.
    """
    strtab = bytearray(b"\0")
    def add_str(s: str) -> int:
        off = len(strtab)
        strtab.extend(s.encode() + b"\0")
        return off
    dyn = [(1, add_str(n)) for n in needed]                       # DT_NEEDED
    if rpath is not None:
        dyn.append((15, add_str(rpath)))                          # DT_RPATH
    if runpath is not None:
        dyn.append((29, add_str(runpath)))                        # DT_RUNPATH
    symbols = [(add_str(n), 0) for n in imports] + [(add_str(n), 1) for n in exports]   # (name, st_shndx)

    phnum = 2 + (interp is not None)                              # LOAD, [INTERP], DYNAMIC
    data_off = 64 + 56 * phnum
    interp_bytes = interp.encode() + b"\0" if interp is not None else b""
    interp_off = data_off
    strtab_off = interp_off + len(interp_bytes)
    sym_off = (strtab_off + len(strtab) + 7) & ~7
    sym_bytes = hash_bytes = b""
    if symbols:
        sym_bytes = bytes(24) + b"".join(struct.pack("<IBBHQQ", name, 0x12, 0, shndx, 0, 0)  # GLOBAL FUNC
                                         for name, shndx in symbols)
        nsyms = len(symbols) + 1
        hash_bytes = struct.pack(f"<{3 + nsyms}I", 1, nsyms, *([0] * (1 + nsyms)))           # nbucket, nchain, ...
    hash_off = sym_off + len(sym_bytes)
    dyn_off = (hash_off + len(hash_bytes) + 7) & ~7
    if symbols:
        dyn += [(6, sym_off), (11, 24), (4, hash_off)]            # DT_SYMTAB, DT_SYMENT, DT_HASH
    dyn += [(5, strtab_off), (10, len(strtab)), (0, 0)]           # DT_STRTAB, DT_STRSZ, DT_NULL
    dyn_bytes = b"".join(struct.pack("<qQ", tag, val) for tag, val in dyn)
    total = dyn_off + len(dyn_bytes)

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)            # ELFCLASS64, LSB, v1
    header = ident + struct.pack("<HHIQQQIHHHHHH", 3, machine, 1, 0, 64, 0, 0, 64, 56, phnum, 64, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total, total, 0x1000)                      # PT_LOAD
    if interp is not None:
        ph += struct.pack("<IIQQQQQQ", 3, 4, interp_off, interp_off, interp_off,
                          len(interp_bytes), len(interp_bytes), 1)                           # PT_INTERP
    ph += struct.pack("<IIQQQQQQ", 2, 6, dyn_off, dyn_off, dyn_off,
                      len(dyn_bytes), len(dyn_bytes), 8)                                     # PT_DYNAMIC
    body = bytearray(header + ph)
    body += interp_bytes + strtab
    body += bytes(sym_off - len(body)) if symbols else b""
    body += sym_bytes + hash_bytes
    body += bytes(dyn_off - len(body))
    body += dyn_bytes
    assert len(body) == total
    return bytes(body)
