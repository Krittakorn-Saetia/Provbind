"""T3: verified evidence and the binding checks (handoff T3; paper Eqs. 10-18).

The compiler reads only what cosign has verified against our public key: the image
signature (v_sig) and two attestations, each bound to the image digest (v_B for the
CycloneDX SBOM, v_P for the SLSA v1 provenance). The debug copies under run/attest/ are
never read. cosign v2 and v3 print different layouts (handoff Section 5, fact 2), so the
output is read defensively.

cosign v3 differs from v2 in two ways that matter here (branch local/rekor-bug has the note):
`cosign verify` also returns the attestation bundles as verified "signatures", so exit 0
alone doesn't mean the image was signed; and its output no longer carries the Rekor entry,
which is read from the signature bundle instead.
"""
from __future__ import annotations

import base64
import binascii
import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterator

log = logging.getLogger("provbind.evidence")

CYCLONEDX = "https://cyclonedx.org/bom"
SLSA_V1 = "https://slsa.dev/provenance/v1"
SIGN_V1 = "https://sigstore.dev/cosign/sign/v1"          # cosign v3's image signature statement
IMAGE_SIGNATURE_TYPES = (SIGN_V1, "cosign container image signature")    # v3; v2's simple signing
GIT_COMMIT = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")         # SHA-1 or SHA-256
BUILDER_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")     # the schema's builder_id pattern
TIMEOUT_S = 300


class EvidenceError(Exception):
    """v_sig, v_B or v_P failed. The CLI exits 2 and writes nothing."""


class Cosign:
    """Runs the cosign commands T3 needs. Tests pass a fake `run`."""

    def __init__(self, key: str, offline: bool = False, binary: str = "cosign",
                 run: Callable[..., subprocess.CompletedProcess] = subprocess.run):
        self.key, self.binary, self._run, self.offline = key, binary, run, offline
        self.flags = ["--insecure-ignore-tlog=true"] if offline else []

    def _exec(self, cmd: list[str]) -> subprocess.CompletedProcess:
        try:
            return self._run(cmd, capture_output=True, text=True, timeout=TIMEOUT_S)
        except FileNotFoundError:
            raise RuntimeError(f"{self.binary} not found on PATH") from None

    def _cosign(self, check: str, command: str, *args: str) -> str:
        try:
            out = self._exec([self.binary, command, "--key", self.key, *self.flags, *args])
        except subprocess.TimeoutExpired:
            raise EvidenceError(f"{check}: cosign {command} timed out after {TIMEOUT_S} s") from None
        if out.returncode != 0:
            raise EvidenceError(f"{check}: cosign {' '.join([command, *args[:-1]])} failed: {_reason(out.stderr)}")
        return out.stdout

    def verify(self, ref: str) -> str:
        return self._cosign("v_sig", "verify", ref)

    def verify_attestation(self, ref: str, predicate: str) -> str:
        check = "v_B" if predicate == "cyclonedx" else "v_P"
        return self._cosign(check, "verify-attestation", "--type", predicate, ref)

    def download_signature(self, ref: str) -> str:
        """The signature bundles attached to `ref`, as `cosign download signature` prints them
        (not a verification: see signature_log_index). Offline there is no Rekor entry to
        read, so nothing runs. A failure gives "" and a warning, never an EvidenceError."""
        if self.offline:
            return ""
        try:
            out = self._exec([self.binary, "download", "signature", ref])
        except subprocess.TimeoutExpired:
            log.warning("cosign download signature timed out after %d s", TIMEOUT_S)
            return ""
        if out.returncode != 0:
            log.warning("cosign download signature failed: %s", _reason(out.stderr))
            return ""
        return out.stdout


def _reason(stderr: str) -> str:
    lines = [ln.strip() for ln in (stderr or "").splitlines() if ln.strip()]
    for ln in lines:
        if ln.startswith("Error:"):
            return ln[len("Error:"):].strip()
    return lines[-1] if lines else "no error message"


@dataclass
class Evidence:
    digest: str                         # sha256:<hex>, the digest everything is bound to
    sbom: dict                          # the CycloneDX BOM: the SBOM statement's predicate
    provenance: dict                    # the SLSA v1 predicate
    builder_id: str
    source_commit: str | None
    rekor_log_index: int | None
    verification: dict = field(default_factory=lambda: {"v_sig": True, "v_B": True, "v_P": True})


def json_values(text: str) -> Iterator[Any]:
    """The JSON values cosign printed: one document, or one per line. Top-level lists are
    flattened. Lines that are not JSON are logged and skipped."""
    text = (text or "").strip()
    if not text:
        return
    try:
        values = [json.loads(text)]
    except json.JSONDecodeError:
        values = []
        for line in text.splitlines():
            if line.strip():
                try:
                    values.append(json.loads(line))
                except json.JSONDecodeError:
                    log.warning("cosign printed a line that is not JSON; ignored: %.80s", line)
    for v in values:
        yield from (v if isinstance(v, list) else [v])


def _b64decode(s: str) -> bytes:
    s = s.strip() + "=" * (-len(s.strip()) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except binascii.Error:
        return base64.urlsafe_b64decode(s)


def statement(obj: Any) -> dict | None:
    """The in-toto statement in one value of verify-attestation output: a DSSE envelope
    (base64 `payload`), a Sigstore bundle holding one (`dsseEnvelope`), or the statement."""
    if not isinstance(obj, dict):
        return None
    if isinstance(obj.get("dsseEnvelope"), dict):
        return statement(obj["dsseEnvelope"])
    if "payload" in obj:
        try:
            stmt = json.loads(_b64decode(obj["payload"]))
        except (ValueError, TypeError, AttributeError) as e:
            log.warning("attestation payload is not base64 JSON; ignored (%s)", e)
            return None
        return stmt if isinstance(stmt, dict) else None
    if "predicateType" in obj:
        return obj
    return None


def binds(stmt: dict, hex_digest: str, predicate_type: str) -> bool:
    """v_B / v_P: the statement has the expected predicateType, at least one subject, and
    every subject's digest.sha256 is the image digest (handoff T3; PH1-01)."""
    if stmt.get("predicateType") != predicate_type:
        return False
    subjects = stmt.get("subject")
    if not isinstance(subjects, list) or not subjects:
        return False
    for s in subjects:
        d = s.get("digest") if isinstance(s, dict) else None
        if not isinstance(d, dict) or d.get("sha256") != hex_digest:
            return False
    return True


def image_signatures(verify_output: str, digest: str) -> list[dict]:
    """v_sig: the entries of `cosign verify` output that sign the image `digest` itself.

    An entry counts when its critical.type is an image-signature type (cosign v3's sign/v1,
    or v2's simple signing) and its critical.image names the digest. cosign v3 also lists
    the attestation bundles, so an image that was attested but never signed still makes
    `cosign verify` exit 0; those entries don't count here.
    """
    found = []
    for value in json_values(verify_output):
        critical = value.get("critical") if isinstance(value, dict) else None
        image = critical.get("image") if isinstance(critical, dict) else None
        if (isinstance(image, dict) and critical.get("type") in IMAGE_SIGNATURE_TYPES
                and image.get("docker-manifest-digest") == digest):
            found.append(value)
    return found


def parse_time(value: Any) -> datetime | None:
    """An RFC 3339 timestamp as an aware UTC datetime; None if it isn't one."""
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2})(\.\d+)?([Zz]|[+-]\d{2}:?\d{2})?", value.strip())
    if not m:
        return None
    base, frac, tz = m.groups()
    tz = "+00:00" if tz in (None, "Z", "z") else (tz if ":" in tz else tz[:3] + ":" + tz[3:])
    # Exactly six fraction digits: Python 3.10's fromisoformat takes only 3 or 6, and
    # would otherwise return None here and quietly change which attestation is newest.
    frac = "." + frac[1:7].ljust(6, "0") if frac else ""
    try:
        dt = datetime.fromisoformat(base.replace("t", "T").replace(" ", "T") + frac + tz)
    except ValueError:
        return None
    return dt.astimezone(timezone.utc)


def _predicate_time(stmt: dict, predicate_type: str) -> datetime | None:
    pred = stmt.get("predicate")
    if not isinstance(pred, dict):
        return None
    if predicate_type == CYCLONEDX:
        return parse_time((pred.get("metadata") or {}).get("timestamp"))
    return parse_time(((pred.get("runDetails") or {}).get("metadata") or {}).get("finishedOn"))


def newest_binding(output: str, hex_digest: str, predicate_type: str) -> dict | None:
    """The newest statement that binds, by the predicate's own timestamp (decision D2).

    cosign's output order carries no time. A statement with a timestamp beats one
    without; on a tie, or when none has one, the last line wins.
    """
    best, best_key = None, None
    for index, value in enumerate(json_values(output)):
        stmt = statement(value)
        if stmt is None or not binds(stmt, hex_digest, predicate_type):
            continue
        ts = _predicate_time(stmt, predicate_type)
        key = (ts is not None, ts or datetime.min.replace(tzinfo=timezone.utc), index)
        if best_key is None or key > best_key:
            best, best_key = stmt, key
    return best


def _as_log_index(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if v >= 0 else None
    if isinstance(v, str) and v.isascii() and v.isdigit():
        return int(v)                  # protobuf's JSON encoding writes int64 as a string
    return None


def find_log_index(value: Any) -> int | None:
    """The first integer (or string of digits) under a key named logIndex or log_index,
    depth-first in document order; None if there is none."""
    if isinstance(value, dict):
        for k, v in value.items():
            if k in ("logIndex", "log_index"):
                n = _as_log_index(v)
                if n is not None:
                    return n
            found = find_log_index(v)
            if found is not None:
                return found
    elif isinstance(value, list):
        for v in value:
            found = find_log_index(v)
            if found is not None:
                return found
    return None


def signature_log_index(bundles_output: str, hex_digest: str) -> int | None:
    """tau_I with cosign v3: the Rekor entry of the image-signature bundle, or None.

    `cosign download signature` prints one Sigstore bundle per line: the image signature
    (a DSSE in-toto statement of type sign/v1 with an empty predicate) and the attestations.
    Take the bundles whose statement is sign/v1 and binds to the image digest, and read
    each one's own entry, verificationMaterial.tlogEntries[0].logIndex. (The entry's
    inclusionProof holds a second logIndex, the log tree's, so find_log_index's first match
    is not used here.) Of several, the latest integratedTime wins, then the last line.

    Trust: `download signature` verifies nothing, and this function doesn't check the
    bundle's signature again. `cosign verify` has just verified the image's signature
    bundles with our key, tlog inclusion included, and the index is recorded for audit;
    Role 4's transparency check (PH6) can re-verify it against Rekor.
    """
    best, best_key = None, None
    for line, value in enumerate(json_values(bundles_output)):
        stmt = statement(value) if isinstance(value, dict) and "dsseEnvelope" in value else None
        if stmt is None or not binds(stmt, hex_digest, SIGN_V1):
            continue
        entries = (value.get("verificationMaterial") or {}).get("tlogEntries")
        entry = entries[0] if isinstance(entries, list) and entries and isinstance(entries[0], dict) else {}
        index = _as_log_index(entry.get("logIndex"))
        if index is None:
            continue
        integrated = _as_log_index(entry.get("integratedTime"))
        key = (integrated if integrated is not None else -1, line)
        if best_key is None or key > best_key:
            best, best_key = index, key
    return best


def signing_identity(provenance: dict) -> tuple[str, str | None]:
    """builder_id = runDetails.builder.id; source_commit = the gitCommit of the first
    resolvedDependencies entry that has one that is a commit hash (40 or 64 hex digits).
    Anything else, such as the "unknown" gen_provenance.py writes outside a git checkout,
    gives None."""
    builder = ((provenance.get("runDetails") or {}).get("builder") or {}).get("id")
    if not isinstance(builder, str) or not BUILDER_URI.match(builder):
        raise EvidenceError(f"v_P: provenance runDetails.builder.id is not a URI: {builder!r}")
    for dep in (provenance.get("buildDefinition") or {}).get("resolvedDependencies") or ():
        digest = dep.get("digest") if isinstance(dep, dict) else None
        commit = digest.get("gitCommit") if isinstance(digest, dict) else None
        if isinstance(commit, str) and GIT_COMMIT.match(commit):
            return builder, commit
        if commit is not None:
            log.info("provenance gitCommit %.40r is not a commit hash; ignored", commit)
    return builder, None


def collect(ref: str, digest: str, cosign: Cosign) -> Evidence:
    """Verify the signature and both attestations for `ref` and return what they say.

    `ref` is where cosign looks (it may name another registry host, see --registry-name);
    `digest` is the image digest every statement must bind to.
    """
    hex_digest = digest.split(":", 1)[1]
    signatures = image_signatures(cosign.verify(ref), digest)                     # v_sig
    if not signatures:
        raise EvidenceError(f"v_sig: cosign verified no image signature for {digest} "
                            "(attestations alone don't count)")

    sbom = newest_binding(cosign.verify_attestation(ref, "cyclonedx"), hex_digest, CYCLONEDX)
    if sbom is None or not isinstance(sbom.get("predicate"), dict):
        raise EvidenceError(f"v_B: no verified CycloneDX attestation binds to {digest}")
    prov = newest_binding(cosign.verify_attestation(ref, "slsaprovenance1"), hex_digest, SLSA_V1)
    if prov is None or not isinstance(prov.get("predicate"), dict):
        raise EvidenceError(f"v_P: no verified SLSA v1 provenance binds to {digest}")

    builder, commit = signing_identity(prov["predicate"])
    log_index = find_log_index(signatures)                           # cosign v2 prints the entry
    if log_index is None:
        log_index = signature_log_index(cosign.download_signature(ref), hex_digest)     # v3
    if log_index is None:
        log.info("no Rekor log index for the image signature; recorded as null")
    return Evidence(digest, sbom["predicate"], prov["predicate"], builder, commit, log_index)
