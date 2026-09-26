"""T3: verified evidence and the binding checks (handoff T3; paper Eqs. 10-18).

The compiler reads only what cosign has verified against our public key: the image
signature (v_sig) and two attestations, each bound to the image digest (v_B for the
CycloneDX SBOM, v_P for the SLSA v1 provenance). The debug copies under run/attest/ are
never read. cosign v2 and v3 print different layouts (handoff Section 5, fact 2), so the
output is read defensively.
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
BUILDER_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")     # the schema's builder_id pattern
TIMEOUT_S = 300


class EvidenceError(Exception):
    """v_sig, v_B or v_P failed. The CLI exits 2 and writes nothing."""


class Cosign:
    """Runs the cosign commands T3 needs. Tests pass a fake `run`."""

    def __init__(self, key: str, offline: bool = False, binary: str = "cosign",
                 run: Callable[..., subprocess.CompletedProcess] = subprocess.run):
        self.key, self.binary, self._run = key, binary, run
        self.flags = ["--insecure-ignore-tlog=true"] if offline else []

    def _cosign(self, check: str, command: str, *args: str) -> str:
        cmd = [self.binary, command, "--key", self.key, *self.flags, *args]
        try:
            out = self._run(cmd, capture_output=True, text=True, timeout=TIMEOUT_S)
        except FileNotFoundError:
            raise RuntimeError(f"{self.binary} not found on PATH") from None
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
    """v_B / v_P: the statement has the expected predicateType and names the image digest
    among its subjects."""
    if stmt.get("predicateType") != predicate_type:
        return False
    for s in stmt.get("subject") or ():
        d = s.get("digest") if isinstance(s, dict) else None
        if isinstance(d, dict) and d.get("sha256") == hex_digest:
            return True
    return False


def parse_time(value: Any) -> datetime | None:
    """An RFC 3339 timestamp as an aware UTC datetime; None if it isn't one."""
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2})(\.\d+)?([Zz]|[+-]\d{2}:?\d{2})?", value.strip())
    if not m:
        return None
    base, frac, tz = m.groups()
    tz = "+00:00" if tz in (None, "Z", "z") else (tz if ":" in tz else tz[:3] + ":" + tz[3:])
    try:
        dt = datetime.fromisoformat(base.replace("t", "T").replace(" ", "T") + (frac or "")[:7] + tz)
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


def signing_identity(provenance: dict) -> tuple[str, str | None]:
    """builder_id = runDetails.builder.id; source_commit = the gitCommit of the first
    resolvedDependencies entry that has one."""
    builder = ((provenance.get("runDetails") or {}).get("builder") or {}).get("id")
    if not isinstance(builder, str) or not BUILDER_URI.match(builder):
        raise EvidenceError(f"v_P: provenance runDetails.builder.id is not a URI: {builder!r}")
    for dep in (provenance.get("buildDefinition") or {}).get("resolvedDependencies") or ():
        digest = dep.get("digest") if isinstance(dep, dict) else None
        commit = digest.get("gitCommit") if isinstance(digest, dict) else None
        if isinstance(commit, str) and commit:
            return builder, commit
    return builder, None


def collect(ref: str, digest: str, cosign: Cosign) -> Evidence:
    """Verify the signature and both attestations for `ref` and return what they say.

    `ref` is where cosign looks (it may name another registry host, see --registry-name);
    `digest` is the image digest every statement must bind to.
    """
    hex_digest = digest.split(":", 1)[1]
    log_index = find_log_index(list(json_values(cosign.verify(ref))))            # v_sig

    sbom = newest_binding(cosign.verify_attestation(ref, "cyclonedx"), hex_digest, CYCLONEDX)
    if sbom is None or not isinstance(sbom.get("predicate"), dict):
        raise EvidenceError(f"v_B: no verified CycloneDX attestation binds to {digest}")
    prov = newest_binding(cosign.verify_attestation(ref, "slsaprovenance1"), hex_digest, SLSA_V1)
    if prov is None or not isinstance(prov.get("predicate"), dict):
        raise EvidenceError(f"v_P: no verified SLSA v1 provenance binds to {digest}")

    builder, commit = signing_identity(prov["predicate"])
    if log_index is None:
        log.info("no Rekor log index in the cosign verify output; recorded as null")
    return Evidence(digest, sbom["predicate"], prov["predicate"], builder, commit, log_index)
