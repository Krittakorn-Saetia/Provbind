"""PH1-02 and PH1-03: whose key signs the evidence, and the transparency record (Test Plan §3.1).

- PH1-02 (fail point C1): each evidence object is signed, not only d_I. The plan: attach an extra SBOM
  attestation signed with a second key. Pass: verification with our key does not accept it, and with
  no valid SBOM left the compiler exits 2.
  The test copies the image, by digest, into a new repository of the same registry (the image's own
  evidence stays untouched), attests the copy with a throwaway key generated for the run, with no
  transparency-log upload, and then checks: the throwaway key verifies its attestation (so it is
  really there and bound to d_I); our key does not accept it; the compiler exits 2 and writes nothing.
  Each run leaves one small repository, localhost:5001/provbind-ph1-02-<name>-<id>, in the registry.
- PH1-03 (Eqs. 5-6): a transparency record τ_I exists. Pass: the image signature's bundle holds a
  Rekor entry with a log index, and when the image's envelope is found (PROVBIND_ENVELOPE, or
  $PROVBIND_RUN/envelopes/<hex>.json), it records the same index. cosign v3 no longer prints the
  entry in `cosign verify`, so it is read from `cosign download signature`. Offline signing has no
  record by design: blocked.
  compiler/evidence.py reads the index from cosign v3's signature bundle since branch
  local/evidence-fixes; an envelope compiled before that holds null. That one known cause is
  recorded as fail and reported by pytest as xfail, so an integration run stays green: recompile
  the envelope. Any other problem fails outright.

The images are PROVBIND_STANDIN_REF and PROVBIND_DEMO_REF, as for PH1-01. Integration tests: they
need cosign, crane and the registry, and never touch pipeline/keys/cosign.key.
"""
import base64
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from compiler.evidence import CYCLONEDX, find_log_index, json_values, newest_binding

from .test_ph1_01_04_evidence import cosign, hex_of, images, last_line

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
SIGN_TYPE = "https://sigstore.dev/cosign/sign/v1"


def run(cmd, env=None, cwd=None, timeout=300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd)


@pytest.fixture(scope="module")
def refs():
    found = images()
    if not found:
        pytest.skip("export PROVBIND_STANDIN_REF=<ref@digest printed by build-and-attest.sh> "
                    "(and PROVBIND_DEMO_REF for the demo image)")
    missing = [tool for tool in ("cosign", "crane") if shutil.which(tool) is None]
    if missing:
        pytest.skip(f"not on PATH: {', '.join(missing)}")
    return found


# --- PH1-02 ------------------------------------------------------------------------------------------

def throwaway_key(directory: Path) -> Path:
    """A key pair made for this run, with an empty password: the "second key"."""
    out = run(["cosign", "generate-key-pair"], env={**os.environ, "COSIGN_PASSWORD": ""}, cwd=directory)
    assert out.returncode == 0, f"cosign generate-key-pair failed: {last_line(out.stderr)}"
    return directory / "cosign.key"


def attest_foreign(key: Path, predicate: Path, ref: str) -> subprocess.CompletedProcess:
    """Attest `ref` with the throwaway key and no transparency-log upload. cosign v3 refuses
    --tlog-upload=false unless signing configs are off; older cosign has no --use-signing-config."""
    base = ["cosign", "attest", "--yes", "--key", str(key), "--type", "cyclonedx", "--predicate", str(predicate)]
    env = {**os.environ, "COSIGN_PASSWORD": ""}
    out = run(base + ["--use-signing-config=false", "--tlog-upload=false", ref], env=env)
    if out.returncode != 0 and "unknown flag" in out.stderr:
        out = run(base + ["--tlog-upload=false", ref], env=env)
    return out


def tlog_entries(ref: str) -> int | None:
    """Transparency-log entries in the attestation bundles attached to `ref` (cosign v3 layout)."""
    out = run(["cosign", "download", "attestation", ref])
    if out.returncode != 0:
        return None
    return sum(len(((v.get("verificationMaterial") or {}).get("tlogEntries")) or [])
               for v in json_values(out.stdout) if isinstance(v, dict))


def test_ph1_02_evidence_signed_with_another_key_is_not_accepted(refs, tmp_path, record_result):
    key = throwaway_key(tmp_path)
    per_image, problems = {}, []
    for label, ref in refs:
        repo, digest = ref.rsplit("@", 1)
        copy_repo = f"{repo.split('/', 1)[0]}/provbind-ph1-02-{label}-{uuid.uuid4().hex[:8]}"
        copy = f"{copy_repo}@{digest}"
        m = {"copy": copy}
        per_image[label] = m

        ours = cosign("verify-attestation", ref, "--type", "cyclonedx")      # a real SBOM to attest again
        stmt = newest_binding(ours.stdout, hex_of(ref), CYCLONEDX) if ours.returncode == 0 else None
        if stmt is None:
            problems.append(f"{label}: no verified SBOM of ours to start from ({last_line(ours.stderr)})")
            continue
        predicate = tmp_path / f"{label}-sbom.json"
        predicate.write_text(json.dumps(stmt["predicate"]), encoding="utf-8")

        copied = run(["crane", "copy", ref, f"{copy_repo}:ph1-02"], timeout=600)
        if copied.returncode != 0:
            problems.append(f"{label}: crane copy failed: {last_line(copied.stderr)}")
            continue
        attested = attest_foreign(key, predicate, copy)
        if attested.returncode != 0:
            problems.append(f"{label}: attesting with the second key failed: {last_line(attested.stderr)}")
            continue

        own = run(["cosign", "verify-attestation", "--key", str(tmp_path / "cosign.pub"),
                   "--insecure-ignore-tlog=true", "--type", "cyclonedx", copy])
        mine = cosign("verify-attestation", copy, "--type", "cyclonedx")
        compiled = run([sys.executable, "-m", "compiler.compile", copy, "--run", str(tmp_path / f"run-{label}")],
                       cwd=ROOT, timeout=600)
        written = sorted((tmp_path / f"run-{label}" / "envelopes").glob("*.json"))
        m.update({"second_key_verifies_it": own.returncode == 0, "our_key_accepts_it": mine.returncode == 0,
                  "compiler_exit": compiled.returncode, "envelope_written": bool(written),
                  "tlog_entries": tlog_entries(copy),
                  "compiler_said": next((ln.split("ERROR: ", 1)[1] for ln in compiled.stderr.splitlines()
                                         if "ERROR: " in ln), "")[:160]})
        if not m["second_key_verifies_it"]:
            problems.append(f"{label}: the second key doesn't verify its own attestation ({last_line(own.stderr)})")
        if m["our_key_accepts_it"]:
            problems.append(f"{label}: our key ACCEPTED an SBOM attestation signed with another key")
        if m["compiler_exit"] != 2 or m["envelope_written"]:
            problems.append(f"{label}: the compiler exited {m['compiler_exit']}"
                            + (" and wrote an envelope" if written else "") + ", not 2 with nothing written")

    ok = not problems
    done = [m for m in per_image.values() if "our_key_accepts_it" in m]
    metrics = {"images": len(per_image),
               "rejected_by_our_key": sum(not m["our_key_accepts_it"] for m in done),
               "compiler_exit_2": sum(m["compiler_exit"] == 2 and not m["envelope_written"] for m in done),
               "second_key_verifies_its_own": sum(m["second_key_verifies_it"] for m in done),
               "per_image": per_image}
    notes = "; ".join(f"{label}: copy {m['copy']}" + (f"; compiler: {m['compiler_said']}" if m.get("compiler_said") else "")
                      for label, m in per_image.items())
    notes += "; " + "; ".join(problems) if problems else \
        "; the second key's SBOM attestation verifies with that key only; our key rejects it; the compiler exits 2"
    record_result("PH1-02", "pass" if ok else "fail", metrics=metrics, notes=notes)
    assert ok, notes


# --- PH1-03 ------------------------------------------------------------------------------------------

def signature_log_entry(ref: str) -> dict | None:
    """The Rekor entry of the image signature bound to d_I: {"log_index", "integrated_time"}, or None.
    cosign v3 keeps it in the signature's bundle (a sign/v1 statement); older cosign prints a bundle
    payload with a logIndex."""
    out = run(["cosign", "download", "signature", ref])
    if out.returncode != 0:
        return None
    hex_digest = hex_of(ref)
    for value in json_values(out.stdout):
        if not isinstance(value, dict):
            continue
        envelope = value.get("dsseEnvelope")
        if isinstance(envelope, dict):
            try:
                stmt = json.loads(base64.b64decode(envelope.get("payload", "")))
            except ValueError:
                continue
            subjects = [((s.get("digest") or {}).get("sha256")) for s in stmt.get("subject") or () if isinstance(s, dict)]
            entries = (value.get("verificationMaterial") or {}).get("tlogEntries") or []
            if stmt.get("predicateType") == SIGN_TYPE and hex_digest in subjects and entries:
                # The entry's own logIndex; its inclusionProof holds another index (the log tree's).
                index = str(entries[0].get("logIndex", ""))
                return {"log_index": int(index) if index.isdigit() else None,
                        "integrated_time": entries[0].get("integratedTime")}
        else:
            index = find_log_index(value)
            if index is not None:
                return {"log_index": index, "integrated_time": None}
    return None


def envelope_for(ref: str) -> tuple[Path | None, dict | None]:
    """The image's envelope: PROVBIND_ENVELOPE if it is this image's, else the run folder's."""
    hex_digest = hex_of(ref)
    candidates = [Path(p) for p in (os.environ.get("PROVBIND_ENVELOPE"),) if p]
    candidates.append(Path(os.environ.get("PROVBIND_RUN", "./run")) / "envelopes" / f"{hex_digest}.json")
    for path in candidates:
        if path.is_file():
            env = json.loads(path.read_text(encoding="utf-8"))
            if (env.get("image") or {}).get("digest") == f"sha256:{hex_digest}":
                return path, env
    return None, None


def as_time(seconds) -> str | None:
    try:
        return dt.datetime.fromtimestamp(int(seconds), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return None


def test_ph1_03_a_transparency_record_exists(refs, record_result):
    if os.environ.get("PROVBIND_OFFLINE") == "1":
        record_result("PH1-03", "blocked", notes="PROVBIND_OFFLINE=1: signing without Rekor, so there is no "
                                                 "transparency record by design (Test Plan §3.1)")
        pytest.skip("offline signing has no transparency record")
    per_image, problems, known = {}, [], []
    for label, ref in refs:
        verified = cosign("verify", ref)
        entry = signature_log_entry(ref) if verified.returncode == 0 else None
        path, env = envelope_for(ref)
        recorded = (env.get("image") or {}).get("rekor_log_index") if env else None
        per_image[label] = {"verify": verified.returncode == 0,
                            "log_index": entry and entry["log_index"],
                            "integrated_time": as_time(entry and entry["integrated_time"]),
                            "envelope": str(path) if path else None, "envelope_log_index": recorded}
        if verified.returncode != 0:
            problems.append(f"{label}: cosign verify failed: {last_line(verified.stderr)}")
        elif not entry or entry["log_index"] is None:
            problems.append(f"{label}: the image signature has no Rekor entry")
        elif env is not None and recorded != entry["log_index"]:
            (known if recorded is None else problems).append(
                f"{label}: τ_I exists (log index {entry['log_index']}), but the envelope records {recorded}"
                + (": compiled before the cosign v3 fix (branch local/evidence-fixes); recompile it"
                   if recorded is None else ""))

    ok = not problems and not known
    metrics = {"images": len(per_image), "log_index": {k: v["log_index"] for k, v in per_image.items()},
               "envelope_log_index": {k: v["envelope_log_index"] for k, v in per_image.items()},
               "integrated_time": {k: v["integrated_time"] for k, v in per_image.items()}, "per_image": per_image}
    notes = "; ".join(f"{label} {ref}: log index {per_image[label]['log_index']}, integrated "
                      f"{per_image[label]['integrated_time']}; envelope "
                      + (f"records {per_image[label]['envelope_log_index']}" if per_image[label]["envelope"]
                         else "not found, so not compared") for label, ref in refs)
    if problems or known:
        notes += "; " + "; ".join(problems + known)
    record_result("PH1-03", "pass" if ok else "fail", metrics=metrics, notes=notes)
    assert not problems, notes
    if known:
        pytest.xfail("known: " + notes)
