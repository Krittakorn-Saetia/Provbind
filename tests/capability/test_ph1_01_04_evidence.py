"""PH1-01 and PH1-04: a real image's build evidence (Test Plan §3.1).

- PH1-01 (Eqs. 1-6): the image, its SBOM and its provenance are signed and bound to d_I. Pass:
  `cosign verify` and both `verify-attestation` calls pass with pipeline/keys/cosign.pub; the
  verified output includes an image signature, not only attestations (cosign v3's `verify` lists
  the attestation bundles too); and every subject of every verified statement is d_I, which is
  stricter than the compiler's binding check (any subject naming d_I).
- PH1-04: the SBOM has dependency edges. Pass: the verified CycloneDX SBOM has at least one edge.
  `unresolved_fraction`, from compiler/sbom.py, is recorded with it.

Both read only what cosign verifies, never the debug copies in run/attest/. The images are
PROVBIND_STANDIN_REF, plus PROVBIND_DEMO_REF when it is set (the plan runs PH1-01 on both). They
are integration tests: they need cosign and the registry, and skip without a reference. They only
verify; they never build or sign. The unit tests at the end check the checking logic anywhere.
"""
import base64
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from compiler.evidence import CYCLONEDX, SLSA_V1, json_values, newest_binding, statement
from compiler.sbom import depths

ROOT = Path(__file__).resolve().parents[2]
PUB = ROOT / "pipeline" / "keys" / "cosign.pub"
IMAGES = (("standin", "PROVBIND_STANDIN_REF"), ("demo", "PROVBIND_DEMO_REF"))
PREDICATES = {"cyclonedx": CYCLONEDX, "slsaprovenance1": SLSA_V1}
# What `cosign verify` prints for an image signature: cosign v3 signs an in-toto statement of the
# first type; cosign v2 printed a simple-signing payload of the second.
IMAGE_SIGNATURE_TYPES = ("https://sigstore.dev/cosign/sign/v1", "cosign container image signature")


def images() -> list[tuple[str, str]]:
    """(label, ref@digest) for each image reference set in the environment."""
    return [(label, os.environ[var].strip()) for label, var in IMAGES if os.environ.get(var, "").strip()]


def hex_of(ref: str) -> str:
    return ref.rsplit("@sha256:", 1)[1]


def cosign(command: str, ref: str, *extra: str) -> subprocess.CompletedProcess:
    offline = ["--insecure-ignore-tlog=true"] if os.environ.get("PROVBIND_OFFLINE") == "1" else []
    return subprocess.run(["cosign", command, "--key", str(PUB), *offline, *extra, ref],
                          capture_output=True, text=True, timeout=300)


def last_line(text: str) -> str:
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return lines[-1] if lines else "no error message"


def signatures(verify_stdout: str, hex_digest: str) -> dict:
    """What `cosign verify` vouched for: its entries, the image signatures among them for this
    digest, and any entry that names another digest."""
    entries = sigs = other = 0
    for value in json_values(verify_stdout):
        critical = value.get("critical") if isinstance(value, dict) else None
        if not isinstance(critical, dict):
            continue
        entries += 1
        named = ((critical.get("image") or {}).get("docker-manifest-digest") or "").rsplit(":", 1)[-1]
        if named != hex_digest:
            other += 1
        elif critical.get("type") in IMAGE_SIGNATURE_TYPES:
            sigs += 1
    return {"verify_entries": entries, "image_signatures": sigs, "entries_for_another_digest": other}


def statements(output: str, hex_digest: str, predicate_type: str) -> dict:
    """The verified statements in `verify-attestation` output: how many have the predicate type,
    and how many subjects, of any statement, are not d_I. A statement without subjects binds to
    nothing, so it counts as one subject that is not d_I."""
    typed = subjects = foreign = 0
    for value in json_values(output):
        stmt = statement(value)
        if stmt is None:
            continue
        typed += stmt.get("predicateType") == predicate_type
        for s in stmt.get("subject") or [None]:
            subjects += 1
            digest = s.get("digest") if isinstance(s, dict) else None
            foreign += not (isinstance(digest, dict) and digest.get("sha256") == hex_digest)
    return {"statements": typed, "subjects": subjects, "subjects_not_d_I": foreign}


@pytest.fixture(scope="module")
def refs():
    found = images()
    if not found:
        pytest.skip("export PROVBIND_STANDIN_REF=<ref@digest printed by build-and-attest.sh> "
                    "(and PROVBIND_DEMO_REF for the demo image)")
    if shutil.which("cosign") is None:
        pytest.skip("cosign is not on PATH")
    return found


@pytest.mark.integration
def test_ph1_01_image_sbom_and_provenance_are_signed_and_bound(refs, record_result):
    per_image, problems = {}, []
    for label, ref in refs:
        hx = hex_of(ref)
        out = cosign("verify", ref)
        m = {"verify": out.returncode == 0, **signatures(out.stdout, hx)}
        if out.returncode != 0:
            problems.append(f"{label}: cosign verify failed: {last_line(out.stderr)}")
        elif not m["image_signatures"]:
            problems.append(f"{label}: cosign verify passed, but its output has no image signature, only attestations")
        if m["entries_for_another_digest"]:
            problems.append(f"{label}: cosign verify printed {m['entries_for_another_digest']} entries for another digest")
        for name, predicate_type in PREDICATES.items():
            out = cosign("verify-attestation", ref, "--type", name)
            s = statements(out.stdout, hx, predicate_type)
            m[name] = {"verify_attestation": out.returncode == 0, **s}
            if out.returncode != 0:
                problems.append(f"{label}: verify-attestation --type {name} failed: {last_line(out.stderr)}")
            elif not s["statements"]:
                problems.append(f"{label}: no verified {name} statement")
            if s["subjects_not_d_I"]:
                problems.append(f"{label}: {s['subjects_not_d_I']} subject(s) in the {name} output are not d_I")
        per_image[label] = m

    ok = not problems
    metrics = {"images": len(per_image),
               "image_signatures": sum(m["image_signatures"] for m in per_image.values()),
               "statements": sum(m[n]["statements"] for m in per_image.values() for n in PREDICATES),
               "subjects_not_d_I": sum(m[n]["subjects_not_d_I"] for m in per_image.values() for n in PREDICATES),
               "per_image": per_image}
    notes = "; ".join(f"{label} {ref}" for label, ref in refs)
    notes += "; " + "; ".join(problems) if problems else "; signature and both attestations verified, every subject is d_I"
    record_result("PH1-01", "pass" if ok else "fail", metrics=metrics, notes=notes)
    assert ok, notes


@pytest.mark.integration
def test_ph1_04_sbom_has_dependency_edges(refs, record_result):
    per_image, problems = {}, []
    for label, ref in refs:
        out = cosign("verify-attestation", ref, "--type", "cyclonedx")
        stmt = newest_binding(out.stdout, hex_of(ref), CYCLONEDX) if out.returncode == 0 else None
        if stmt is None or not isinstance(stmt.get("predicate"), dict):
            problems.append(f"{label}: no verified CycloneDX SBOM bound to the image"
                            + (f" ({last_line(out.stderr)})" if out.returncode != 0 else ""))
            continue
        bom = stmt["predicate"]
        deps = bom.get("dependencies") or []
        packages, unresolved = depths(bom)
        m = {"dependency_entries": len(deps),
             "edges": sum(len(d.get("dependsOn") or []) for d in deps if isinstance(d, dict)),
             "unresolved_fraction": round(unresolved, 4),
             "packages": len(packages),
             "packages_without_purl": sum(not key.startswith("pkg:") for key in packages)}
        per_image[label] = m
        if not m["edges"]:
            problems.append(f"{label}: the SBOM has no dependency edges, so every depth would be null")

    ok = bool(per_image) and not problems
    metrics = {f"{label}_{key}": m[key]
               for key in ("dependency_entries", "edges", "unresolved_fraction", "packages", "packages_without_purl")
               for label, m in per_image.items()}
    notes = "; ".join(f"{label} {ref}: {per_image[label]['dependency_entries']} dependency entries, "
                      f"{per_image[label]['edges']} edges, unresolved_fraction {per_image[label]['unresolved_fraction']} "
                      f"({per_image[label]['packages_without_purl']} of {per_image[label]['packages']} package "
                      "entries have no purl)"
                      for label, ref in refs if label in per_image)
    if problems:
        notes = "; ".join(filter(None, [notes, *problems]))
    record_result("PH1-04", "pass" if ok else "fail", metrics=metrics, notes=notes)
    assert ok, notes


# --- the checking logic, without cosign ------------------------------------------------------------

HX, OTHER = "0a" * 32, "0b" * 32


def _entry(kind: str, hex_digest: str = HX) -> dict:
    return {"critical": {"identity": {"docker-reference": "localhost:5001/x"},
                         "image": {"docker-manifest-digest": f"sha256:{hex_digest}"}, "type": kind},
            "optional": {}}


def _dsse(predicate_type: str, *subject_hexes: str) -> str:
    stmt = {"_type": "https://in-toto.io/Statement/v1", "predicateType": predicate_type,
            "subject": [{"digest": {"sha256": h}} for h in subject_hexes], "predicate": {}}
    return json.dumps({"payloadType": "application/vnd.in-toto+json",
                       "payload": base64.b64encode(json.dumps(stmt).encode()).decode(), "signatures": []})


def test_signatures_counts_the_image_signature_not_the_attestations():
    """cosign v3.1.3's real `verify` output for the stand-in: one entry per bundle."""
    out = json.dumps([_entry(CYCLONEDX), _entry(SLSA_V1), _entry("https://sigstore.dev/cosign/sign/v1")])
    assert signatures(out, HX) == {"verify_entries": 3, "image_signatures": 1, "entries_for_another_digest": 0}


def test_signatures_finds_none_when_only_attestations_verify():
    out = json.dumps([_entry(CYCLONEDX), _entry(SLSA_V1)])
    assert signatures(out, HX)["image_signatures"] == 0


def test_signatures_reads_cosign_v2_output():
    out = "\n".join(json.dumps([_entry("cosign container image signature")]) for _ in range(2))
    assert signatures(out, HX)["image_signatures"] == 2


def test_signatures_for_another_digest_do_not_count():
    out = json.dumps([_entry("https://sigstore.dev/cosign/sign/v1", OTHER)])
    assert signatures(out, HX) == {"verify_entries": 1, "image_signatures": 0, "entries_for_another_digest": 1}


def test_statements_requires_every_subject_to_be_d_i():
    out = "\n".join([_dsse(CYCLONEDX, HX), _dsse(CYCLONEDX, HX, OTHER)])
    assert statements(out, HX, CYCLONEDX) == {"statements": 2, "subjects": 3, "subjects_not_d_I": 1}


def test_statements_of_another_type_are_not_counted_but_their_subjects_are():
    assert statements(_dsse(SLSA_V1, OTHER), HX, CYCLONEDX) == {"statements": 0, "subjects": 1, "subjects_not_d_I": 1}


def test_a_statement_without_subjects_is_bound_to_nothing():
    assert statements(_dsse(CYCLONEDX), HX, CYCLONEDX)["subjects_not_d_I"] == 1
