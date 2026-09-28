"""T3: evidence from canned cosign output (no cosign, no registry)."""
import base64
import json
import subprocess
from pathlib import Path

import pytest

from compiler.evidence import (CYCLONEDX, SIGN_V1, SLSA_V1, Cosign, EvidenceError, collect, find_log_index,
                               image_signatures, newest_binding, parse_time, signature_log_index)

HEX = "ab" * 32
DIGEST = "sha256:" + HEX
REF = "localhost:5001/standin-app@" + DIGEST
COMMIT = "9f31ab2c4d5e6f708192a3b4c5d6e7f8091a2b3c"
BUILDER = "https://github.com/sf9-26/provbind/builders/local@v1"


def sbom(timestamp="2026-09-26T10:00:00Z", name="requests"):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"timestamp": timestamp},
            "components": [{"bom-ref": "x", "type": "library", "name": name, "purl": f"pkg:pypi/{name}@1"}]}


def provenance(finished="2026-09-26T10:00:05Z", commit=COMMIT, builder=BUILDER):
    return {"buildDefinition": {"buildType": "https://example.test/build@v1",
                                "resolvedDependencies": [{"uri": "docker://python", "name": "base-image",
                                                          "digest": {"sha256": "cd" * 32}},
                                                         {"uri": "git+local", "name": "source",
                                                          "digest": {"gitCommit": commit}}]},
            "runDetails": {"builder": {"id": builder}, "metadata": {"finishedOn": finished}}}


def stmt(predicate_type, predicate, hex_digest=HEX):
    return {"_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "localhost:5001/standin-app", "digest": {"sha256": hex_digest}}],
            "predicateType": predicate_type, "predicate": predicate}


def dsse(statement):
    return {"payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
            "signatures": [{"keyid": "", "sig": "MEUCIQ"}]}


def lines(*values):
    return "\n".join(json.dumps(v) for v in values) + "\n"


VERIFY_V2 = json.dumps([{"critical": {"image": {"docker-manifest-digest": DIGEST},
                                      "type": "cosign container image signature"},
                         "optional": {"Bundle": {"SignedEntryTimestamp": "MEU",
                                                 "Payload": {"body": "e30=", "integratedTime": 1758880000,
                                                             "logIndex": 123456789, "logID": "c0d2"}}}}])

# Real cosign v3.1.3 output for the stand-in (docs/reports/REKOR-BUG-2026-09-28.md). The download
# fixture is trimmed: the two attestation predicates are cut, the sign/v1 bundle is whole.
FIXTURES = Path(__file__).with_name("fixtures")
V3_HEX = "0a6bfbb07745da4c50e29e159cf426b05ff4481540a9894c746e1190961944a3"
V3_DIGEST = "sha256:" + V3_HEX
V3_REF = "localhost:5001/standin-app@" + V3_DIGEST
VERIFY_V3 = (FIXTURES / "cosign-v3-verify.json").read_text()
BUNDLES_V3 = (FIXTURES / "cosign-v3-download-signature.jsonl").read_text()


def v3_entry(type_, digest=V3_DIGEST):
    return {"critical": {"identity": {"docker-reference": V3_REF}, "image": {"docker-manifest-digest": digest},
                         "type": type_}, "optional": {}}


def sign_bundle(log_index, integrated="1790502170", hex_digest=V3_HEX, predicate_type=SIGN_V1):
    """A cosign v3 signature bundle. Its inclusionProof holds a second, different logIndex."""
    return {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {"tlogEntries": [
                {"inclusionProof": {"logIndex": "2850999164", "treeSize": "2851000000"},
                 "logIndex": log_index, "integratedTime": integrated}]},
            "dsseEnvelope": dsse(stmt(predicate_type, {}, hex_digest))}


class FakeCosign:
    def __init__(self, verify=VERIFY_V2, sbom_out=None, prov_out=None, bundles=""):
        self.calls = []
        self.out = {"verify": verify, "download": bundles,
                    "cyclonedx": lines(dsse(stmt(CYCLONEDX, sbom()))) if sbom_out is None else sbom_out,
                    "slsaprovenance1": lines(dsse(stmt(SLSA_V1, provenance()))) if prov_out is None else prov_out}

    def verify(self, ref):
        self.calls.append("verify")
        if isinstance(self.out["verify"], Exception):
            raise self.out["verify"]
        return self.out["verify"]

    def verify_attestation(self, ref, predicate):
        self.calls.append(predicate)
        return self.out[predicate]

    def download_signature(self, ref):
        self.calls.append("download")
        return self.out["download"]


def v3_cosign(verify=VERIFY_V3, bundles=BUNDLES_V3):
    """The stand-in's real v3 output, with canned attestations bound to its digest."""
    return FakeCosign(verify, lines(dsse(stmt(CYCLONEDX, sbom(), V3_HEX))),
                      lines(dsse(stmt(SLSA_V1, provenance(), V3_HEX))), bundles)


# --- output shapes ---------------------------------------------------------------------------

def test_dsse_envelopes_decode():
    ev = collect(REF, DIGEST, FakeCosign())
    assert ev.sbom["components"][0]["name"] == "requests"
    assert ev.builder_id == BUILDER
    assert ev.source_commit == COMMIT
    assert ev.rekor_log_index == 123456789
    assert ev.verification == {"v_sig": True, "v_B": True, "v_P": True}


def test_bare_statements_decode():
    fake = FakeCosign(sbom_out=lines(stmt(CYCLONEDX, sbom())), prov_out=lines(stmt(SLSA_V1, provenance())))
    ev = collect(REF, DIGEST, fake)
    assert ev.sbom["bomFormat"] == "CycloneDX" and ev.source_commit == COMMIT


def test_sigstore_bundle_with_dsse_envelope_decodes():
    bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
              "dsseEnvelope": dsse(stmt(CYCLONEDX, sbom())),
              "verificationMaterial": {"tlogEntries": [{"logIndex": "42"}]}}
    ev = collect(REF, DIGEST, FakeCosign(sbom_out=lines(bundle)))
    assert ev.sbom["bomFormat"] == "CycloneDX"


def test_one_pretty_printed_document_decodes():
    ev = collect(REF, DIGEST, FakeCosign(sbom_out=json.dumps(dsse(stmt(CYCLONEDX, sbom())), indent=2)))
    assert ev.sbom["bomFormat"] == "CycloneDX"


def test_non_json_lines_are_skipped(caplog):
    out = "warning: something\n" + lines(dsse(stmt(CYCLONEDX, sbom())))
    assert collect(REF, DIGEST, FakeCosign(sbom_out=out)).sbom["bomFormat"] == "CycloneDX"
    assert "not JSON" in caplog.text


# --- binding (v_B, v_P) -----------------------------------------------------------------------

def test_wrong_subject_digest_raises():
    with pytest.raises(EvidenceError, match="v_B"):
        collect(REF, DIGEST, FakeCosign(sbom_out=lines(dsse(stmt(CYCLONEDX, sbom(), hex_digest="cd" * 32)))))


def test_wrong_predicate_type_raises():
    old = stmt("https://slsa.dev/provenance/v0.2", provenance())
    with pytest.raises(EvidenceError, match="v_P"):
        collect(REF, DIGEST, FakeCosign(prov_out=lines(dsse(old))))


def test_no_attestation_at_all_raises():
    with pytest.raises(EvidenceError, match="v_B"):
        collect(REF, DIGEST, FakeCosign(sbom_out=""))


@pytest.mark.parametrize("position", [0, 1], ids=["other-first", "other-last"])
def test_a_second_subject_naming_another_image_does_not_bind(position):
    s = stmt(CYCLONEDX, sbom())                          # every subject must be d_I (T3, PH1-01)
    s["subject"].insert(position, {"name": "other", "digest": {"sha256": "ef" * 32}})
    with pytest.raises(EvidenceError, match="v_B"):
        collect(REF, DIGEST, FakeCosign(sbom_out=lines(dsse(s))))


@pytest.mark.parametrize("subjects", [[], None, [{"name": "no digest"}], "not a list"],
                         ids=["empty", "missing", "no-digest", "not-a-list"])
def test_a_statement_without_usable_subjects_does_not_bind(subjects):
    s = stmt(SLSA_V1, provenance())
    s["subject"] = subjects
    with pytest.raises(EvidenceError, match="v_P"):
        collect(REF, DIGEST, FakeCosign(prov_out=lines(dsse(s))))


# --- signature (v_sig) ----------------------------------------------------------------------------

def test_signature_failure_stops_before_the_attestations():
    fake = FakeCosign(verify=EvidenceError("v_sig: cosign verify failed: no signatures found"))
    with pytest.raises(EvidenceError, match="v_sig"):
        collect(REF, DIGEST, fake)
    assert fake.calls == ["verify"]


def test_real_v3_verify_output_has_one_image_signature():
    assert [e["critical"]["type"] for e in image_signatures(VERIFY_V3, V3_DIGEST)] == [SIGN_V1]


def test_attestations_alone_are_not_a_signature():
    """cosign v3 `verify` exits 0 for an image that was attested but never signed, and
    lists only the attestation bundles (seen on Korn-PC, 29 September)."""
    only_attestations = [e for e in json.loads(VERIFY_V3) if e["critical"]["type"] != SIGN_V1]
    fake = v3_cosign(verify=json.dumps(only_attestations))
    with pytest.raises(EvidenceError, match=r"^v_sig: cosign verified no image signature for sha256:0a6b"):
        collect(V3_REF, V3_DIGEST, fake)
    assert fake.calls == ["verify"]


def test_v2_simple_signing_is_a_signature():
    assert len(image_signatures(VERIFY_V2, DIGEST)) == 1


@pytest.mark.parametrize("entry", [
    v3_entry(SIGN_V1, digest="sha256:" + "cd" * 32),                 # signs another image
    v3_entry(CYCLONEDX),
    {"critical": {"image": {"docker-manifest-digest": V3_DIGEST}}},   # no type at all
    {"critical": {"type": SIGN_V1}},                                  # no image
    {"critical": None}, "a string",
], ids=["other-digest", "attestation", "no-type", "no-image", "critical-null", "not-an-object"])
def test_entries_that_do_not_sign_this_image_do_not_count(entry):
    assert image_signatures(json.dumps([entry]), V3_DIGEST) == []


def test_verify_output_one_entry_per_line_decodes():
    out = lines(v3_entry(CYCLONEDX), v3_entry(SIGN_V1))
    assert len(image_signatures(out, V3_DIGEST)) == 1


# --- newest attestation (decision D2) ------------------------------------------------------------

def test_newest_by_predicate_timestamp_not_output_order():
    newer = dsse(stmt(CYCLONEDX, sbom("2026-09-26T12:00:00Z", name="newer")))
    older = dsse(stmt(CYCLONEDX, sbom("2026-09-26T09:00:00Z", name="older")))
    chosen = newest_binding(lines(newer, older), HEX, CYCLONEDX)
    assert chosen["predicate"]["components"][0]["name"] == "newer"


def test_newest_provenance_decides_the_commit():
    old = dsse(stmt(SLSA_V1, provenance("2026-09-26T09:00:00Z", commit="1" * 40)))
    new = dsse(stmt(SLSA_V1, provenance("2026-09-26T11:00:00+01:00", commit="2" * 40)))  # 10:00Z
    assert collect(REF, DIGEST, FakeCosign(prov_out=lines(new, old))).source_commit == "2" * 40


@pytest.mark.parametrize("stamps", [("2026-09-26T10:00:00Z",) * 2, (None, None)], ids=["tie", "missing"])
def test_tie_or_missing_timestamp_takes_the_last_line(stamps):
    a, b = (dsse(stmt(CYCLONEDX, sbom(ts, name=n))) for ts, n in zip(stamps, ("first", "last")))
    assert newest_binding(lines(a, b), HEX, CYCLONEDX)["predicate"]["components"][0]["name"] == "last"


def test_non_binding_newer_attestation_is_ignored():
    stale = dsse(stmt(CYCLONEDX, sbom("2026-09-26T08:00:00Z", name="binds")))
    other = dsse(stmt(CYCLONEDX, sbom("2026-09-26T23:00:00Z", name="other-image"), hex_digest="cd" * 32))
    assert newest_binding(lines(stale, other), HEX, CYCLONEDX)["predicate"]["components"][0]["name"] == "binds"


@pytest.mark.parametrize("value,expected", [
    ("2026-09-26T10:00:00Z", "2026-09-26T10:00:00+00:00"),
    ("2026-09-26T10:00:00.123456789Z", "2026-09-26T10:00:00.123456+00:00"),
    ("2026-09-26T12:34:56.5+00:00", "2026-09-26T12:34:56.500000+00:00"),     # 3.10 rejects 1 digit as-is
    ("2026-09-26T12:34:56.1234Z", "2026-09-26T12:34:56.123400+00:00"),
    ("2026-09-26T17:00:00+0700", "2026-09-26T10:00:00+00:00"),
    ("2026-09-26T10:00:00", "2026-09-26T10:00:00+00:00"),
    ("yesterday", None), (None, None), (5, None),
])
def test_parse_time(value, expected):
    got = parse_time(value)
    assert (got.isoformat() if got else None) == expected


# --- Rekor log index -----------------------------------------------------------------------------

@pytest.mark.parametrize("doc,expected", [
    (json.loads(VERIFY_V2), 123456789),
    ([{"a": {"b": [{"log_index": 7}]}}], 7),
    ({"tlogEntries": [{"logIndex": "31415"}]}, 31415),
    ({"logIndex": True, "x": {"logIndex": -1}, "y": {"logIndex": 5}}, 5),
    ([{"critical": {}, "optional": None}], None),
    ([], None),
])
def test_find_log_index(doc, expected):
    assert find_log_index(doc) == expected


def test_missing_log_index_is_none():
    verify = json.dumps([{"critical": {"image": {"docker-manifest-digest": DIGEST},
                                       "type": "cosign container image signature"}, "optional": None}])
    fake = FakeCosign(verify=verify)
    assert collect(REF, DIGEST, fake).rekor_log_index is None
    assert fake.calls[-1] == "download"                  # looked in the bundles too, found nothing


def test_v2_log_index_comes_from_verify_without_a_download():
    fake = FakeCosign()
    assert collect(REF, DIGEST, fake).rekor_log_index == 123456789
    assert "download" not in fake.calls


def test_v3_log_index_comes_from_the_signature_bundle():
    """The stand-in's real output: the sign/v1 bundle's entry, not the attestations' (2972903754,
    2972904049) and not the inclusion proof's."""
    fake = v3_cosign()
    ev = collect(V3_REF, V3_DIGEST, fake)
    assert ev.rekor_log_index == 2972903426
    assert fake.calls == ["verify", "cyclonedx", "slsaprovenance1", "download"]


def test_the_entry_s_own_log_index_is_read_not_the_inclusion_proof_s():
    assert signature_log_index(lines(sign_bundle("2972903426")), V3_HEX) == 2972903426   # proof comes first


@pytest.mark.parametrize("other", [
    sign_bundle("1", hex_digest="cd" * 32),                         # signs another image
    sign_bundle("2", predicate_type=CYCLONEDX),                     # an attestation
    {"mediaType": "x", "verificationMaterial": {"tlogEntries": [{"logIndex": "3"}]}},  # no statement
    {"dsseEnvelope": dsse(stmt(SIGN_V1, {}, V3_HEX)), "verificationMaterial": {"tlogEntries": []}},
    "not an object",
], ids=["other-digest", "attestation", "no-dsse", "no-tlog-entry", "not-an-object"])
def test_bundles_that_are_not_this_image_s_logged_signature_are_ignored(other):
    assert signature_log_index(lines(other), V3_HEX) is None
    assert signature_log_index(lines(other, sign_bundle("7")), V3_HEX) == 7


def test_of_several_signatures_the_latest_integrated_time_wins():
    newer, older = sign_bundle("20", integrated="1790502200"), sign_bundle("10", integrated="1790502100")
    assert signature_log_index(lines(newer, older), V3_HEX) == 20
    assert signature_log_index(lines(sign_bundle("30", integrated=None), sign_bundle("31", integrated=None)),
                               V3_HEX) == 31                          # no time: the last line


def test_no_bundles_gives_none(caplog):
    caplog.set_level("INFO", logger="provbind.evidence")
    assert collect(V3_REF, V3_DIGEST, v3_cosign(bundles="")).rekor_log_index is None
    assert "recorded as null" in caplog.text


# --- signing identity ----------------------------------------------------------------------------

def test_commit_comes_from_the_first_entry_that_has_one():
    assert collect(REF, DIGEST, FakeCosign()).source_commit == COMMIT   # entry 0 has only sha256


def test_no_commit_gives_none():
    prov = provenance()
    prov["buildDefinition"]["resolvedDependencies"][1]["digest"] = {"sha1": "x"}
    assert collect(REF, DIGEST, FakeCosign(prov_out=lines(dsse(stmt(SLSA_V1, prov))))).source_commit is None


@pytest.mark.parametrize("commit,expected", [
    ("unknown", None),                   # gen_provenance.py outside a git checkout
    ("", None), ("9f31ab2", None), (12345, None), ("g" * 40, None),
    ("ab" * 32, "ab" * 32),              # a SHA-256 repository
    ("9F31AB2C4D5E6F708192A3B4C5D6E7F8091A2B3C", "9F31AB2C4D5E6F708192A3B4C5D6E7F8091A2B3C"),
])
def test_only_a_commit_hash_is_a_source_commit(commit, expected):
    prov = provenance(commit=commit)
    assert collect(REF, DIGEST, FakeCosign(prov_out=lines(dsse(stmt(SLSA_V1, prov))))).source_commit == expected


def test_a_later_real_commit_beats_an_earlier_unknown():
    prov = provenance()
    prov["buildDefinition"]["resolvedDependencies"].insert(0, {"uri": "git+local", "digest": {"gitCommit": "unknown"}})
    assert collect(REF, DIGEST, FakeCosign(prov_out=lines(dsse(stmt(SLSA_V1, prov))))).source_commit == COMMIT


@pytest.mark.parametrize("builder", [None, "sf9-26/local-build"])
def test_builder_must_be_a_uri(builder):
    prov = provenance(builder=builder)
    with pytest.raises(EvidenceError, match="builder.id"):
        collect(REF, DIGEST, FakeCosign(prov_out=lines(dsse(stmt(SLSA_V1, prov)))))


# --- the real Cosign wrapper, with a fake subprocess.run -----------------------------------------------

def fake_run(returncode=0, stdout="", stderr="", record=None):
    def run(cmd, **kwargs):
        if record is not None:
            record.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)
    return run


def test_cosign_command_lines():
    calls = []
    c = Cosign("pipeline/keys/cosign.pub", run=fake_run(stdout="[]", record=calls))
    c.verify(REF)
    c.verify_attestation(REF, "cyclonedx")
    assert calls == [["cosign", "verify", "--key", "pipeline/keys/cosign.pub", REF],
                     ["cosign", "verify-attestation", "--key", "pipeline/keys/cosign.pub",
                      "--type", "cyclonedx", REF]]


def test_offline_adds_insecure_ignore_tlog():
    calls = []
    Cosign("k.pub", offline=True, run=fake_run(record=calls)).verify(REF)
    assert "--insecure-ignore-tlog=true" in calls[0]


def test_download_signature_command_line():
    calls = []
    assert Cosign("k.pub", run=fake_run(stdout="{}\n", record=calls)).download_signature(REF) == "{}\n"
    assert calls == [["cosign", "download", "signature", REF]]


def test_offline_runs_no_download():
    calls = []
    assert Cosign("k.pub", offline=True, run=fake_run(stdout="{}", record=calls)).download_signature(REF) == ""
    assert calls == []


def test_a_failed_download_is_a_warning_not_an_evidence_error(caplog):
    stderr = "Error: no signatures associated with image\nmain.go:74: error during command execution"
    assert Cosign("k.pub", run=fake_run(1, stderr=stderr)).download_signature(REF) == ""
    assert "no signatures associated with image" in caplog.text

    def slow(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])
    assert Cosign("k.pub", run=slow).download_signature(REF) == ""
    assert "timed out" in caplog.text


def test_cosign_failure_is_an_evidence_error_with_the_reason():
    stderr = "Error: no matching signatures: invalid signature\nmain.go:74: error during command execution: ..."
    with pytest.raises(EvidenceError, match=r"^v_P: cosign verify-attestation --type slsaprovenance1 failed: "
                                            r"no matching signatures: invalid signature$"):
        Cosign("k.pub", run=fake_run(1, stderr=stderr)).verify_attestation(REF, "slsaprovenance1")


def test_cosign_timeout_is_an_evidence_error():
    def run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])
    with pytest.raises(EvidenceError, match="timed out"):
        Cosign("k.pub", run=run).verify(REF)


def test_missing_cosign_binary_is_not_an_evidence_error():
    def run(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])
    with pytest.raises(RuntimeError, match="not found on PATH"):
        Cosign("k.pub", run=run).verify(REF)
