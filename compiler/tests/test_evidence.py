"""T3: evidence from canned cosign output (no cosign, no registry)."""
import base64
import json
import subprocess

import pytest

from compiler.evidence import (CYCLONEDX, SLSA_V1, Cosign, EvidenceError, collect, find_log_index,
                               newest_binding, parse_time)

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


VERIFY_V2 = json.dumps([{"critical": {"image": {"docker-manifest-digest": DIGEST}},
                         "optional": {"Bundle": {"SignedEntryTimestamp": "MEU",
                                                 "Payload": {"body": "e30=", "integratedTime": 1758880000,
                                                             "logIndex": 123456789, "logID": "c0d2"}}}}])


class FakeCosign:
    def __init__(self, verify=VERIFY_V2, sbom_out=None, prov_out=None):
        self.calls = []
        self.out = {"verify": verify,
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


def test_a_matching_subject_among_several_binds():
    s = stmt(CYCLONEDX, sbom())
    s["subject"].insert(0, {"name": "other", "digest": {"sha256": "ef" * 32}})
    assert collect(REF, DIGEST, FakeCosign(sbom_out=lines(dsse(s)))).sbom["bomFormat"] == "CycloneDX"


def test_signature_failure_stops_before_the_attestations():
    fake = FakeCosign(verify=EvidenceError("v_sig: cosign verify failed: no signatures found"))
    with pytest.raises(EvidenceError, match="v_sig"):
        collect(REF, DIGEST, fake)
    assert fake.calls == ["verify"]


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
    verify = json.dumps([{"critical": {"image": {"docker-manifest-digest": DIGEST}}, "optional": None}])
    assert collect(REF, DIGEST, FakeCosign(verify=verify)).rekor_log_index is None


# --- signing identity ----------------------------------------------------------------------------

def test_commit_comes_from_the_first_entry_that_has_one():
    assert collect(REF, DIGEST, FakeCosign()).source_commit == COMMIT   # entry 0 has only sha256


def test_no_commit_gives_none():
    prov = provenance()
    prov["buildDefinition"]["resolvedDependencies"][1]["digest"] = {"sha1": "x"}
    assert collect(REF, DIGEST, FakeCosign(prov_out=lines(dsse(stmt(SLSA_V1, prov))))).source_commit is None


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
