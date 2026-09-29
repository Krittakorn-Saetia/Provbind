"""T11: envelope assembly, schema validation, atomic write and the CLI's exit codes.

The synthetic image has the stand-in's shape: merged /usr, Python built into /usr/local,
dpkg and pip records, a whiteout, a setuid binary and one package the SBOM does not list.
Layers are plain tar so digests do not depend on the local zlib.

Regenerate the golden file after an intended change, then review its diff:
    PROVBIND_UPDATE_GOLDEN=1 pytest -q compiler/tests/test_compile.py
"""
import copy
import json
import math
import os
import stat
from pathlib import Path

import jsonschema
import pytest

from compiler import oci
from compiler.compile import (EXIT_ERROR, EXIT_EVIDENCE, EXIT_INPUT, EXIT_OK, build_envelope, main, validate,
                              write_atomically)
from compiler.evidence import Evidence
from ml.features import FEATURES_VERSION, feature_names

from .helpers import FakeCosign, FakeRegistry, Tar, image_config, make_elf

GOLDEN = Path(__file__).with_name("golden") / "envelope.json"
REPO = "localhost:5001/standin-app"
NOW = "2026-09-26T00:00:00Z"
COMMIT = "9f31ab2c4d5e6f708192a3b4c5d6e7f8091a2b3c"
BUILDER = "https://github.com/sf9-26/provbind/builders/local@v1"
INTERP = "/lib64/ld-linux-x86-64.so.2"
SITE = "usr/local/lib/python3.11/site-packages"

PURL = {
    "requests": "pkg:pypi/requests@2.32.3",
    "urllib3": "pkg:pypi/urllib3@2.2.2",
    "pip": "pkg:pypi/pip@24.0",
    "coreutils": "pkg:deb/debian/coreutils@9.1-1?arch=amd64&distro=debian-12",
    "dash": "pkg:deb/debian/dash@0.5.12-2?arch=amd64&distro=debian-12",
    "libc6": "pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=debian-12",
    "login": "pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1?arch=amd64&distro=debian-12",
}

STATUS = "".join(f"Package: {n}\nStatus: install ok installed\nArchitecture: amd64\nVersion: {v}\n\n" for n, v in [
    ("coreutils", "9.1-1"), ("dash", "0.5.12-2"), ("libc6", "2.36-9"), ("login", "1:4.13+dfsg1-1"),
    ("unlisted-pkg", "1.0")]).encode()


def dist_info(name, version, files):
    """A pip install of `name`: its files plus METADATA and RECORD."""
    t = Tar()
    info = f"{SITE}/{name}-{version}.dist-info"
    for f in files:
        t.file(f"{SITE}/{f}", f"# {f}\n".encode())
    t.file(f"{info}/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode())
    record = "".join(f"{f},,\n" for f in files) + f"{name}-{version}.dist-info/METADATA,,\n" \
                                                 f"{name}-{version}.dist-info/RECORD,,\n"
    t.file(f"{info}/RECORD", record.encode())
    return t


def push_synthetic(reg):
    base = (Tar().symlink("bin", "usr/bin").symlink("lib", "usr/lib").symlink("lib64", "usr/lib64")
            .dir("etc").dir("etc/ld.so.conf.d")
            .file("etc/passwd", b"root:x:0:0:root:/root:/bin/bash\n")
            .file("etc/ld.so.conf", b"include /etc/ld.so.conf.d/*.conf\n")
            .file("etc/ld.so.conf.d/libc.conf", b"/usr/local/lib\n")
            .file("etc/ld.so.conf.d/x86_64-linux-gnu.conf", b"/lib/x86_64-linux-gnu\n/usr/lib/x86_64-linux-gnu\n")
            .dir("usr").dir("usr/bin").dir("usr/lib").dir("usr/lib/x86_64-linux-gnu").dir("usr/lib64")
            .file("usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", make_elf(), 0o755)
            .file("usr/lib/x86_64-linux-gnu/libc.so.6", make_elf(needed=["ld-linux-x86-64.so.2"]), 0o755)
            .file("usr/lib/x86_64-linux-gnu/libm.so.6", make_elf(needed=["libc.so.6"]), 0o644)
            .symlink("usr/lib64/ld-linux-x86-64.so.2", "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
            .file("usr/bin/dash", make_elf(interp=INTERP, needed=["libc.so.6"]), 0o755)
            .symlink("usr/bin/sh", "dash")
            .file("usr/bin/ls", make_elf(interp=INTERP, needed=["libc.so.6"]), 0o755)
            .file("usr/bin/su", make_elf(interp=INTERP, needed=["libc.so.6"]), 0o4755)
            .dir("usr/share").dir("usr/share/unlisted").file("usr/share/unlisted/data", b"x")
            .dir("tmp").file("tmp/stale", b"left over from the base")
            .dir("var").dir("var/lib").dir("var/lib/dpkg").dir("var/lib/dpkg/info")
            .file("var/lib/dpkg/status", STATUS)
            .file("var/lib/dpkg/info/coreutils.list", b"/.\n/bin\n/bin/ls\n")
            .file("var/lib/dpkg/info/dash.list", b"/bin/dash\n/bin/sh\n")
            .file("var/lib/dpkg/info/libc6:amd64.list", b"/lib/x86_64-linux-gnu/libc.so.6\n"
                  b"/lib/x86_64-linux-gnu/libm.so.6\n/lib64/ld-linux-x86-64.so.2\n")
            .file("var/lib/dpkg/info/login.list", b"/bin/su\n")
            .file("var/lib/dpkg/info/unlisted-pkg.list", b"/usr/share/unlisted/data\n"))
    python = (Tar().dir("usr/local").dir("usr/local/bin").dir("usr/local/lib")
              .file("usr/local/bin/python3.11", make_elf(interp=INTERP, needed=["libpython3.11.so.1.0", "libc.so.6"]), 0o755)
              .symlink("usr/local/bin/python3", "python3.11").symlink("usr/local/bin/python", "python3")
              .file("usr/local/lib/libpython3.11.so.1.0", make_elf(needed=["libm.so.6", "libc.so.6"]), 0o755)
              .extend(dist_info("pip", "24.0", ["pip/__init__.py"])))
    install = (Tar().extend(dist_info("requests", "2.32.3", ["requests/__init__.py", "requests/api.py"]))
               .extend(dist_info("urllib3", "2.2.2", ["urllib3/__init__.py"]))
               .dir("tmp").whiteout("tmp/.wh.stale"))
    app = Tar().dir("app").file("app/app.py", b"import requests\n")
    cfg = image_config(Env=["PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"],
                       ExposedPorts={"8080/tcp": {}})
    return reg.push_image([base, python, install, app], cfg, kind="tar")


SBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"timestamp": "2026-09-26T09:59:00Z"},
    "components": [{"bom-ref": f"{p}&package-id={n}" if "?" in p else f"{p}?package-id={n}",
                    "type": "library", "name": n, "purl": p} for n, p in PURL.items()]
                  + [{"bom-ref": "os:debian@12", "type": "operating-system", "name": "debian", "version": "12"}],
    "dependencies": [],
}
_REF = {c["name"]: c["bom-ref"] for c in SBOM["components"]}
SBOM["dependencies"] = [{"ref": _REF[a], "dependsOn": [_REF[b] for b in bs]}
                        for a, bs in {"requests": ["urllib3"], "coreutils": ["libc6"], "dash": ["libc6"]}.items()]

PROVENANCE = {
    "buildDefinition": {"buildType": "https://github.com/sf9-26/provbind/buildtypes/docker-build@v1",
                        "externalParameters": {}, "internalParameters": {"uncommittedChanges": False},
                        "resolvedDependencies": [{"uri": "git+local", "name": "source", "digest": {"gitCommit": COMMIT}}]},
    "runDetails": {"builder": {"id": BUILDER}, "metadata": {"finishedOn": "2026-09-26T10:00:00Z"}},
}


def evidence_for(digest):
    return Evidence(digest, SBOM, PROVENANCE, BUILDER, COMMIT, 123456789)


@pytest.fixture
def synthetic(tmp_path):
    reg = FakeRegistry()
    digest = push_synthetic(reg)
    return reg, digest, f"{REPO}@{digest}"


@pytest.fixture
def envelope(synthetic, tmp_path):
    reg, digest, ref = synthetic
    image = oci.fetch(ref, str(tmp_path / "cache"), reg)
    env = build_envelope(image, evidence_for(digest), NOW)
    validate(env)
    return env


# --- golden file -------------------------------------------------------------------------------

def test_golden_envelope(envelope):
    env = copy.deepcopy(envelope)
    env.pop("timings_ms")
    if os.environ.get("PROVBIND_UPDATE_GOLDEN") == "1":
        GOLDEN.parent.mkdir(exist_ok=True)
        GOLDEN.write_text(json.dumps(env, indent=2) + "\n")
    assert env == json.loads(GOLDEN.read_text())


# --- what the golden file must say (handoff Section 1, "done when") ----------------------------------

def test_closure_holds_python_libpython_libc_and_the_loader(envelope):
    assert envelope["closure"] == ["/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                                   "/usr/lib/x86_64-linux-gnu/libc.so.6", "/usr/lib/x86_64-linux-gnu/libm.so.6",
                                   "/usr/local/bin/python3.11", "/usr/local/lib/libpython3.11.so.1.0"]


def test_ls_and_dash_are_files_but_not_in_the_closure(envelope):
    for p in ("/usr/bin/ls", "/usr/bin/dash"):
        assert p in envelope["files"] and p not in envelope["closure"]
    assert "/bin/ls" not in envelope["files"]


def test_whited_out_file_is_absent(envelope):
    assert "/tmp/stale" not in envelope["files"]


def test_package_files_are_owned_by_their_purls(envelope):
    files = envelope["files"]
    site = "/" + SITE
    for p in (f"{site}/requests/__init__.py", f"{site}/requests/api.py", f"{site}/requests-2.32.3.dist-info/RECORD"):
        assert files[p]["package"] == PURL["requests"]
    assert files["/usr/bin/ls"]["package"] == PURL["coreutils"]
    assert files["/usr/bin/dash"]["package"] == PURL["dash"]
    assert files["/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"]["package"] == PURL["libc6"]
    assert files["/usr/bin/su"]["package"] == PURL["login"]


def test_unowned_and_unmatched_files_have_null_package(envelope):
    files = envelope["files"]
    for p in ("/app/app.py", "/usr/local/bin/python3.11", "/etc/passwd", "/usr/share/unlisted/data"):
        assert files[p]["package"] is None
    assert {f["package"] for f in files.values()} - {None} <= set(envelope["packages"])


def test_depths_and_unresolved_fraction(envelope):
    depth = {p: v["depth"] for p, v in envelope["packages"].items()}
    assert depth == {PURL["requests"]: 1, PURL["urllib3"]: 2, PURL["coreutils"]: 1, PURL["dash"]: 1,
                     PURL["libc6"]: 2, PURL["pip"]: None, PURL["login"]: None}
    assert envelope["unresolved_fraction"] == pytest.approx(2 / 7)


def test_symlinks_are_real_paths(envelope):
    assert envelope["symlinks"] == {
        "/bin": "/usr/bin", "/lib": "/usr/lib", "/lib64": "/usr/lib64", "/usr/bin/sh": "/usr/bin/dash",
        "/usr/lib64/ld-linux-x86-64.so.2": "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "/usr/local/bin/python": "/usr/local/bin/python3.11", "/usr/local/bin/python3": "/usr/local/bin/python3.11"}


def test_image_fields_layers_modes_and_verification(envelope, synthetic):
    _, digest, ref = synthetic
    assert envelope["image"] == {"ref": ref, "digest": digest, "builder_id": BUILDER,
                                 "source_commit": COMMIT, "rekor_log_index": 123456789}
    assert [l["index"] for l in envelope["layers"]] == [0, 1, 2, 3]
    assert envelope["files"]["/usr/bin/su"]["mode"] == "04755"
    assert envelope["files"]["/app/app.py"]["layer"] == 3
    assert envelope["capabilities"] == []
    assert envelope["verification"] == {"v_sig": True, "v_M": True, "v_C": True, "v_B": True, "v_P": True}
    assert set(envelope["timings_ms"]) >= {"union", "canonicalise", "closure", "sbom", "owners", "caps"}


# --- schema ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("field", ["closure", "files", "image", "unresolved_fraction"])
def test_schema_rejects_a_missing_field(envelope, field):
    broken = copy.deepcopy(envelope)
    del broken[field]
    with pytest.raises(jsonschema.ValidationError):
        validate(broken)


def test_schema_rejects_a_mode_without_leading_zero(envelope):
    broken = copy.deepcopy(envelope)
    broken["files"]["/usr/bin/su"]["mode"] = "4755"
    with pytest.raises(jsonschema.ValidationError):
        validate(broken)


# --- the CLI ----------------------------------------------------------------------------------------

def run_cli(tmp_path, ref, reg, cosign, *extra):
    run = tmp_path / "run"
    code = main([ref, "--run", str(run), "--key", str(tmp_path / "cosign.pub"), *extra], crane=reg, cosign=cosign)
    return code, run


def envelopes(run):
    d = run / "envelopes"
    return sorted(os.listdir(d)) if d.exists() else []


def test_cli_writes_the_envelope_and_prints_its_path(synthetic, tmp_path, capsys):
    reg, digest, ref = synthetic
    code, run = run_cli(tmp_path, ref, reg, FakeCosign(digest, SBOM, PROVENANCE))
    out = capsys.readouterr()
    path = run / "envelopes" / f"{digest.split(':')[1]}.json"
    assert code == EXIT_OK
    assert out.out == f"{path}\n"                       # stdout carries only the path
    assert "[compile]" in out.err
    env = json.loads(path.read_text())
    validate(env)
    assert env["compiled_at"].endswith("Z") and env["closure"]
    assert envelopes(run) == [path.name]                # no temp file left behind
    assert b"\r\n" not in path.read_bytes()             # the same bytes on every OS
    if os.name == "posix":                              # readable by the other roles' processes
        umask = os.umask(0)
        os.umask(umask)
        assert stat.S_IMODE(path.stat().st_mode) == 0o666 & ~umask


def test_write_does_not_need_fchmod(tmp_path, monkeypatch):
    monkeypatch.delattr(os, "fchmod", raising=False)    # Windows before Python 3.13 has none
    path = write_atomically({"a": 1}, str(tmp_path), "sha256:" + "ab" * 32)
    assert json.loads(path.read_text()) == {"a": 1}


def test_failed_write_leaves_no_temp_file(tmp_path):
    with pytest.raises(TypeError):
        write_atomically({"not json": object()}, str(tmp_path), "sha256:" + "ab" * 32)
    assert os.listdir(tmp_path / "envelopes") == []


def test_cli_registry_name_reaches_crane_and_cosign(synthetic, tmp_path, capsys):
    reg, digest, ref = synthetic
    cosign = FakeCosign(digest, SBOM, PROVENANCE)
    code, run = run_cli(tmp_path, ref, reg, cosign, "--registry-name", "10.0.0.5:5001")
    assert code == EXIT_OK
    assert all(r.startswith("10.0.0.5:5001/standin-app@") for r in cosign.refs + [c[1] for c in reg.calls])
    assert json.loads((run / "envelopes" / f"{digest.split(':')[1]}.json").read_text())["image"]["ref"] == ref


def test_cli_reference_not_by_digest_exits_3(synthetic, tmp_path, capsys):
    reg, digest, _ = synthetic
    code, run = run_cli(tmp_path, f"{REPO}:latest", reg, FakeCosign(digest, SBOM, PROVENANCE))
    assert code == EXIT_INPUT and envelopes(run) == []
    assert capsys.readouterr().out == ""


def test_cli_unreachable_registry_exits_3_before_any_evidence(synthetic, tmp_path, capsys):
    _, digest, ref = synthetic
    cosign = FakeCosign(digest, SBOM, PROVENANCE)
    code, run = run_cli(tmp_path, ref, FakeRegistry(), cosign)
    assert code == EXIT_INPUT and envelopes(run) == []
    assert cosign.refs == []                            # the preflight ran first (decision D3)


def test_cli_failed_signature_exits_2_and_writes_nothing(synthetic, tmp_path, capsys):
    reg, digest, ref = synthetic
    code, run = run_cli(tmp_path, ref, reg, FakeCosign(digest, SBOM, PROVENANCE, fail="v_sig: no signatures"))
    assert code == EXIT_EVIDENCE and envelopes(run) == []
    assert "v_sig: no signatures" in capsys.readouterr().err


def test_cli_attested_but_unsigned_image_exits_2(synthetic, tmp_path, capsys):
    reg, digest, ref = synthetic
    code, run = run_cli(tmp_path, ref, reg, FakeCosign(digest, SBOM, PROVENANCE, signed=False))
    assert code == EXIT_EVIDENCE and envelopes(run) == []
    assert "v_sig: cosign verified no image signature" in capsys.readouterr().err


def test_cli_attestation_bound_to_another_image_exits_2(synthetic, tmp_path, capsys):
    reg, digest, ref = synthetic
    cosign = FakeCosign(digest, SBOM, PROVENANCE)
    cosign.out["cyclonedx"] = FakeCosign("sha256:" + "cd" * 32, SBOM, PROVENANCE).out["cyclonedx"]
    code, run = run_cli(tmp_path, ref, reg, cosign)
    assert code == EXIT_EVIDENCE and envelopes(run) == []
    assert "v_B: no verified CycloneDX attestation binds" in capsys.readouterr().err


def test_cli_tampered_layer_exits_2(synthetic, tmp_path, capsys):
    reg, digest, ref = synthetic
    layer = json.loads(reg.manifests[digest])["layers"][1]["digest"]
    reg.blobs[layer] = b"tampered"
    code, run = run_cli(tmp_path, ref, reg, FakeCosign(digest, SBOM, PROVENANCE))
    assert code == EXIT_EVIDENCE and envelopes(run) == []


def test_cli_missing_public_key_exits_3(synthetic, tmp_path, capsys):
    reg, _, ref = synthetic
    code = main([ref, "--run", str(tmp_path / "run"), "--key", str(tmp_path / "nope.pub")], crane=reg)
    assert code == EXIT_INPUT
    assert "public key not found" in capsys.readouterr().err


def test_cli_invalid_envelope_exits_1_and_writes_nothing(synthetic, tmp_path, capsys, monkeypatch):
    reg, digest, ref = synthetic
    import compiler.compile as compile_module
    real = compile_module.build_envelope

    def missing_closure(*args, **kwargs):
        env = real(*args, **kwargs)
        del env["closure"]
        return env
    monkeypatch.setattr(compile_module, "build_envelope", missing_closure)
    code, run = run_cli(tmp_path, ref, reg, FakeCosign(digest, SBOM, PROVENANCE))
    assert code == EXIT_ERROR and envelopes(run) == []
    assert "ValidationError" in capsys.readouterr().err


# --- --features-out: the feature side of dataset D1 (T13 step 3) -----------------------------------

class Recorder:
    """A model that predicts nothing and keeps the features the compiler gives it."""
    theta, vocabulary, seen = 0.5, [], None

    def predict_proba(self, features):
        self.seen = dict(features)
        return {}


def test_the_features_are_the_ones_the_model_is_given(synthetic, tmp_path):
    reg, digest, ref = synthetic
    image = oci.fetch(ref, str(tmp_path / "cache"), reg)
    recorder, features = Recorder(), {}
    env = build_envelope(image, evidence_for(digest), NOW, model=recorder, features=features)
    row = features["features"]
    assert row == {k: None if math.isnan(v) else v for k, v in recorder.seen.items()}
    assert list(row) == list(feature_names())                   # the 46 fixed features, in order
    assert row["cfg.exposed_ports"] == 1.0 and row["clo.size"] == len(env["closure"]) == 5
    assert row["dep.privileged"] == row["dep.caps_added"] == row["dep.caps_dropped"] == 0.0   # the default pod
    assert "features" in env["timings_ms"]


def test_without_the_flag_there_is_no_features_step(envelope):
    assert "features" not in envelope["timings_ms"]


def test_cli_features_out_appends_one_line_per_compile(synthetic, tmp_path, capsys):
    reg, digest, ref = synthetic
    out = tmp_path / "ml" / "data" / "features.jsonl"
    for _ in range(2):
        code, run = run_cli(tmp_path, ref, reg, FakeCosign(digest, SBOM, PROVENANCE), "--features-out", str(out))
        assert code == EXIT_OK
    assert "features appended" in capsys.readouterr().err
    lines = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2 and lines[0] == lines[1]
    row = lines[0]
    env = json.loads((run / "envelopes" / f"{digest.split(':')[1]}.json").read_text())
    assert (row["digest"], row["ref"], row["features_version"]) == (digest, ref, FEATURES_VERSION)
    assert row["packages"] == sorted(env["packages"])
    assert row["exposed_ports"] == ["8080/tcp"]
    assert list(row["features"]) == list(feature_names())


def test_cli_features_out_writes_nothing_when_the_evidence_fails(synthetic, tmp_path, capsys):
    reg, digest, ref = synthetic
    out = tmp_path / "features.jsonl"
    code, _ = run_cli(tmp_path, ref, reg, FakeCosign(digest, SBOM, PROVENANCE, fail="v_sig: no signatures"),
                      "--features-out", str(out))
    assert code == EXIT_EVIDENCE and not out.exists()


def test_cli_failed_features_append_writes_no_envelope(synthetic, tmp_path, capsys):
    reg, digest, ref = synthetic
    (tmp_path / "a-file").write_text("")
    code, run = run_cli(tmp_path, ref, reg, FakeCosign(digest, SBOM, PROVENANCE),
                        "--features-out", str(tmp_path / "a-file" / "features.jsonl"))
    assert code == EXIT_ERROR and envelopes(run) == []
