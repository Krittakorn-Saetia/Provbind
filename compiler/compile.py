"""T11: compile one image's envelope (handoff T11).

    python -m compiler.compile <ref@digest> --run $PROVBIND_RUN [--key pipeline/keys/cosign.pub]
                               [--registry-name HOST]

preflight -> evidence -> fetch -> union -> canonicalise -> closure -> SBOM -> owners -> caps
-> assemble. The envelope is validated against contracts/envelope.schema.json and written
atomically to <run>/envelopes/<digest-hex>.json. stdout carries only that path; progress
and timings go to stderr.

Capabilities come from the ML-A model in ml/model/ when there is one, otherwise from the
curated allowlist; PROVBIND_CAPS_MODEL names another model directory, or "none" for the
allowlist (compiler/caps.py).

Exit codes: 0 written; 1 unexpected error; 2 evidence failed verification or binding, or a
manifest, config or blob hash mismatch; 3 bad input (not by digest, registry unreachable,
image missing, not linux/amd64, no public key, an ML-A model that cannot be used). No
envelope is written unless the exit is 0. Layer blobs that pass their hash check stay in
<run>/cache/blobs (T4) whatever the exit; a download that fails its check is deleted, and a
cached blob is checked again before every reuse.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from . import caps, closure, evidence, layers, oci, owners, paths, sbom

log = logging.getLogger("provbind.compile")

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "contracts" / "envelope.schema.json"
SCHEMA_VERSION = "provbind.envelope/v0"
EXIT_OK, EXIT_ERROR, EXIT_EVIDENCE, EXIT_INPUT = 0, 1, 2, 3


@contextmanager
def timed(timings: dict, step: str):
    start = time.perf_counter()
    try:
        yield
    finally:
        timings[step] = round((time.perf_counter() - start) * 1000, 1)
        log.info("%-12s %8.1f ms", step, timings[step])


def build_envelope(image: oci.Image, ev: evidence.Evidence, compiled_at: str,
                   timings: dict | None = None, model=None) -> dict:
    """Everything after the network: union, canonicalise, closure, SBOM, owners, caps,
    assemble. Reads only the verified blobs on disk. `model` is the ML-A model from
    caps.load_model; without one the allowlist decides."""
    timings = {} if timings is None else timings
    with timed(timings, "union"):
        u = layers.union(image.layers)
    with u:
        with timed(timings, "canonicalise"):
            c = paths.canonicalise(u.files, u.links, u.dirs, u.link_layers)
            fs = u.replace(files=c.files, links=c.links, dirs=c.dirs, link_layers=c.link_layers)
            symlinks = paths.resolve_links(fs.links, fs.files, fs.dirs)
        with timed(timings, "closure"):
            reachable = closure.closure(image.config, fs)
        with timed(timings, "sbom"):
            packages, unresolved = sbom.depths(ev.sbom)
        with timed(timings, "owners"):
            package_of = owners.match(owners.owners(fs.files, fs.links, fs.read), packages)
        with timed(timings, "caps"):                  # no 𝒞_K8s cap: the pod is unknown here
            capabilities = caps.for_image(packages, image.config, reachable, fs, model)
    log.info("%d files, %d symlinks, %d in the closure, %d packages (%.0f%% unresolved)",
             len(fs.files), len(symlinks), len(reachable), len(packages), 100 * unresolved)

    return {
        "schema": SCHEMA_VERSION,
        "image": {"ref": image.ref, "digest": image.digest, "builder_id": ev.builder_id,
                  "source_commit": ev.source_commit, "rekor_log_index": ev.rekor_log_index},
        "layers": [{"index": l.index, "digest": l.digest,
                    **({"media_type": l.media_type} if l.media_type else {})} for l in image.layers],
        "files": {p: {"sha256": e.sha256, "layer": e.layer, "package": package_of.get(p), "mode": e.mode}
                  for p, e in sorted(fs.files.items())},
        "symlinks": dict(sorted(symlinks.items())),
        "closure": reachable,
        "packages": dict(sorted(packages.items())),
        "capabilities": capabilities,
        "unresolved_fraction": unresolved,
        "compiled_at": compiled_at,
        "verification": {"v_sig": ev.verification["v_sig"], "v_M": image.verification["v_M"],
                         "v_C": image.verification["v_C"], "v_B": ev.verification["v_B"],
                         "v_P": ev.verification["v_P"]},
        "timings_ms": timings,
    }


def validate(envelope: dict) -> None:
    """Raise jsonschema.ValidationError unless the envelope matches the contract."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(envelope)


def write_atomically(envelope: dict, run_dir: str, digest: str) -> Path:
    """<run>/envelopes/<digest-hex>.json via a temp file and a rename, so readers never see
    half a file. The temp name does not end in .json, so a *.json glob never picks it up.

    The temp file is always closed before it is renamed or removed, which Windows requires.
    open(..., "x") creates it with the usual 0666 & ~umask, so other roles can read it
    (mkstemp would make it 0600), and newline="\\n" keeps the bytes the same on every OS.
    """
    out_dir = Path(run_dir) / "envelopes"
    out_dir.mkdir(parents=True, exist_ok=True)
    hex_digest = digest.split(":", 1)[1]
    final = out_dir / f"{hex_digest}.json"
    tmp = out_dir / f".{hex_digest}.{os.getpid()}.{secrets.token_hex(4)}.json.tmp"
    try:
        with open(tmp, "x", encoding="utf-8", newline="\n") as f:
            json.dump(envelope, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, final)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return final


def compiled_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compile_image(ref: str, run_dir: str, key: str, registry_name: str | None = None,
                  crane=None, cosign=None, now: str | None = None) -> Path:
    """The whole pipeline; returns the envelope path. Raises BadInput, EvidenceError,
    IntegrityError or anything unexpected; writes no envelope unless it returns (verified
    blobs may stay in the cache)."""
    timings: dict[str, float] = {}
    repo, digest = oci.parse_ref(ref)
    if cosign is None and not os.path.isfile(key):
        raise oci.BadInput(f"public key not found: {key}")
    model = caps.load_model(caps.model_dir())          # before any network work
    crane = crane or oci.Crane()
    cosign = cosign or evidence.Cosign(key, offline=os.environ.get("PROVBIND_OFFLINE") == "1")
    fetch_ref = f"{oci.with_registry(repo, registry_name)}@{digest}"

    with timed(timings, "preflight"):
        raw_manifest = oci.preflight(ref, crane, registry_name)
    with timed(timings, "evidence"):
        ev = evidence.collect(fetch_ref, digest, cosign)
    log.info("verified: signature, CycloneDX and SLSA attestations; builder %s, commit %s, Rekor %s",
             ev.builder_id, ev.source_commit, ev.rekor_log_index)
    with timed(timings, "fetch"):
        image = oci.fetch(ref, os.path.join(run_dir, "cache", "blobs"), crane, registry_name, raw_manifest)
    envelope = build_envelope(image, ev, now or compiled_now(), timings, model)
    with timed(timings, "validate"):
        validate(envelope)
    return write_atomically(envelope, run_dir, digest)


class _Formatter(logging.Formatter):
    def format(self, record):
        prefix = "" if record.levelno < logging.WARNING else record.levelname + ": "
        return f"[compile] {prefix}{record.getMessage()}"


def main(argv: list[str] | None = None, crane=None, cosign=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m compiler.compile", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ref", help="image reference by digest: <registry>/<name>@sha256:<64 hex>")
    ap.add_argument("--run", default=os.environ.get("PROVBIND_RUN", "./run"), help="run folder (default $PROVBIND_RUN or ./run)")
    ap.add_argument("--key", default="pipeline/keys/cosign.pub", help="cosign public key")
    ap.add_argument("--registry-name", help="registry host to fetch from instead of the reference's own")
    args = ap.parse_args(argv)

    logger = logging.getLogger("provbind")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_Formatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    started = time.perf_counter()
    try:
        path = compile_image(args.ref, args.run, args.key, args.registry_name, crane, cosign)
    except evidence.EvidenceError as e:
        log.error("evidence failed: %s; no envelope written", e)
        return EXIT_EVIDENCE
    except oci.IntegrityError as e:
        log.error("integrity check failed: %s; no envelope written", e)
        return EXIT_EVIDENCE
    except oci.BadInput as e:
        log.error("bad input: %s", e)
        return EXIT_INPUT
    except Exception as e:                                  # anything else is our bug or the host's
        log.error("unexpected error: %s: %s", type(e).__name__, e)
        return EXIT_ERROR
    finally:
        logger.removeHandler(handler)
    print(path)
    print(f"[compile] wrote {path} in {time.perf_counter() - started:.1f} s", file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
