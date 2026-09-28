#!/usr/bin/env python3
"""Print a SLSA v1 provenance *predicate* for an image, in one of two modes.

Build mode, for an image built from a local docker build context (build-and-attest.sh):

    gen_provenance.py --context DIR [--dockerfile PATH] [--builder-id URI]

Re-tag mode, for a public image that was pulled, re-tagged into the local registry and attested
with our key, as Role 1's ML-A corpus profiling does (testbed/profile_corpus.sh, Test Plan §4.1):

    gen_provenance.py --subject REF@sha256:<digest> [--commit SHA] [--source IMAGE] [--builder-id URI]

A re-tagged image was not built here, so nothing is known about its source commit. Its only
resolved dependency is the image itself, with no gitCommit, and the compiler then records the
envelope's source_commit as null. The commit given with --commit is the PROVBIND checkout that
ran the re-tag (Role 1 passes `git rev-parse --short HEAD`, which is expanded to the full SHA);
it goes in internalParameters.harnessCommit and is never passed off as the image's source.

cosign wraps this predicate in an in-toto Statement whose subject is the image
digest (`cosign attest --type slsaprovenance1 --predicate <file> <ref>`).
cosign parses slsaprovenance1 predicates into typed structs, so only the field
names defined by https://slsa.dev/spec/v1.0/provenance are used here; anything
else would be dropped silently. externalParameters and internalParameters are
free-form in SLSA v1, so the keys inside them are kept.
"""
import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import uuid

DEFAULT_BUILDER = "https://github.com/sf9-26/provbind/builders/local@v1"
BUILD_TYPE = "https://github.com/sf9-26/provbind/buildtypes/docker-build@v1"
RETAG_TYPE = "https://github.com/sf9-26/provbind/buildtypes/retag@v1"
REF_BY_DIGEST = re.compile(r"^(?P<repo>[^@\s]+)@sha256:(?P<hex>[0-9a-f]{64})$")


def run(cmd, cwd=None):
    """Return stdout of cmd, or None if it fails or the tool is missing."""
    try:
        out = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else None


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def uncommitted_changes(ctx, dockerfile):
    """True if git sees changes or untracked files in the context or Dockerfile, None if git can't tell."""
    try:
        out = subprocess.run(["git", "status", "--porcelain", "--", ctx, dockerfile],
                             cwd=ctx, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return bool(out.stdout.strip()) if out.returncode == 0 else None


def first_from(dockerfile):
    """Image reference of the first FROM line (handles --platform=... and AS name)."""
    with open(dockerfile, encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split()
            if parts and parts[0].upper() == "FROM":
                args = [p for p in parts[1:] if not p.startswith("--")]
                return args[0] if args else None
    return None


def base_digest(image):
    """sha256 hex of the base image: from a pinned reference, else via `crane digest`."""
    if image is None:
        return None
    m = re.search(r"@sha256:([0-9a-f]{64})$", image)
    if m:
        return m.group(1)
    d = run(["crane", "digest", image])
    return d.split(":", 1)[1] if d and d.startswith("sha256:") else None


def run_details(builder_id, started):
    return {
        "builder": {"id": builder_id},
        "metadata": {"invocationId": str(uuid.uuid4()), "startedOn": started, "finishedOn": utc_now()},
    }


def build_predicate(args, started):
    """Build mode: the image was built from args.context by build-and-attest.sh."""
    ctx = os.path.abspath(args.context)
    dockerfile = args.dockerfile or os.path.join(ctx, "Dockerfile")

    commit = run(["git", "rev-parse", "HEAD"], cwd=ctx)
    repo = run(["git", "config", "--get", "remote.origin.url"], cwd=ctx) or "local"
    if commit is None:
        print("gen_provenance: WARNING: not a git checkout; source commit recorded as 'unknown'",
              file=sys.stderr)
    dirty = uncommitted_changes(ctx, dockerfile) if commit else None
    if dirty:
        print("gen_provenance: WARNING: the build context has uncommitted changes; "
              "the recorded commit is not exactly what was built", file=sys.stderr)

    base = first_from(dockerfile)
    resolved = [{
        "uri": f"git+{repo}",
        "digest": {"gitCommit": commit or "unknown"},
        "name": "source",
    }]
    bd = base_digest(base)
    if base:
        entry = {"uri": f"docker://{base.split('@')[0]}", "name": "base-image"}
        if bd:
            entry["digest"] = {"sha256": bd}
        else:
            print(f"gen_provenance: WARNING: could not resolve a digest for base image {base}",
                  file=sys.stderr)
        resolved.append(entry)

    # internalParameters is free-form in SLSA v1, so cosign's typed struct keeps these keys.
    internal = {"command": "docker build --platform linux/amd64 --provenance=false --sbom=false"}
    if dirty is not None:
        internal["uncommittedChanges"] = dirty

    return {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "repository": repo,
                "context": os.path.relpath(ctx),
                "dockerfile": os.path.relpath(dockerfile),
            },
            "internalParameters": internal,
            "resolvedDependencies": resolved,
        },
        "runDetails": run_details(args.builder_id, started),
    }


def repository(ref_repo):
    """A reference's repository without its tag: localhost:5001/x:latest -> localhost:5001/x."""
    if ":" in ref_repo.rsplit("/", 1)[-1]:
        return ref_repo[:ref_repo.rfind(":")]
    return ref_repo


def full_commit(commit):
    """The full SHA of `commit` in the current checkout, or `commit` as given if git can't resolve it."""
    full = run(["git", "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}"])
    if full is None:
        print(f"gen_provenance: WARNING: cannot resolve commit {commit!r} in this checkout; "
              "recorded as given", file=sys.stderr)
        return commit
    return full


def retag_predicate(args, started):
    """Re-tag mode: a public image re-tagged into the local registry; nothing was built here."""
    subject = args.subject.strip()
    m = REF_BY_DIGEST.match(subject)
    commit = full_commit(args.commit) if args.commit else run(["git", "rev-parse", "HEAD"])
    harness_repo = run(["git", "config", "--get", "remote.origin.url"])

    external = {"image": subject}
    if args.source:
        external["source"] = args.source
    # Free-form in SLSA v1, like build mode's: the PROVBIND checkout that ran the re-tag. It is
    # kept out of resolvedDependencies so the compiler never reads it as the image's source commit.
    internal = {"command": "docker pull, docker tag, docker push (re-tag into the local registry)"}
    if commit:
        internal["harnessCommit"] = commit
    if harness_repo:
        internal["harnessRepository"] = harness_repo

    return {
        "buildDefinition": {
            "buildType": RETAG_TYPE,
            "externalParameters": external,
            "internalParameters": internal,
            # The re-tag's only input is the image itself.
            "resolvedDependencies": [{
                "uri": f"docker://{repository(m['repo'])}",
                "digest": {"sha256": m["hex"]},
                "name": "image",
            }],
        },
        "runDetails": run_details(args.builder_id, started),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--context", help="build mode: the docker build context directory")
    mode.add_argument("--subject", help="re-tag mode: the re-tagged image, <repo>@sha256:<64 hex>")
    ap.add_argument("--dockerfile", help="build mode: default <context>/Dockerfile")
    ap.add_argument("--commit", help="re-tag mode: the PROVBIND commit that ran the re-tag "
                                     "(default: HEAD of the current checkout)")
    ap.add_argument("--source", help="re-tag mode: the public image that was re-tagged, e.g. nginx:1.27")
    ap.add_argument("--builder-id", default=os.environ.get("PROVBIND_BUILDER_ID", DEFAULT_BUILDER),
                    help="URI identifying the builder (SLSA requires a URI)")
    args = ap.parse_args()

    if args.subject is not None:
        if args.dockerfile:
            ap.error("--dockerfile is for build mode (--context), not re-tag mode (--subject)")
        if not REF_BY_DIGEST.match(args.subject.strip()):
            ap.error(f"--subject must be a reference by digest, <repo>@sha256:<64 hex>: {args.subject}")
    elif args.commit is not None or args.source is not None:
        ap.error("--commit and --source are for re-tag mode (--subject); "
                 "build mode reads the commit from the context's git checkout")

    started = utc_now()
    predicate = build_predicate(args, started) if args.subject is None else retag_predicate(args, started)
    json.dump(predicate, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
