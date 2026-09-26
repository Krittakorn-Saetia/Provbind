#!/usr/bin/env python3
"""Print a SLSA v1 provenance *predicate* for a local docker build.

cosign wraps this predicate in an in-toto Statement whose subject is the image
digest (`cosign attest --type slsaprovenance1 --predicate <file> <ref>`).
cosign parses slsaprovenance1 predicates into typed structs, so only the field
names defined by https://slsa.dev/spec/v1.0/provenance are used here; anything
else would be dropped silently.

usage: gen_provenance.py --context DIR [--dockerfile PATH] [--builder-id URI]
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


def run(cmd, cwd=None):
    """Return stdout of cmd, or None if it fails or the tool is missing."""
    try:
        out = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else None


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


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--context", required=True, help="docker build context directory")
    ap.add_argument("--dockerfile", help="default: <context>/Dockerfile")
    ap.add_argument("--builder-id", default=os.environ.get("PROVBIND_BUILDER_ID", DEFAULT_BUILDER),
                    help="URI identifying the builder (SLSA requires a URI)")
    args = ap.parse_args()

    ctx = os.path.abspath(args.context)
    dockerfile = args.dockerfile or os.path.join(ctx, "Dockerfile")
    started = dt.datetime.now(dt.timezone.utc)

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

    predicate = {
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
        "runDetails": {
            "builder": {"id": args.builder_id},
            "metadata": {
                "invocationId": str(uuid.uuid4()),
                "startedOn": started.isoformat().replace("+00:00", "Z"),
                "finishedOn": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            },
        },
    }
    json.dump(predicate, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
