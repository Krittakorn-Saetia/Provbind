"""T1: gen_provenance.py prints a SLSA v1 predicate. No Docker or network needed:
the Dockerfiles pin the base image by digest, so the generator never calls crane."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

GEN = Path(__file__).resolve().parents[1] / "gen_provenance.py"
BASE_HEX = "ab" * 32
DOCKERFILE = f"FROM --platform=linux/amd64 python:3.11-slim@sha256:{BASE_HEX} AS base\nCOPY app.py .\n"

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def context(tmp_path):
    ctx = tmp_path / "app"
    ctx.mkdir()
    (ctx / "Dockerfile").write_text(DOCKERFILE)
    (ctx / "app.py").write_text("print('hi')\n")
    return ctx


def generate(ctx):
    env = {k: v for k, v in os.environ.items() if k != "PROVBIND_BUILDER_ID"}
    env["GIT_CEILING_DIRECTORIES"] = str(ctx.parent)   # never pick up an enclosing checkout
    out = subprocess.run([sys.executable, str(GEN), "--context", str(ctx)],
                         capture_output=True, text=True, check=True, env=env)
    return json.loads(out.stdout), out.stderr


def commit_all(ctx):
    git(ctx, "init", "-q")
    git(ctx, "add", ".")
    git(ctx, "commit", "-q", "-m", "init")
    return git(ctx, "rev-parse", "HEAD")


@needs_git
def test_predicate_has_the_fields_t1_checks(context):
    head = commit_all(context)
    pred, _ = generate(context)
    bd = pred["buildDefinition"]
    assert bd["buildType"] == "https://github.com/sf9-26/provbind/buildtypes/docker-build@v1"
    assert bd["resolvedDependencies"][0]["digest"]["gitCommit"] == head
    assert pred["runDetails"]["builder"]["id"] == "https://github.com/sf9-26/provbind/builders/local@v1"


@needs_git
def test_pinned_base_image_is_recorded_without_crane(context):
    commit_all(context)
    pred, _ = generate(context)
    base = pred["buildDefinition"]["resolvedDependencies"][1]
    assert base == {"uri": "docker://python:3.11-slim", "name": "base-image",
                    "digest": {"sha256": BASE_HEX}}


@needs_git
def test_clean_tree_records_no_uncommitted_changes(context):
    commit_all(context)
    pred, err = generate(context)
    assert pred["buildDefinition"]["internalParameters"]["uncommittedChanges"] is False
    assert "uncommitted" not in err


@needs_git
@pytest.mark.parametrize("change", ["modified", "untracked"])
def test_uncommitted_changes_are_recorded_and_warned(context, change):
    commit_all(context)
    if change == "modified":
        (context / "app.py").write_text("print('changed')\n")
    else:
        (context / "extra.txt").write_text("new\n")
    pred, err = generate(context)
    assert pred["buildDefinition"]["internalParameters"]["uncommittedChanges"] is True
    assert "uncommitted changes" in err


def test_not_a_git_checkout_records_unknown_commit(context):
    pred, err = generate(context)
    assert pred["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] == "unknown"
    assert "uncommittedChanges" not in pred["buildDefinition"]["internalParameters"]
    assert "not a git checkout" in err


def test_help_exits_zero():
    out = subprocess.run([sys.executable, str(GEN), "--help"], capture_output=True, text=True)
    assert out.returncode == 0 and "--context" in out.stdout
