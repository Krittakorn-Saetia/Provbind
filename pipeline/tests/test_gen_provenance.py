"""T1: gen_provenance.py prints a SLSA v1 predicate. No Docker or network needed:
the Dockerfiles pin the base image by digest, so the generator never calls crane.

Build mode (--context) is what build-and-attest.sh runs; re-tag mode (--subject) is what Role 1's
testbed/profile_corpus.sh runs for the ML-A corpus images."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from compiler.evidence import signing_identity

GEN = Path(__file__).resolve().parents[1] / "gen_provenance.py"
BASE_HEX = "ab" * 32
DOCKERFILE = f"FROM --platform=linux/amd64 python:3.11-slim@sha256:{BASE_HEX} AS base\nCOPY app.py .\n"
SUBJECT_HEX = "cd" * 32
SUBJECT = f"localhost:5001/nginx_1.27@sha256:{SUBJECT_HEX}"
DEFAULT_BUILDER = "https://github.com/sf9-26/provbind/builders/local@v1"

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
    assert out.returncode == 0 and "--context" in out.stdout and "--subject" in out.stdout


# --- re-tag mode ---------------------------------------------------------------------------------

def retag(cwd, *args, check=True):
    """Run the generator in `cwd`, as profile_corpus.sh does from the repository root."""
    env = {k: v for k, v in os.environ.items() if k != "PROVBIND_BUILDER_ID"}
    env["GIT_CEILING_DIRECTORIES"] = str(Path(cwd).parent)   # never pick up an enclosing checkout
    return subprocess.run([sys.executable, str(GEN), *args], cwd=cwd, capture_output=True, text=True,
                          check=check, env=env)


@needs_git
def test_retag_mode_accepts_role1s_profiling_call(context):
    """testbed/profile_corpus.sh: gen_provenance.py --subject "$ref" --commit "$(git rev-parse --short HEAD)"."""
    head = commit_all(context)
    pred = json.loads(retag(context, "--subject", SUBJECT, "--commit", head[:7]).stdout)
    bd = pred["buildDefinition"]
    assert bd["buildType"] == "https://github.com/sf9-26/provbind/buildtypes/retag@v1"
    assert bd["externalParameters"] == {"image": SUBJECT}
    assert bd["resolvedDependencies"] == [{"uri": "docker://localhost:5001/nginx_1.27", "name": "image",
                                           "digest": {"sha256": SUBJECT_HEX}}]
    assert bd["internalParameters"]["harnessCommit"] == head          # the short SHA, expanded
    assert pred["runDetails"]["builder"]["id"] == DEFAULT_BUILDER
    assert set(pred) == {"buildDefinition", "runDetails"}           # the same SLSA v1 shape as build mode
    assert set(pred["runDetails"]["metadata"]) == {"invocationId", "startedOn", "finishedOn"}


@needs_git
def test_retag_names_no_source_commit_so_the_compiler_records_null(context):
    """The harness commit is not the image's source: the compiler must not read it as one."""
    commit_all(context)
    pred = json.loads(retag(context, "--subject", SUBJECT).stdout)
    assert pred["buildDefinition"]["internalParameters"]["harnessCommit"]   # HEAD, by default
    assert not any("gitCommit" in d["digest"] for d in pred["buildDefinition"]["resolvedDependencies"])
    assert signing_identity(pred) == (DEFAULT_BUILDER, None)


def test_retag_strips_a_tag_from_the_dependency_uri(tmp_path):
    subject = f"localhost:5001/nginx_1.27:latest@sha256:{SUBJECT_HEX}"
    pred = json.loads(retag(tmp_path, "--subject", subject).stdout)
    assert pred["buildDefinition"]["resolvedDependencies"][0]["uri"] == "docker://localhost:5001/nginx_1.27"


def test_retag_records_the_source_image(tmp_path):
    pred = json.loads(retag(tmp_path, "--subject", SUBJECT, "--source", "nginx:1.27").stdout)
    assert pred["buildDefinition"]["externalParameters"] == {"image": SUBJECT, "source": "nginx:1.27"}


def test_retag_outside_git_records_the_commit_as_given(tmp_path):
    out = retag(tmp_path, "--subject", SUBJECT, "--commit", "abc1234")
    assert json.loads(out.stdout)["buildDefinition"]["internalParameters"]["harnessCommit"] == "abc1234"
    assert "cannot resolve commit" in out.stderr


def test_retag_outside_git_without_a_commit_records_none(tmp_path):
    internal = json.loads(retag(tmp_path, "--subject", SUBJECT).stdout)["buildDefinition"]["internalParameters"]
    assert "harnessCommit" not in internal and "harnessRepository" not in internal


@pytest.mark.parametrize("args, message", [
    (["--subject", "localhost:5001/nginx_1.27:latest"], "reference by digest"),
    (["--subject", SUBJECT, "--context", "."], "not allowed with"),
    (["--subject", SUBJECT, "--dockerfile", "Dockerfile"], "build mode"),
    (["--context", ".", "--commit", "abc1234"], "re-tag mode"),
    (["--context", ".", "--source", "nginx:1.27"], "re-tag mode"),
    ([], "one of the arguments"),
])
def test_bad_arguments_exit_2_and_print_nothing(tmp_path, args, message):
    out = retag(tmp_path, *args, check=False)
    assert out.returncode == 2 and message in out.stderr and out.stdout == ""
