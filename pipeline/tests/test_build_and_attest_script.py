"""build-and-attest.sh with fake docker, crane, syft and cosign first on PATH. Checks the
flags each tool receives and that stdout carries only the reference. Needs bash and jq,
not Docker; nothing is built, pushed or signed."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "pipeline" / "build-and-attest.sh"
DIGEST = "sha256:" + "cd" * 32

pytestmark = pytest.mark.skipif(not (shutil.which("bash") and shutil.which("jq")),
                                reason="needs bash and jq")

FAKE_TOOL = r"""#!/usr/bin/env bash
echo "$(basename "$0") $*" >> "$FAKE_LOG"
case "$(basename "$0") $1" in
  "crane digest") echo "%s" ;;
  syft\ *) echo '{"components":[],"dependencies":[{"ref":"a","dependsOn":["b"]}]}' ;;
  "cosign verify") echo '[{}]' ;;
esac
""" % DIGEST


def run_script(tmp_path, offline):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("docker", "crane", "syft", "cosign"):
        fake = bin_dir / tool
        fake.write_text(FAKE_TOOL)
        fake.chmod(0o755)
    log = tmp_path / "tools.log"
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}", FAKE_LOG=str(log),
               PROVBIND_RUN=str(tmp_path / "run"), PROVBIND_REGISTRY="localhost:5001",
               COSIGN_KEY=str(tmp_path / "cosign.key"), COSIGN_PASSWORD="")
    env.pop("PROVBIND_OFFLINE", None)
    if offline:
        env["PROVBIND_OFFLINE"] = "1"
    out = subprocess.run(["bash", str(SCRIPT), "testbed/standin-app", "standin-app"],
                         cwd=ROOT, env=env, capture_output=True, text=True)
    return out, log.read_text().splitlines()


@pytest.mark.parametrize("offline", [False, True], ids=["online", "offline"])
def test_flags_reach_the_tools(tmp_path, offline):
    out, calls = run_script(tmp_path, offline)
    assert out.returncode == 0, out.stderr
    assert out.stdout == f"localhost:5001/standin-app@{DIGEST}\n"

    build = next(c for c in calls if c.startswith("docker build"))
    assert "--platform linux/amd64 --provenance=false --sbom=false" in build

    signing = [c for c in calls if c.startswith(("cosign sign", "cosign attest"))]
    verifying = [c for c in calls if c.startswith("cosign verify")]
    assert len(signing) == 3 and len(verifying) == 3
    assert all(("--tlog-upload=false" in c) == offline for c in signing)
    assert all(("--insecure-ignore-tlog=true" in c) == offline for c in verifying)
    assert all(c.endswith(f"localhost:5001/standin-app@{DIGEST}") for c in signing + verifying)


def test_refuses_to_run_without_cosign_password(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "COSIGN_PASSWORD"}
    out = subprocess.run(["bash", str(SCRIPT), "testbed/standin-app", "standin-app"],
                         cwd=ROOT, env=env, capture_output=True, text=True)
    assert out.returncode == 64 and "COSIGN_PASSWORD" in out.stderr and out.stdout == ""
