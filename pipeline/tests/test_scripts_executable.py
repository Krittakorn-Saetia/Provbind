"""The build script is run as a command (CLAUDE.md, Role 1's Makefile and the handoffs), not
through bash, so git must keep its executable bit. It was lost once, when the file was edited
from Windows (43143f2)."""
import os
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "pipeline" / "build-and-attest.sh"


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX-only")
def test_build_and_attest_is_executable():
    assert os.access(SCRIPT, os.X_OK), f"chmod +x {SCRIPT.name} and git update-index --chmod=+x"
