"""Unit tests for the demo app and its test package (Role 1).

These prove the package is a safe no-op in the source tree (no payload embedded) and that the
attack-2 burst helper behaves, without ever running a real payload.
"""
import importlib
import pathlib
import sys

import pytest

DEMO = pathlib.Path(__file__).resolve().parents[2] / "testbed" / "demo-app"


@pytest.fixture
def demo_modules():
    added = [str(DEMO), str(DEMO / "requestz-helper")]
    for p in added:
        sys.path.insert(0, p)
    # Import fresh so path changes take effect even if a name was seen before.
    for name in ("app", "requestz_helper", "requestz_helper.check", "requestz_helper._payload"):
        sys.modules.pop(name, None)
    app = importlib.import_module("app")
    rh = importlib.import_module("requestz_helper")
    try:
        yield app, rh
    finally:
        for name in ("app", "requestz_helper", "requestz_helper.check", "requestz_helper._payload"):
            sys.modules.pop(name, None)
        for p in added:
            if p in sys.path:
                sys.path.remove(p)


def test_package_version(demo_modules):
    _, rh = demo_modules
    assert rh.__version__ == "0.1.0"


def test_check_update_is_noop_without_payload(demo_modules, tmp_path):
    # Source tree has an empty payload, so check_update must do nothing and drop no file.
    _, rh = demo_modules
    drop = tmp_path / ".x9"
    assert rh.check_update(drop_path=str(drop)) is False
    assert not drop.exists()


def test_cache_burst_writes_and_reads(demo_modules, tmp_path):
    app, _ = demo_modules
    n = app.cache_burst(base_dir=str(tmp_path / ".cache"), n=25, duration=0)
    assert n == 25
    files = list((tmp_path / ".cache").glob("c*.dat"))
    assert len(files) == 25


def test_payload_is_empty_in_source_tree():
    # Guard: the committed payload module must stay empty (no binary/blob in the repo).
    payload = (DEMO / "requestz-helper" / "requestz_helper" / "_payload.py").read_text()
    assert 'PAYLOAD_B64 = ""' in payload


def test_dockerfile_pins_both_stages_to_the_standin_base():
    # Korn's §5.2 step 1: both FROM lines use the stand-in's digest (gen_provenance records the first).
    root = DEMO.parents[1]
    standin = [l.split()[1] for l in (root / "testbed/standin-app/Dockerfile").read_text().splitlines()
               if l.startswith("FROM ")]
    demo = [l.split()[1] for l in (DEMO / "Dockerfile").read_text().splitlines() if l.startswith("FROM ")]
    assert len(demo) == 2 and "@sha256:" in standin[0]
    assert demo == [standin[0], standin[0]]
