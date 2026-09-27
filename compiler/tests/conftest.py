import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: needs Docker and the local registry at localhost:5001")


@pytest.fixture(autouse=True)
def allowlist_capabilities(request, monkeypatch):
    """Unit tests compile with the curated allowlist unless they load a model themselves, so a
    model trained into ml/model/ on this machine cannot change their results. Integration tests
    are left alone."""
    if request.node.get_closest_marker("integration") is None:
        monkeypatch.setenv("PROVBIND_CAPS_MODEL", "none")
