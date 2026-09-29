"""Guard tests for ml/corpus.yaml, the ML-A profiling corpus D1 (Test Plan §4.1, Role 1)."""
import pathlib

import pytest

yaml = pytest.importorskip("yaml")

CORPUS = pathlib.Path(__file__).resolve().parents[2] / "ml" / "corpus.yaml"


def _load():
    with open(CORPUS, encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_corpus_parses_and_is_a_list():
    entries = _load()
    assert isinstance(entries, list) and all(isinstance(e, dict) for e in entries)


def test_corpus_has_at_least_20_images():
    # Test Plan §4.7: 20 images minimum for a feasibility result (target 40).
    assert len(_load()) >= 20


def test_every_entry_names_an_image():
    for e in _load():
        assert e.get("image"), f"entry without image: {e}"


def test_images_are_unique():
    images = [e["image"] for e in _load()]
    assert len(images) == len(set(images)), "duplicate image in corpus"


def test_ports_are_ints_when_present():
    for e in _load():
        if "port" in e:
            assert isinstance(e["port"], int), f"non-int port in {e['image']}"


def test_workload_references_host_placeholder_when_it_uses_the_service():
    # A workload that hits {host} is fine; an empty workload (no server) is fine too. Guard against
    # a workload that mentions a hard-coded host instead of the {host} placeholder.
    for e in _load():
        w = e.get("workload", "")
        if w and "curl" in w and "http://" in w:
            assert "{host}" in w, f"{e['image']} workload should use the {{host}} placeholder"


def test_includes_our_own_images():
    images = {e["image"] for e in _load()}
    assert "localhost:5001/standin-app" in images
    assert "localhost:5001/demo-app" in images
