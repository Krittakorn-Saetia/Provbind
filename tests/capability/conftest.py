import datetime as dt, json, os, pathlib, pytest

RUN = pathlib.Path(os.environ.get("PROVBIND_RUN", "./run"))


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: needs the cluster, Tetragon or the local registry")


@pytest.fixture
def record_result():
    """Write run/results/<ID>.json in the result.schema.json format."""
    def _write(test_id, status, metrics=None, notes="", artifacts=None, **extra):
        (RUN / "results").mkdir(parents=True, exist_ok=True)
        doc = {"id": test_id, "status": status,
               "finished": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "metrics": metrics or {}, "artifacts": artifacts or [], "notes": notes, **extra}
        (RUN / "results" / f"{test_id}.json").write_text(json.dumps(doc, indent=2))
        return doc
    return _write
