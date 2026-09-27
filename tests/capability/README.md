# Capability tests

The plan is `docs/PROVBIND-Capability-Test-Plan.md`; every test ID is listed in `registry.json`.

1. **One pytest file per test ID or small group** (for example `test_ph4_05_undeclared_exec.py`). Mark tests that need the cluster with `@pytest.mark.integration`.
2. **Record a result** from each test with the `record_result` fixture (`conftest.py`). It writes `run/results/<ID>.json` in the `result.schema.json` format. A `fail` or `blocked` result needs a note explaining it.
3. **Build the report** with `python -m eval.report`, which writes `run/results/REPORT.md`. Tests without a result appear as `not_run`.

`test_cf_reference_example.py` shows the pattern with the reference cuckoo filter. On synthetic paths it records `not_run`; set `PROVBIND_ENVELOPE=run/envelopes/<digest>.json` to run CF-01 and CF-02 for real.
