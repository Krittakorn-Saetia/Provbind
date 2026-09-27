# PROVBIND prototype: rules for Claude Code

Team repo for the SF9-26 PROVBIND 4-day prototype. Four roles share it. The team plan is the sprint handoff; per-role specs live in `docs/`.

## Rules for every role
- Files in `contracts/` are frozen. Never change a contract, or the shape of any file in the run folder, without the team agreeing. If a change looks necessary, stop and say so.
- Paths inside containers are real absolute paths with symlinks resolved: `/usr/bin/ls`, not `/bin/ls`.
- Parts communicate only through files in `$PROVBIND_RUN` (default `./run`). JSONL files are append-only; whole-file outputs go to a temp file that is then renamed.
- Python 3.11. Tests use pytest; tests that need Docker or the cluster are marked `integration`.
- Never read, print or commit private keys (`pipeline/keys/*.key`). Never commit `./run`.
- stdout is for machine-readable output; logs go to stderr.

## Role 2 (pipeline/, compiler/)
Before working in `pipeline/` or `compiler/`, read `docs/ROLE2-HANDOFF.md`. It holds the tasks, algorithms and tests.

## Commands
- Unit tests: `pytest -q`
- Integration tests (Docker and the local registry): `pytest -q -m integration`
- Build and attest one image: `pipeline/build-and-attest.sh <context-dir> <name>`
- Compile an envelope: `python -m compiler.compile <ref@digest> --run $PROVBIND_RUN`

## Capability tests
- The plan is `docs/PROVBIND-Capability-Test-Plan.md`; every test ID is in `tests/capability/registry.json`.
- Record each result with the `record_result` fixture (`tests/capability/conftest.py`). A `fail` or `blocked` result needs a note explaining why.

## Claude Code on the web
- In cloud sessions, run `pytest -m "not integration"`. Tests marked `integration` need Docker, kind, Tetragon or the local registry and run on the demo PC. Do not try to install or start a Kubernetes cluster or eBPF tooling in the cloud sandbox.
- If a download or network call is blocked, stop and report which host was blocked instead of working around it.
- The environment setup script is `scripts/cloud-setup.sh`.

## Documents
- Start with `README.md`.
- `docs/reference/` is read-only: never edit Aj Ohm's draft or our older drafts. Changes to the paper are proposed in the test plan's update log (Section 10).
- Never download, extract or commit real malicious package samples (test plan §12.4).
