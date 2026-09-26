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
