# compiler/: rules for this folder

- The spec is `docs/ROLE2-HANDOFF.md`: tasks T3–T11, algorithms in Section 7. Follow the algorithms exactly. The layer union must be two-pass per layer (Section 7.1).
- Evidence comes only through cosign verification (`evidence.py`). Never parse the debug files in `run/attest/` from compiler code.
- Every envelope is validated against `contracts/envelope.schema.json` before it is written, and written atomically.
- Exit codes: 0 written · 1 unexpected error · 2 evidence failed verification or binding (write nothing) · 3 bad input.
- Unit tests build their own fixtures (`tarfile`, `io.BytesIO`, small dicts) and must not need Docker or the network.
- Standard library first. Allowed extras: pyelftools, zstandard, packageurl-python, jsonschema.
- When image or packaging behaviour is unclear, write a failing test that captures the case before changing code.
