# demo-app (Role 1)

The signed application the PROVBIND demo deploys, and the harmless test package that stands in for
a compromised dependency. **Everything here is harmless test code and runs only inside the throwaway
demo container** (Test Plan §7, Sprint Handoff §5). No real malware is used anywhere in PROVBIND.

## Layout

| Path | What it is |
|---|---|
| `app.py` | HTTP server on 8080: `/` and `/healthz` return `ok`; `/update` triggers attack-1; `/update2` triggers attack-2 |
| `requestz-helper/` | The test package (`pkg:pypi/requestz-helper@0.1.0`), installed from local source only |
| `requestz-helper/requestz_helper/check.py` | `check_update()`: drops the base64 payload to `/tmp/.x9`, runs it (attack-1) |
| `requestz-helper/requestz_helper/_payload.py` | Empty in git; the build embeds the compiled payload here as base64 |
| `x9.c` | The payload source: appends one inert marker to `/etc/passwd`, then sleeps |
| `gen_payload.sh` | Compiles `x9.c` statically and embeds it into `_payload.py` (run by the Dockerfile) |
| `Dockerfile` | Two-stage build: compile + embed the payload, then install the package and run the app |

## What each scenario shows

- **attack-1 (`/update`)** — `check_update()` writes the embedded payload to `/tmp/.x9` and runs it.
  `/tmp/.x9` is in no image layer, so PROVBIND raises **D_exec undeclared**; the payload's write to
  `/etc/passwd` raises **D_write**. Both share one chain (E2E-01).
- **attack-2 (`/update2`)** — 300 new files are written under `/tmp/.cache` and read back, using only
  declared binaries. No deterministic rule fires; ML-B should raise **D_beh** (E2E-03, MLB-05).

## Why the payload is embedded, not committed

The repo carries only `x9.c` (harmless source) and an empty `_payload.py`. The image build compiles
`x9.c` and base64-encodes it into `_payload.py`, so the payload lives inside a `.py` and never exists
as a file in the image. Its dropped hash is therefore new, which is why PROVBIND reports `/tmp/.x9`
as **undeclared** rather than **relocated** (Sprint Handoff §5). Real droppers behave the same way.

## Build (demo PC)

```bash
pipeline/build-and-attest.sh testbed/demo-app demo-app      # or: make demo-app
```

Pin the base image by digest first (see the Dockerfile header), or the envelope changes between runs.
`requestz-helper` is installed with `pip install --no-index ./requestz-helper`; it is fictional on
PyPI and must never be fetched from there.
