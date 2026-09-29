# Role 1 session notes, 28 September 2026

What Claude Code (cloud) built for **Role 1 — Testbed and evaluation** in this session. It covers
the code and scripts added, how they map to Role 1's tasks and tests, how to run them, and what
still needs the demo PC.

Branch: `claude/zen-hypatia-pyrg25`. Commits:
- `Role 1: evaluation harness, ML-A profiling, scenarios and capability tests`
- `Role 1: demo app and the requestz-helper test package`
- this notes file.

Rules kept: no cluster, Docker, kind, Tetragon or Falco was started in the cloud (only
`pytest -m "not integration"`); `contracts/` and `docs/reference/` were not touched; no key or
`run/` folder was committed; no real malicious sample was downloaded (Test Plan §12.4).

---

## 1. What Role 1 owns, and where it stands

Role 1 owns the demo PC, the demo app and its test package, the scenarios, Falco capture, the
comparison table, and the ML-A corpus profiling (Sprint Handoff §5). Role 1's tests (owner R1):
P0 — MLA-03, E2E-01 to 03, E2E-11, E2E-12, EV-01; plus the CF and other R1 tests in `registry.json`.

Everything that runs without the cluster is done and tested in the cloud. Everything that needs the
cluster is written and ready to run on the demo PC.

| Area | Deliverable | State |
|---|---|---|
| Demo app | `testbed/demo-app/` (app, `requestz-helper`, `x9.c`, Dockerfile) | Done; hand to Role 2 |
| Evaluation | `eval/compare.py`, `eval/ground_truth.py`, `eval/capture_falco.sh` | Done, unit-tested |
| ML-A corpus (D1) | `ml/corpus.yaml` (24 images) | Done |
| Profiling (MLA-03) | `testbed/profiling/`, `testbed/profile_corpus.sh` | Label maths done + tested; capture runs on the PC |
| Scenarios | `testbed/scenarios/{benign,attack,attack2,trust,tamper}.sh` + `lib.sh` | Done; run on the PC |
| Cluster bootstrap | `testbed/kind-with-registry.sh`, root `Makefile` | Done; run on the PC |
| Capability tests | CF-03/04/06, EV-01, E2E-01/02/03/11/12 | Done; results below |

---

## 2. The code

### 2.1 Evaluation (`eval/`)

- **`compare.py`** — the heart of EV-01. Matches PROVBIND alerts and Falco lines to `ground_truth.csv`
  rows by pod (namespace + `pod_prefix`) and time window, and prints one row per scenario: the truth,
  PROVBIND's classes with their highest bucket, and Falco's rules with their highest priority.
  `--json` gives machine-readable rows. Robust ISO-8601 parsing (handles `Z`, offsets, and Falco's
  nanoseconds). `python -m eval.compare --run $PROVBIND_RUN`.
- **`ground_truth.py`** — appends one `ground_truth.csv` row per scenario run (Sprint Handoff §4.7;
  D4 wants at least three runs per scenario). `--start now`/`--end now` fill the current UTC time.
- **`capture_falco.sh`** — streams Falco's JSON to `run/falco.jsonl` (keeps only JSON lines).

### 2.2 ML-A corpus and profiling (MLA-03)

- **`ml/corpus.yaml`** — dataset D1: 24 public images (web servers, datastores, caches, a broker,
  language apps, a static Go binary, utilities, plus our stand-in and demo images), with a workload
  each. At least 20 is the minimum; a list of more to reach 40 is at the bottom of the file.
- **`testbed/profiling/labels.py`** — turns Tetragon `cap_capable` events into capability labels.
  A capability with at least one **granted** check is a label; denied-only checks are recorded
  separately; the label is the **union of two runs**, and the two-run disagreement is the label
  noise (§4.2). Reuses `ml.alg1.ALL_CAPS`/`normalise`, so labels share Role 2's capability names.
- **`testbed/profiling/run.py`** — assembles `ml/data/labels.jsonl` from captured events (runs
  anywhere). Reports label noise and the capabilities too rare to train (<3 positive images).
- **`testbed/profile_corpus.sh`** — the demo-PC capture half: re-tag + attest each image, deploy it
  twice for 120 s under Role 3's `cap_capable` policy, save the raw events, then assemble.

### 2.3 Scenarios (`testbed/scenarios/`)

`benign.sh` (benign-1), `attack.sh` (attack-1), `attack2.sh` (attack-2), `trust.sh` (trust-1),
`tamper.sh` (tamper-1), sharing `lib.sh` (wait for `envelope_ready`, hit the app's own endpoint,
record ground truth). Triggers are harmless; the attack ones wait for the envelope so their events
do not land in the cold-start window.

### 2.4 Demo app (`testbed/demo-app/`)

The signed app the demo deploys, plus `requestz-helper`, the harmless test package that stands in
for a compromised dependency. `/update` drops and runs an embedded test payload (`x9.c`: appends one
inert marker to `/etc/passwd`, then sleeps) → D_exec undeclared + D_write. `/update2` writes 300 new
files under `/tmp/.cache` and reads them back → the ML-B case. The payload is compiled and
base64-embedded at image build, so the repo holds only the C source and an empty placeholder, and
`/tmp/.x9` shows up as undeclared (new hash), not relocated. `requestz-helper` installs from local
source only and must never be fetched from PyPI. See `testbed/demo-app/README.md`.

### 2.5 Cluster bootstrap and the Makefile

`testbed/kind-with-registry.sh` (kind wired to `localhost:5001`) and a root `Makefile` with Role 1's
targets: `up`/`down`, `demo-app`, `benign`/`attack`/`attack2`/`trust`/`tamper`, `falco-capture`,
`profile`, `assemble-labels`, `compare`, `report`, `corpus-check`, `test`. Role 4 extends the
Makefile with the controller, alerts and `make demo` targets.

---

## 3. Tests and results

New this session: 413 unit + capability tests pass (`pytest -m "not integration"`; was 344 on the
merged `main`), 3 skipped (Role 2 ML tests without LightGBM), 13 deselected (integration). pyflakes
clean. Breakdown of the new tests: `eval` 21, `testbed` label/assemble/corpus/demo-app 44, plus the
capability tests below.

Capability results (recorded by the `record_result` fixture; synthetic runs are `not_run` by design):

| ID | P | Status here | Note |
|---|---|---|---|
| CF-06 | P1 | **pass** | Reference filter, expansion off: overflow is reported via `add()==False`; every accepted insert stays retrievable (no silent loss). Data-independent property. |
| CF-02 | P1 | not_run | §6.2 pre-check on synthetic paths: fp-rate 3e-5 (16-bit) ≤ 1.2e-4 theory; 0.014 (8-bit) ≤ 0.031. |
| CF-03 | P1 | not_run | §6.2 pre-check: filter 64 KB vs a Python set's ~0.5 MB of container overhead. |
| CF-04 | P1 | not_run | §6.2 pre-check: the Python filter is several times slower per lookup than a `set` (as §6.2 predicts). |
| EV-01 | P0 | not_run | Needs `alerts.jsonl`, `falco.jsonl`, `ground_truth.csv` from the PC. Logic verified against a synthetic integrated run folder. |
| E2E-01/02/03 | P0 | not_run | attack-1 / benign-1 / attack-2. Logic verified on synthetic data (D_exec+D_write in one chain; nothing above Low; D_beh only). |
| E2E-11/12 | P0 | not_run | Trust withdrawal and log tampering; depend on Role 4's trust alerts and `verify_log`. |

CF-02/03/04 are recorded `not_run` on purpose: §6.2 says the synthetic pre-check is not a project
result. Re-run them with `PROVBIND_ENVELOPE=run/envelopes/<digest>.json` on a real envelope, where
they record `pass`.

---

## 4. How to run

```bash
# anywhere
pytest -q -m "not integration"
python -m eval.report --run $PROVBIND_RUN            # writes run/results/REPORT.md
python -m eval.compare --run $PROVBIND_RUN           # PROVBIND vs Falco vs ground truth (after a run)

# demo PC
make up                                              # kind + registry, Tetragon, Falco, Neo4j, ns demo
make demo-app                                        # build, sign and attest testbed/demo-app
./eval/capture_falco.sh &                            # start capturing Falco
make attack ; make benign ; make attack2            # run scenarios (append ground truth)
make trust ; make tamper                            # trust-1 and tamper-1
make profile                                         # MLA-03: writes ml/data/labels.jsonl
python -m eval.compare                               # the comparison table
```

The CF pre-checks on a real envelope:
`PROVBIND_ENVELOPE=run/envelopes/<hex>.json pytest -q tests/capability/test_cf_0{3,4}*.py tests/capability/test_cf_02*.py`

---

## 5. Handoffs and what still needs the demo PC

**To Role 2:** `testbed/demo-app/` is ready to build, attest and compile. The "done when" checks
should hold: `python3.11`/`libpython`/libc in the closure; `/usr/bin/ls` and `/usr/bin/dash` in
`files` but not the closure; no entry for `/tmp/.x9`; `requestz_helper` files owned by
`pkg:pypi/requestz-helper@0.1.0`. Pin the base image digest first (see the Dockerfile header).

**To Role 3:** `profile_corpus.sh` needs the `cap_capable` TracingPolicy applied. Confirm the
Tetragon export container name (`-c export-stdout`, marked VERIFY).

**To Role 4:** `compare.py` reads `alerts.jsonl` and `ground_truth.csv`; the trust and tamper E2E
tests assume Role 4's trust alert shape and `alerts.verify_log`. If those differ, E2E-11/12 adapt
to a `trust`-classed alert and a `verify_log.verify(run)` entry point — align at the next merge.

**Pending on the PC (P0 by Day 3 noon):**
1. `make up`, then run every scenario with Falco capturing → `alerts.jsonl`, `falco.jsonl`,
   `ground_truth.csv`; EV-01 and E2E-01/02/03/11/12 then record real results.
2. `make profile` on at least 20 corpus images → `ml/data/labels.jsonl` for MLA-03, which Role 2
   joins to its features and trains (MLA-04/05).
3. Re-run CF-02/03/04 on the compiled demo envelope for real numbers.

## 6. Open points

- **Base image not pinned.** `testbed/demo-app/Dockerfile` uses `python:3.11-slim`; pin by digest
  before the final demo, or the envelope changes between runs (same as `standin-app`).
- **attack-3..8 endpoints** (P1 scenarios: relocated binary, in-place modify, library injection,
  capability excess, egress) return 501 for now; add them if P0 is comfortably done.
- **DB workloads** in `corpus.yaml` assume a helper image with the right clients; `profile_corpus.sh`
  defaults to a curl-only helper. Use a richer client image for the datastore rows.
- **`requestz-helper` name.** Fictional on PyPI; the build installs it from local source with
  `--no-index`. Never let a build resolve that name from an index.
