# Role 1 → Roles 2, 3, 4: hand-off

**28 September 2026.** What Role 1 (Testbed and evaluation) has delivered, what each of the other
roles needs from it, and the few cross-role formats we should confirm at the next merge. Branch
`claude/zen-hypatia-pyrg25` (PR #16). Full detail is in `docs/ROLE1-SESSION-NOTES-2026-09-28.md`.

No contract in `contracts/` was changed. Role 1 only **produces** `ground_truth.csv`, `falco.jsonl`
and `results/`, and **reads** `bindings.json` (Role 4), `alerts.jsonl` (Role 4) and the envelopes
(Role 2). If any of the shapes below differ from what you build, tell me and I adapt Role 1's side.

## What's ready now (runs anywhere)

- `testbed/demo-app/` — the signed app + `requestz-helper` test package (for Role 2).
- `eval/compare.py`, `eval/ground_truth.py`, `eval/capture_falco.sh` — the comparison and ground truth.
- `ml/corpus.yaml` — the 24-image ML-A corpus (D1).
- `testbed/profiling/` + `testbed/profile_corpus.sh` — capability-label profiling (MLA-03).
- `testbed/scenarios/*.sh`, `testbed/kind-with-registry.sh`, root `Makefile`.
- Capability tests CF-03/04/06, EV-01, E2E-01/02/03/11/12. Suite: 413 passed.

---

## To Role 2 — Evidence and compiler

**1. The demo app is ready to build, attest and compile.**
```bash
make demo-app            # = pipeline/build-and-attest.sh testbed/demo-app demo-app
python -m compiler.compile <ref@digest> --run $PROVBIND_RUN
```
- **Pin the base image digest first** (`testbed/demo-app/Dockerfile` header), or the envelope
  changes between runs — same rule as `standin-app`.
- `requestz-helper` installs from **local source only** (`pip install --no-index ./requestz-helper`);
  it is fictional on PyPI and must never be resolved from an index. The Dockerfile already does this.
- Your "done when" checks should hold: `python3.11`, `libpython3.11` and libc in `closure`;
  `/usr/bin/ls` and `/usr/bin/dash` in `files` but not `closure`; **no** entry for `/tmp/.x9`;
  the `requestz_helper` files owned by `pkg:pypi/requestz-helper@0.1.0`. (Verified locally that the
  package installs with a `requestz-helper` 0.1.0 dist-info and a RECORD, which `owners.py` reads.)

**2. Please hand back the demo envelope path.** Once you compile the demo (and re-compile the
stand-in), post `run/envelopes/<digest>.json`. Role 1 needs it to run the real CF-02/03/04
pre-checks (`PROVBIND_ENVELOPE=...`) instead of synthetic paths, and it unblocks your own PH3-04/07/08/09
and MLA-02 real runs.

**3. ML-A labels (MLA-03) → your dataset join (T13 step 3).** After the demo-PC profiling run,
Role 1 writes `ml/data/labels.jsonl`, **one row per image**, keyed by digest:
```json
{"image": "nginx:1.27", "digest": "sha256:...", "labels": ["CAP_NET_BIND_SERVICE", ...],
 "denied": ["CAP_SYS_ADMIN", ...], "runs": 2, "run_disagreement": 1,
 "disagreement_fraction": 0.5, "workload": "..."}
```
- `labels` are the capabilities with a granted check, unioned over two runs; `denied` are
  attempts only (never labels); `run_disagreement`/`disagreement_fraction` are the label noise (§4.2).
- Capability names come from `ml.alg1.ALL_CAPS`/`normalise`, so they match your model's label space.
- Join is **by digest**, so I record each image's digest. Your side still needs the per-image
  **features** by digest — your proposed `--features-out ml/data/features.jsonl` flag on the
  compiler is the missing half (ELF imports can only be read while the image is open).

---

## To Role 3 — Node runtime

**1. Profiling needs your `cap_capable` policy.** `testbed/profile_corpus.sh` assumes Role 3's
`cap_capable` TracingPolicy is applied on the cluster, and streams
`kubectl logs -n kube-system ds/tetragon -c export-stdout` (the container name is marked **VERIFY** —
please confirm it for the demo PC).

**2. The label parser expects this `cap_capable` event shape** (`testbed/profiling/labels.py`,
`parse_tetragon_cap_events`):
- `process_kprobe.function_name == "cap_capable"`;
- a `capability_arg` in `args` with a `name` (e.g. `CAP_NET_ADMIN`) or a `value` (the index);
- `return.int_arg` = 0 granted / -1 denied (§4.2, §8);
- `process.pod.namespace` / `process.pod.name`, so we can keep only the workload's own pods.
If your normalised/exported cap events look different, point me at a sample and I'll adjust the parser.

**3. Scenarios and the detections you must produce.** The demo app endpoints drive your verifier:
- `/update` (attack-1) → **D_exec undeclared** (`/tmp/.x9` in no layer) + **D_write** (`/etc/passwd`),
  one chain (E2E-01);
- `/update2` (attack-2) → no deterministic detection, **D_beh** from ML-B (E2E-03, MLB-05).
Role 1's E2E tests read `alerts.jsonl` (produced by Role 4 from your `detections.jsonl`) and check
these classes/subclasses exactly as named in Sprint Handoff §4.4.

**4. Cuckoo filter split.** Role 1 ran the §6.2 pre-checks on synthetic paths: CF-02 (fp-rate),
CF-03 (memory), CF-04 (lookup time) — recorded `not_run` until run on a real envelope — and **CF-06**
(full-filter behaviour) passes as a property of `node/ref_cuckoo.py`. CF-01 (no false negatives) and
**CF-05** (effect on the real event path, the M15 keep-or-replace decision) are yours; build one
filter per envelope on the node. Re-run CF-02/03/04 for real once Role 2 hands over an envelope.

**5. ML-B write hook.** attack-2 (300 files under `/tmp/.cache`) is the MLB-05 case, produced by
`/update2`. Remember the write hook must cover **all paths** in monitored pods for ML-B (Test Plan §5).

---

## To Role 4 — Alerts and integration

Role 1's `eval/compare.py` and the E2E tests are the main consumers of your outputs. They assume
the Sprint Handoff §4 shapes; please confirm or tell me where you diverge.

**1. `alerts.jsonl` (§4.5).** `compare.py` reads: `container` = `"namespace/pod/container"` (or
explicit `namespace`/`pod`), `time` (ISO-8601 UTC), `class`, `subclass`, `bucket`
(critical/high/medium/low), `chain_id`. E2E-01 checks that the attack-1 D_exec and D_write share one
`chain_id`.

**2. Trust alerts (E2E-11).** Role 1's test recognises a trust alert by `class`/`kind`/`type`
starting with `trust`, or a `trust_reason`/`trust` field. **Tell me the exact shape** your trust
loop emits and I'll match it precisely.

**3. `verify_log` (E2E-12).** Role 1's test does `from alerts import verify_log` and expects an entry
point like `verify_log.verify(run)` returning an object with `.ok` / `.first_bad`. If your API or
exit convention differs, give me the interface and I'll adapt the test (or I can shell out to
`python -m alerts.verify_log` if you prefer that contract).

**4. Files the scenarios touch — confirm the paths:**
- `trust.sh` writes a local OSV advisory (MAL- id) to `run/advisories/requestz-helper.json`
  (override `PROVBIND_ADVISORY`). Does your ComponentCheck read that path/format?
- `tamper.sh` edits `run/log/violations.jsonl` (override `PROVBIND_LOG`). Is that your log path?
- `lib.sh` waits for `envelope_ready: true` in `run/bindings.json` (§4.2: dict keyed by container id
  with `namespace`, `pod`, `envelope_ready`). Confirm your controller writes it that way.

**5. The Makefile.** Role 1 created the root `Makefile` with its own targets (up/down, scenarios,
profile, compare, report). It's yours to extend with the controller, alerts and **`make demo`**
targets — please add, don't rename Role 1's. `make up` already brings up Neo4j (§10) for your
attribution step.

---

## Cross-role confirmations needed (quick list)

| # | Owner | Confirm |
|---|---|---|
| 1 | R2 | Post the compiled demo envelope path; add `--features-out` for the ML-A feature join |
| 2 | R3 | Tetragon export container name; the `cap_capable` event field shape |
| 3 | R4 | Trust alert shape (E2E-11); `verify_log` API (E2E-12); advisory, log and bindings paths |

Ping me on any of these and I'll align Role 1's parser/tests the same day.
