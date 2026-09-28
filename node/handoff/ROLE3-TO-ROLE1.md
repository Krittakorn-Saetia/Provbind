# Handoff from Role 3 to Role 1: what to run and record on the demo PC

**From:** Role 3 (node runtime). **For:** Role 1 (testbed and evaluation). **Date:** 28 September 2026.

**State.** Role 3's code is in four stacked PRs. Merge them in order:

| PR | What it holds |
|---|---|
| [#11](https://github.com/Krittakorn-Saetia/Provbind/pull/11) | Normaliser and Tetragon policies |
| [#12](https://github.com/Krittakorn-Saetia/Provbind/pull/12) | Verifier and `node.run` |
| [#13](https://github.com/Krittakorn-Saetia/Provbind/pull/13) | ML-B |
| [#14](https://github.com/Krittakorn-Saetia/Provbind/pull/14) | Cuckoo filter and CF-05 |

Reference material:

| File | What it covers |
|---|---|
| `node/README.md` | How to run and test the node |
| `node/ROLE3_STATUS.md` | Every task and test, with open questions (Q1 to Q10) |
| `ml/data/mlb/README.md` | How to build the ML-B dataset, D2 |

## 1. The short version

Role 3 turns Tetragon's JSON into `events.jsonl` and `detections.jsonl` (Sprint Handoff §7). All of it was built and tested in the cloud, which has no Tetragon, so the PH4, MLB and CF-05 capability tests record `not_run` there. **They turn into pass or fail only from evidence recorded on the demo PC, which is yours.**

Four things only you can do:
1. Install Tetragon with our policies, and save 5 minutes of real output (§3).
2. Record one Tetragon session while your scenarios run, with the right `ground_truth.csv` rows (§4).
3. Record the ML-B benign data: at least 4 hours, plus a held-out hour (§5).
4. Run the live tests and the capability tests against those recordings (§3, §4, §5).

## 2. What you get from Role 3

| Output | Where | Notes |
|---|---|---|
| Normalised events | `$PROVBIND_RUN/events.jsonl` | §4.3 fields only. Kinds: exec, write, load, exit. **Cap and connect events are not written**, because §4.3 has no field for a capability or a destination (Q1). |
| Detections | `$PROVBIND_RUN/detections.jsonl` | §4.4 fields exactly. Role 4 turns them into alerts, which your `compare.py` reads. |
| Run summary | JSON on the node's stdout when it stops | Events per kind, drops by reason, cold-start windows per container (the data for PH2-10), envelope cache stats |
| Test results | `$PROVBIND_RUN/results/<ID>.json` | Role 3's IDs, for your `REPORT.md` |

Expected detections per scenario (these feed E2E-01 to 03 and EV-01):

| Scenario | Role 3 reports |
|---|---|
| benign-1 | Two weak `D_exec / outside_closure`: `sh` as `/usr/bin/dash`, and `ls`. Low after Role 4's cap. `cat` is a third if the envelope declares it. |
| attack-1 | `D_exec / undeclared` for `/tmp/.x9`, and `D_write / declared_file` for `/etc/passwd` |
| attack-2 | No deterministic detection. With a trained ML-B model and `--mlb`: at least one `D_beh` |
| attack-9 | One `binding / unknown_container` (or `binding / unverified` if the controller wrote a failed binding), once per container |

## 3. Tetragon on the demo PC (Day 1)

```bash
helm upgrade --install tetragon cilium/tetragon -n kube-system -f node/tetragon/values.yaml
kubectl apply -f node/tetragon/write.yaml -f node/tetragon/truncate.yaml -f node/tetragon/cap.yaml
kubectl get tracingpoliciesnamespaced -n demo          # each policy must be listed, with no error
```

| Policy | Needed for |
|---|---|
| `values.yaml` | Every run. It limits Tetragon's export to namespace `demo` and to exec, exit and kprobe events. |
| `write.yaml`, `truncate.yaml` | D_write; the ML-B features |
| `cap.yaml` | D_cap (attack-6); ML-B; **your MLA-03 labels** (§6) |
| `load.yaml` | attack-5 and benign-3 only. It adds many events, so leave it off for the demo. |
| `connect.yaml` | attack-7 only, plus ML-B if you want connection features |

Check these on the PC. Each policy file also says what to verify.
- [ ] `uname -r`. On a kernel older than 6.2, delete the `security_file_truncate` entry from `truncate.yaml`, or the policy fails to load.
- [ ] The export container is named `export-stdout`: `kubectl logs -n kube-system ds/tetragon -c export-stdout --tail=5`.
- [ ] The Helm value names in `values.yaml` match your chart: `helm show values cilium/tetragon`.
- [ ] Tetragon's chart and app versions are recorded in `testbed/VERSIONS.md`.

**Save 5 minutes of real output** as `node/testdata/raw.jsonl`. This is Role 3's Day-1 item, but it needs the PC. Run a few commands in a demo pod meanwhile, then replay it:

```bash
timeout 300 kubectl logs -n kube-system ds/tetragon -c export-stdout -f > node/testdata/raw.jsonl
python -m node.run --run $PROVBIND_RUN --replay node/testdata/raw.jsonl --no-events
```

The summary's `dropped` field counts every line the normaliser could not use, by reason. Commit `raw.jsonl` and send Role 3 the summary. The normaliser's input shapes come from Tetragon's documentation, and this file is the first check against our real version.

**Run the live tests.** They need a running demo pod, and they trigger their own events with `kubectl exec`:

```bash
pytest -q -m integration tests/capability/test_ph4_01_02_events.py   # PH4-01, PH4-02a, PH4-02b
```

For a real-path check (PH4-01), set `PROVBIND_ENVELOPE` to the demo image's envelope (`$PROVBIND_RUN/envelopes/<hex>.json`). PH4-02b needs `load.yaml` and `connect.yaml` applied while it runs.

## 4. Recording the scenarios

**How to record.** One recording covers a whole session:
1. Start the node with `tee` **before** the first scenario.
2. Run your scenarios. Each one appends its row to `ground_truth.csv`, as your scripts already do.
3. Stop the node after the last one.

```bash
kubectl logs -n kube-system ds/tetragon -c export-stdout -f | tee $PROVBIND_RUN/rec.jsonl \
  | python -m node.run --run $PROVBIND_RUN --egress egress.json
```

Keep recordings inside the run folder, which git ignores; never commit them.

**What each `ground_truth.csv` row must get right** (§4.7). The replay keeps only events inside some row, and judges each scenario only by the events and detections inside its row.
- **`scenario`:** exactly the Test Plan §7 ID: `attack-1`, `benign-1`, and so on. Add one row named **`ph4-14`** (label `benign`) around the `/tmp/new.txt` write described below.
- **`namespace`:** `demo`. **`pod_prefix`:** the prefix of the pod the scenario runs in. For attack-9, that is the unsigned pod's prefix, not `demo-app`.
- **`start` and `end`:** UTC ISO 8601 with a `Z`. The window must contain every event of the scenario. Start before the trigger, and end after it settles.
- **No other activity** in the same pod during a scenario's window. A hand-typed `kubectl exec` during attack-2, for example, adds a detection and fails MLB-05.

| Scenario | Checked by | What must happen | Policies |
|---|---|---|---|
| attack-1 | PH4-05, PH4-12 (and Role 4's PH5-13) | A file whose path ends in `/.x9` is executed. It is in no image layer. It writes `/etc/passwd`, which is not a mount. | write |
| attack-2 | MLB-05 | See the attack-2 notes below | the same set as D2 (§5) |
| attack-3 | PH4-09; PH4-07 and PH4-18 stay `blocked` | `/usr/bin/ls` copied to `/tmp/.l`, then run | write |
| attack-4 | PH4-08 (`blocked`) | `/usr/bin/ls` overwritten, then run | write |
| attack-5 | PH4-10 | `LD_PRELOAD=/tmp/libx.so python3 -c pass` | **load** |
| attack-6 | PH4-15 | The app changes a file's owner to uid 4242 (CAP_CHOWN; the pod runs as root) | **cap** |
| attack-7 | PH4-16 | The app connects to an address outside the egress list (below) | **connect**, plus the egress list |
| attack-9 | PH4-03 | An unsigned image started in namespace `demo`. The row covers the pod's start. | any |
| benign-1 | PH4-06 | Your `benign.sh`: `sh -c 'ls /; cat /etc/hostname'` via `kubectl exec` | write |
| benign-3 | PH4-11 | The app does a DNS lookup (`socket.getaddrinfo`) | **load** |
| benign-4 | PH4-13 | See the benign-4 notes below | write |
| ph4-14 | PH4-14 | `kubectl exec -n demo deploy/demo-app -- sh -c 'echo x > /tmp/new.txt'` inside the row | write |

**attack-2 notes (MLB-05):**
- **Run the burst inside the long-running app process:** a thread or the request handler, not a new subprocess. ML-B ignores processes younger than 10 s.
- **300 new files under `/tmp/.cache` in about 20 s,** read back, with no exec and no write to a file in the image.
- **Keep the row open at least 35 s after the burst.** A `D_beh` is timed at the end of its window, which can be up to 30 s later.

**benign-4 notes (PH4-13):**
- Mount an `emptyDir` over an image directory that **has files in the image**, and write to one of them. Example: `/app/data/seed.json` baked into the image, with `/app/data` mounted.
- If no image file under a mount is written, PH4-13 records `fail` with the note "the rule was not exercised".

**Egress list for D_net** (`--egress`, and `PROVBIND_EGRESS` for the tests). A JSON file of what the demo app may reach:

```json
{"allow": ["10.96.0.0/12", "10.244.0.0/16", "127.0.0.0/8"]}
```

Those are kind's default service and pod ranges plus loopback, so check yours. Entries can also name a port: `"10.96.0.10/32:53"`, `"*:443"`.

**Then judge the recording:**

```bash
export PROVBIND_RUN=/path/to/run          # holds bindings.json, envelopes/ and ground_truth.csv
PROVBIND_RECORDING=$PROVBIND_RUN/rec.jsonl PROVBIND_EGRESS=egress.json \
  pytest -q tests/capability/test_ph4_*.py tests/capability/test_cf_05_*.py
```

- A scenario with no row records `not_run`.
- PH4-07, PH4-08 and PH4-18 record `blocked` until the node has a runtime hash source (C3).
- PH4-04 is a live scale test (5 replicas, then 0). It needs Role 4's controller running: `pytest -q -m integration tests/capability/test_ph4_04_cache.py`.

## 5. ML-B data (D2)

The full steps are in `ml/data/mlb/README.md`. In short:
1. **First benign run, at least 4 hours.** Run your load generator: curl at random intervals, health checks, and the app's own cache-file writes (Test Plan §5). Record Tetragon with `tee` into the run folder, as in §4.
2. **Second benign run, at least 1 hour, starting at least 1 hour after the first.** This is the held-out set for MLB-04.
3. **Use the same Tetragon policies as the attack-2 run.** The window features count every kind of event.
4. **Build the windows and commit them** to `ml/data/mlb/<hex>/`, with `python -m node.mlb windows`, then `split`. Commit the windows only: raw recordings are large and hold host details.
5. **For MLB-06**, do the same for at least 2 corpus images (one folder per digest).

**Why 4 hours, not 3** (Q9): a window starts at a process's first event. On a synthetic load of one request every 5 s, 3 hours gave only about 290 windows, fewer than 100 for validation. The threshold then falls back to the 95th percentile, and MLB-04's 1% target is out of reach.

## 6. Your tests that use Role 3's code

**MLA-03 (P0, yours): ML-A labels.**
- `node/tetragon/cap.yaml` is the capability policy, namespaced to `demo`. Either profile the corpus in `demo`, or copy the policy with another namespace and add that namespace to `values.yaml`'s allow list (Q3).
- `node/normalize.py` already parses the events:

```python
from node.normalize import Normalizer
norm = Normalizer(namespaces=("demo",))          # or the corpus namespace
for line in open("profile.jsonl"):
    ev = norm(line)
    if ev is not None and ev.kind == "cap":
        use(ev.pod, ev.exe, ev.cap, ev.granted)  # granted: True, False (denied), None (no return value)
```

The label is the set of capabilities with at least one **granted** check (Test Plan §4.2). Denied checks are attempts: record them separately.

**CF-02, CF-03, CF-04, CF-06 (yours).** The node uses the test kit's filter, `node/ref_cuckoo.py`, unchanged: `Store(run_dir, cuckoo=True)` builds one per envelope. For CF-06: when the filter is full, the node logs an error, counts `filter_full`, and runs without it, so nothing is lost silently (`node/tests/test_cuckoo_path.py` shows it). CF-01 is recorded by the kit's `test_cf_reference_example.py` once `PROVBIND_ENVELOPE` is set. CF-05 (Role 3) measured on synthetic data that the filter doubles per-event latency.

**EV-03 ablations.** Role 3's switches:

| Ablation | How to run it |
|---|---|
| Strict against split closure (C2) | PH4-06 reports both from one replay |
| ML-B on and off | `node.run --mlb` |
| Cuckoo filter on and off | `node.run --cuckoo` |
| ML-A against the allowlist | Two envelopes of the same image (ask Role 2). The test for it is MLA-07, which has no file yet (Q2). |

**EV-07 (ML-C).** Keep it apart from ML-B: don't import `node/mlb.py`, and don't read or write `ml/data/mlb/` (Test Plan §12.2). If you build ML-C from `events.jsonl`, it won't see cap or connect events (Q1).

## 7. Environment variables for Role 3's tests

| Variable | Meaning |
|---|---|
| `PROVBIND_RUN` | Run folder: `bindings.json`, `envelopes/`, `ground_truth.csv`, `results/` |
| `PROVBIND_RECORDING` | The Tetragon recording (or an `events.jsonl`) |
| `PROVBIND_GROUND_TRUTH` | `ground_truth.csv`, if it is not in the run folder |
| `PROVBIND_EGRESS` | Egress list for D_net |
| `PROVBIND_ENVELOPE` | One envelope, for PH4-01's real-path check (and Role 2's PH3 tests) |
| `PROVBIND_DETECTIONS` | A live node's `detections.jsonl`, schema-checked by PH4-17 |
| `PROVBIND_MLB_DATA`, `PROVBIND_MLB_DIGEST` | D2's folder (default `ml/data/mlb/`), and which digest is the demo image |
| `PROVBIND_DEMO_POD`, `…_POD_PREFIX`, `…_CONTAINER`, `…_PORT`, `…_DEPLOY` | Where the live tests act. Default: the first running `demo-app*` pod, port 8080. |
| `PROVBIND_TETRAGON_NAMESPACE`, `…_SELECTOR`, `…_CONTAINER` | Where the live tests read Tetragon. Default: `kube-system`, `app.kubernetes.io/name=tetragon`, `export-stdout`. |

## 8. Limits to say plainly in the report

- **No runtime hash source yet (C3).** D_hash never fires, and PH4-07, 08 and 18 are `blocked`:
  - attack-3 shows `D_exec / undeclared` instead of `D_hash / relocated`;
  - attack-4 shows `D_write`, then a weak `D_exec / outside_closure`, instead of `D_hash / modified`.
- **`events.jsonl` has no cap or connect events** (Q1).
- **The normaliser's input shapes** come from Tetragon's documentation until `raw.jsonl` confirms them.
- **ML-B uses a proposed fix.** The Isolation Forest scored attack-2's burst exactly at its threshold on synthetic data, so we added a range guard. MLB-05 reports both (Q8).
- **Possible false positive.** With `cap.yaml` on, the container runtime's own capability checks during `kubectl exec` may show up as D_cap in benign-1. If you see D_cap or D_load in a benign run, send Role 3 that recording.

## 9. Checklist

- [ ] Tetragon installed with `values.yaml`; `write`, `truncate` and `cap` policies loaded; versions in `VERSIONS.md`
- [ ] `node/testdata/raw.jsonl` committed; its replay summary sent to Role 3
- [ ] `pytest -m integration tests/capability/test_ph4_01_02_events.py` run
- [ ] Egress list written (`egress.json`)
- [ ] Scenario session recorded with every row above, including `ph4-14`; `load.yaml` and `connect.yaml` on for attack-5, attack-7 and benign-3
- [ ] `PROVBIND_RECORDING=$PROVBIND_RUN/rec.jsonl pytest -q tests/capability/test_ph4_*.py tests/capability/test_cf_05_*.py` run; results in `REPORT.md`
- [ ] D2: 4 or more benign hours, plus a held-out hour, windows committed to `ml/data/mlb/<hex>/`; MLB tests run
- [ ] MLA-03 profiled with `cap.yaml`; labels parsed as in §6

**Questions for you:**
- Q3: in which namespace will you profile the ML-A corpus?
- Q9: can your load generator run 4 or more hours?
- Which egress destinations does the demo app really use?
