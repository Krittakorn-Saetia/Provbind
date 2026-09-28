# node/: Phase 4, runtime observation and verification (Role 3)

Everything between the kernel and `detections.jsonl` (Sprint Handoff §7; Explanation §7). Tetragon's JSON export comes in on stdin. Normalised events and detections go out to the run folder. Status and open questions: `ROLE3_STATUS.md`.

## Layout

| Path | What it is |
|---|---|
| `normalize.py` | Tetragon JSON → events (Eq. 50, Sprint Handoff §4.3), with the namespace filter |
| `store.py` | `bindings.json` and `envelopes/`, reloaded on change; one cached envelope per digest (Eq. 52) |
| `verify.py` | The decision order (Eqs. 53–56, M12) and the §4.4 detection record |
| `pipeline.py` | Binding, holding events through the cold-start window (C4), binding failures |
| `run.py` | `python -m node.run`: live from stdin, or `--replay` a file |
| `output.py` | Append-only `events.jsonl` and `detections.jsonl`; detection IDs survive restarts |
| `scenarios.py` | Replay harness: a recording plus `ground_truth.csv` → results per scenario |
| `mlb.py` | ML-B (Algorithm 2): the gate, per-process windows, features Ψ_I, the per-image model, g_I, θ_A, D_beh; `python -m node.mlb` |
| `forest.py` | An Isolation Forest as JSON, scored in pure Python exactly as scikit-learn scores it |
| `detection.schema.json` | Sprint Handoff §4.4 as a JSON Schema, with the classes Role 3 emits (PH4-17) |
| `tetragon/*.yaml` | TracingPolicies, one per hook, plus Helm values for the export filter |
| `synth.py` | Synthetic Tetragon events and the Test Plan §7 scenario library. For tests only |
| `ref_cuckoo.py` | The test kit's reference Cuckoo filter (Test Plan §6.1) |
| `tests/` | Unit tests; they build their own fixtures and need no cluster |

## Running it

```bash
# live, on the demo PC
kubectl logs -n kube-system ds/tetragon -c export-stdout -f | tee rec.jsonl | python -m node.run --run $PROVBIND_RUN

# replay a recording (deterministic: time is the events' own)
python -m node.run --run $PROVBIND_RUN --replay rec.jsonl
```

- **Output.** Every event is appended to `<run>/events.jsonl` and every detection to `<run>/detections.jsonl`. Logs go to stderr. At the end, one JSON summary goes to stdout: counts per kind and verdict, dropped lines by reason, held and released events, cold-start windows, and envelope cache stats.
- **Options:**

  | Option | Effect |
  |---|---|
  | `--egress FILE` | Turns on D_net. The file is `{"allow": ["10.96.0.0/12", "127.0.0.1:8080", "*:443"]}` |
  | `--grace S` (30) | How long a container may run without a binding |
  | `--envelope-timeout S` (300) | How long a bound container may wait for its envelope before `binding / no_envelope` |
  | `--no-events` | Don't write `events.jsonl` |
  | `--mlb` | Score ML-B windows with the model beside each envelope (`<hex>.mlb/model.json`) |
  | `--windows-out FILE` | Record every closed ML-B window, for dataset D2 |
  | `--namespace NS` / `--all-namespaces` | Which namespaces to monitor |
  | `--summary FILE` | Also write the summary to FILE |

- **Exit codes.** 0 done; 2 bad arguments; 3 bad input (the replay file is missing, or it is the `events.jsonl` being written).

## Verification

The decision order is in `verify.py`'s docstring. Each event gets one outcome.

**Detections.** Every detection has exactly the fields of Sprint Handoff §4.4. The classes beyond §4.4's table come from the Test Plan, and Role 4's scorer needs to know them:

| class / subclass | Meaning | Origin |
|---|---|---|
| D_exec / undeclared | Executed file is in no layer | AUTHENTICATED |
| D_exec / outside_closure | Declared, not reachable from the entrypoint. **Weak** (C2), capped at Low | AUTHENTICATED |
| D_load / undeclared | Mapped library is in no layer (PH4-10) | AUTHENTICATED |
| D_load / outside_closure | Declared library outside the closure, mapped by a process in the closure (dlopen, NSS). **Weak** (PH4-11) | AUTHENTICATED |
| D_write / declared_file | Write to an image file that is not under a mount | AUTHENTICATED |
| D_hash / modified | Declared path, different runtime hash | AUTHENTICATED |
| D_hash / relocated | Path in no layer, content of a declared file | AUTHENTICATED |
| D_cap / not_in_envelope | Granted capability outside the envelope's set (PH4-15) | INFERRED unless every capability is AUTHENTICATED |
| D_net / not_allowed | Connection outside `--egress` (PH4-16). The envelope has no egress set yet (M8) | CONFIGURED |
| binding / unknown_container | No binding after `--grace` seconds (Eq. 51) | AUTHENTICATED |
| binding / unverified | `bindings.json` says the image's evidence failed | AUTHENTICATED |
| binding / no_envelope | Bound and verified, but no envelope after `--envelope-timeout`. Its events stay held | AUTHENTICATED |
| D_beh / anomalous_window | An ML-B window scored above θ_A, or beyond the range guard (below). Never a contradiction | INFERRED |

**Rules that shape the counts:**
- **Binding failures** are reported once per container and subclass, for its first event. Later events are counted, not reported.
- **Declared libraries outside the closure** are reported once per container and library, and only when the process that maps them is itself in the closure. A process outside the closure (`sh`, `ls`) was reported when it started.
- **Runtime hashes.** Without a runtime hash (path-only mode, the default) there is no D_hash, and an undeclared exec says `path-only` in its detail (PH4-09). The pipeline takes a `hasher`; there is no real hash source yet (C3, R3-T9).
- **Runtime paths.** Looked up as reported first, then through the image's symlinks. That covers a Tetragon version that reports `/bin/sh` for `/usr/bin/dash`.
- **Mounts** are compared as given in the binding and as real paths in the image, so `/var/run/secrets/…` on Debian also covers `/run/secrets/…`.

**Cold start (C4, PH2-10).** Events that arrive before their container's binding or envelope are held, in order, and verified when both are ready. The summary reports each container's window in seconds.

## ML-B: the behavioural path

`node/mlb.py`'s docstring has the details. The settings are Test Plan §5's:
- **Gate.** Only conforming events enter a window (MLB-01). A suppressed repeat of a weak detection does not count as conforming.
- **Windows.** 30 s or 200 events per process, for processes at least 10 s old.
- **Features.** 20 of them: counts and rates.
- **Model.** An Isolation Forest per image, stored as JSON beside the envelope, with θ_A at the 99th percentile of the validation windows.
- **Dataset.** D2 lives in `ml/data/mlb/`. Its README says how to build it and how long to record: at least 4 hours.

**The range guard: a finding, and a proposed fix.** An Isolation Forest scores anything beyond its training range like the most extreme benign window: it follows the same path through every tree. A feature that never varied in training gets no split at all.

On the synthetic data, attack-2's burst window (200 writes, all to new files) scored exactly θ_A, where the benign maximum was 15 writes. So the forest alone missed it in every seed. The only attack-2 window it flagged was flagged for unrelated rare events.

The guard flags a window with any feature above twice its largest benign value. It caught the burst and added no false positive on the held-out windows. It is on by default (`train --guard 0` turns it off). MLB-04 and MLB-05 report the forest alone next to it (Test Plan §0, rule 1), and every D_beh detail says which rule fired.

```bash
python -m node.mlb windows --run $PROVBIND_RUN --replay rec.jsonl --out w.jsonl      # windows of a recording
python -m node.mlb split --windows w.jsonl --out-dir ml/data/mlb/<hex>              # chronological 70/30
python -m node.mlb train --data ml/data/mlb/<hex> --run $PROVBIND_RUN               # model beside the envelope
python -m node.mlb evaluate --data ml/data/mlb/<hex> --run $PROVBIND_RUN            # held-out false positives
```

## Tetragon policies

| File | Hook | Kind | Needed for |
|---|---|---|---|
| built in | `process_exec`, `process_exit` | exec, exit | D_exec, D_hash; ML-B process lifetimes |
| `values.yaml` | Helm: export only namespace `demo`, only exec, exit and kprobe events | | Every run |
| `write.yaml` | `security_file_permission` with MAY_WRITE, **all paths** | write | D_write; ML-B needs every file written |
| `truncate.yaml` | `security_path_truncate`, `security_file_truncate` (kernel 6.2+) | write | D_write on truncation |
| `cap.yaml` | `cap_capable`, with its return value | cap | D_cap; ML-B; ML-A labels (MLA-03, Role 1) |
| `load.yaml` | `security_mmap_file` with PROT_EXEC | load | D_load (P1). Adds many events: apply it for the P1 runs only |
| `connect.yaml` | `tcp_connect` | connect | D_net (P1); ML-B connection features |

Every policy is a `TracingPolicyNamespaced` in namespace `demo`, so the kernel filters by namespace (Test Plan §8). The hook names follow the Test Plan's verified list. The exact YAML must still be checked against the Tetragon version on the demo PC; each file says what to check.

```bash
helm upgrade --install tetragon cilium/tetragon -n kube-system -f node/tetragon/values.yaml
kubectl apply -f node/tetragon/write.yaml -f node/tetragon/truncate.yaml -f node/tetragon/cap.yaml
kubectl get tracingpoliciesnamespaced -n demo
```

**Use the same policy set** for the ML-B benign runs and for the attack-2 run. The window features count every kind.

## Events

`events.jsonl` uses the field names of Sprint Handoff §4.3 only:

| Kind | Fields |
|---|---|
| exec | time, kind, container_id, namespace, pod, container, pid, ppid, exe, parent_exe, hash |
| write | … parent_exe, path |
| load | … parent_exe, path, hash |
| exit | … parent_exe |

- **Cap and connect events are not written to `events.jsonl`.** Their payload (capability; destination) has no contract field, so they are verified in memory only. A replay of `events.jsonl` therefore has no D_cap or D_net. Replay Tetragon's own JSON (the `tee` above) instead. Adding the fields needs the team: `ROLE3_STATUS.md`, Q1.
- **Paths are kept exactly as Tetragon reports them.** A suffix like ` (deleted)` is never stripped, because an attacker can name a file that way.
- **Dropped lines are counted by reason** (other namespace, host process, read-only access, refused by the LSM, not a file). Nothing is dropped silently.

## Tests and evidence

```bash
pytest -q -m "not integration" node/tests                     # node unit tests (not yet in pytest.ini's testpaths)
pytest -q tests/capability/test_ph4_*.py tests/capability/test_mlb_*.py   # PH4 and MLB capability tests
pytest -q -m integration tests/capability/test_ph4_*.py       # demo PC: live triggers, scale test
```

The capability tests record results with `record_result`. Without evidence they run on synthetic data and record `not_run`. On the demo PC, they read:

| Variable | Used for |
|---|---|
| `PROVBIND_RECORDING` | Tetragon JSON recorded while the scenarios ran (`tee rec.jsonl` above), or an `events.jsonl` |
| `PROVBIND_GROUND_TRUTH` | Role 1's `ground_truth.csv` (default `$PROVBIND_RUN/ground_truth.csv`) |
| `$PROVBIND_RUN` | The run folder's `bindings.json` and `envelopes/` |
| `PROVBIND_EGRESS` | The egress allow list for D_net (PH4-16) |
| `PROVBIND_DETECTIONS` | A live node's `detections.jsonl`, schema-checked by PH4-17 |
| `PROVBIND_MLB_DATA`, `PROVBIND_MLB_DIGEST` | Dataset D2 (default `ml/data/mlb/`) and which image is the demo image (MLB-03 to 06) |
| `PROVBIND_ENVELOPE` | The image's envelope, for PH4-01's real-path check |
| `PROVBIND_DEMO_POD`, `…_POD_PREFIX`, `…_CONTAINER`, `…_PORT`, `…_DEPLOY` | Where the live tests act (default: `demo-app*` pods, port 8080) |
| `PROVBIND_TETRAGON_NAMESPACE`, `…_SELECTOR`, `…_CONTAINER` | Where the live tests read Tetragon's export |

**Recipe on the demo PC:**
1. Start the node with the `tee` above.
2. Run Role 1's scenarios. Each run appends its row to `ground_truth.csv`. For PH4-14, also write `/tmp/new.txt` in a demo pod.
3. Stop the node.
4. Run `PROVBIND_RECORDING=rec.jsonl pytest -q tests/capability/test_ph4_*.py`.

Tests whose scenario has no row record `not_run`. Tests that need something the recording cannot have record `blocked`, with the reason: D_hash needs a runtime hash source; D_net needs an egress list.
