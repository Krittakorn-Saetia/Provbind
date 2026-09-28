# node/: Phase 4, runtime observation and verification (Role 3)

Everything between the kernel and `detections.jsonl` (Sprint Handoff §7; Explanation §7). Tetragon's JSON export comes in on stdin. Normalised events and detections go out to the run folder. Status and open questions: `ROLE3_STATUS.md`.

## Layout

| Path | What it is |
|---|---|
| `normalize.py` | Tetragon JSON → events (Eq. 50, Sprint Handoff §4.3), with the namespace filter |
| `tetragon/*.yaml` | TracingPolicies, one per hook, plus Helm values for the export filter |
| `synth.py` | Synthetic Tetragon events for tests. Never a project result |
| `ref_cuckoo.py` | The test kit's reference Cuckoo filter (Test Plan §6.1) |
| `tests/` | Unit tests; they build their own fixtures and need no cluster |

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

**Use the same policy set** for the ML-B benign runs and for the attack-2 run. The window features count every kind, so a model trained without `cap.yaml` would see capability checks as new.

## Events

`events.jsonl` uses the field names of Sprint Handoff §4.3 only:

| Kind | Fields |
|---|---|
| exec | time, kind, container_id, namespace, pod, container, pid, ppid, exe, parent_exe, hash |
| write | … parent_exe, path |
| load | … parent_exe, path, hash |
| exit | … parent_exe |

- **`hash`** is the executed file's sha256, as 64 hex digits. It is `null` in path-only mode, which is the default: Tetragon reports paths, not hashes (fail point C3).
- **Cap and connect events are not written to `events.jsonl`.** Their payload (capability; destination address and port) has no contract field, so they are verified in memory only. Replaying `events.jsonl` therefore cannot reproduce D_cap, D_net or the ML-B features that count them. For those, replay Tetragon's own JSON, recorded with `tee`. Adding the fields needs the team: `ROLE3_STATUS.md`, Q1.
- **Paths are kept exactly as Tetragon reports them.** A suffix like ` (deleted)` is never stripped, because an attacker can name a file that way. A relative exec path is only joined to the process's working directory.
- **Dropped events are counted by reason** (other namespace, host process, read-only access, refused by the LSM, not a file). Nothing is dropped silently.

## Tests

```bash
pytest -q -m "not integration" node/tests          # node unit tests (not yet in pytest.ini's testpaths)
pytest -q tests/capability/test_ph4_01_02_events.py
pytest -q -m integration tests/capability/test_ph4_01_02_events.py    # demo PC: live triggers
```

The capability tests record results with `record_result`. They read their evidence from environment variables:

| Variable | Used for |
|---|---|
| `PROVBIND_RECORDING` | Tetragon JSON recorded on the demo PC (`kubectl logs … -f \| tee rec.jsonl`) |
| `PROVBIND_ENVELOPE` | The image's envelope, for the real-path check (PH4-01) |
| `PROVBIND_DEMO_POD`, `PROVBIND_DEMO_POD_PREFIX`, `PROVBIND_DEMO_CONTAINER`, `PROVBIND_DEMO_PORT` | Where the live tests trigger events (default: the first running `demo-app*` pod; port 8080) |
| `PROVBIND_TETRAGON_NAMESPACE`, `…_SELECTOR`, `…_CONTAINER` | Where the live tests read Tetragon's export (default `kube-system`, `app.kubernetes.io/name=tetragon`, `export-stdout`) |

Without evidence, a test runs its checks on a synthetic stream and records `not_run`. A live test saves its capture in `run/results/<ID>/`. Later unit-test runs re-read that capture, so they never reset a live result.
