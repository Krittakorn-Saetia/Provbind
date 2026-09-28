# Handoff from Role 3 to Role 4: detections, bindings and `make demo`

**From:** Role 3 (node runtime). **For:** Role 4 (alerts and integration). **Date:** 28 September 2026.

**State.** Role 3's code is in four stacked PRs. Merge them in order:

| PR | What it holds |
|---|---|
| [#11](https://github.com/Krittakorn-Saetia/Provbind/pull/11) | Normaliser and Tetragon policies |
| [#12](https://github.com/Krittakorn-Saetia/Provbind/pull/12) | Verifier and `node.run` |
| [#13](https://github.com/Krittakorn-Saetia/Provbind/pull/13) | ML-B |
| [#14](https://github.com/Krittakorn-Saetia/Provbind/pull/14) | Cuckoo filter and CF-05 |

For how to run and test the node, see `node/README.md`. For every task and open question, see `node/ROLE3_STATUS.md`.

## 1. The short version

You read our `detections.jsonl`; we read your `bindings.json`.
- **Detections have exactly the §4.4 fields,** but the Test Plan adds classes that §4.4's table lacks. Your scorer needs values for them (§2).
- **The node needs four things from the controller:** the binding soon after a container starts, `verified` and `mounts` right, atomic writes, and entries removed when pods go (§3).
- **`make demo` runs `python -m node.run`** fed by Tetragon (§4).

## 2. `detections.jsonl`: what you receive

**Format:**
- Sprint Handoff §4.4 exactly: the same 16 fields, in that order.
- `node/detection.schema.json` encodes it, with every class and subclass we emit. You could add it to `contracts/check_contracts.py`.
- Our PH4-17 checks every detection against it.

**Writing:**
- **Append-only.** Each line is written in one call and flushed straight away. A reader tailing the file must wait for the newline of the last line.
- **`id`** is `det-NNNN`. After a restart it continues from the highest ID already in the file, so IDs never repeat.
- **`time` is the event's own time, not when the detection was written.** Two things arrive late and out of time order:
  - events held through a container's cold start, which are verified when its binding and envelope are ready;
  - `D_beh`, which is timed at the end of its window, up to 30 s after the behaviour.
- **For chains** (Sprint Handoff §8: "within 60 s of the chain's last detection"), **compare `time` values, not arrival times.**
- **`pid` and `ppid`** are Tetragon's. VERIFY on the demo PC which PID namespace they are in, since the kind node is itself a container. In attack-1, the `D_exec` for `/tmp/.x9` and its `D_write` on `/etc/passwd` share the payload's pid, so they chain (PH5-13).

**Classes.** The s_τ column is the proposal in Explanation §8, Step 2. The scorer is yours to set.

| class / subclass | Meaning | origin | `clause.kind` / `clause.path` | Proposed s_τ |
|---|---|---|---|---|
| D_exec / undeclared | Executed file is in no layer | AUTHENTICATED | `file_set` / the path run | 1.00 |
| D_hash / modified | Declared path, different runtime hash | AUTHENTICATED | `file_hash` / the declared path | 1.00 |
| D_load / undeclared | Mapped library is in no layer | AUTHENTICATED | `file_set` / the library | 0.85 |
| D_write / declared_file | Write to an image file that is not under a mount | AUTHENTICATED | `file_set` / the declared path | 0.80 |
| D_hash / relocated | Path in no layer, content of a declared file | AUTHENTICATED | `file_hash` / the path run | 0.70 |
| D_cap / not_in_envelope | A granted capability that is not in the envelope | INFERRED (see below) | `capabilities` / the process's executable | 0.60 |
| D_net / not_allowed | A connection outside the egress allow list | CONFIGURED | `egress` / the process's executable | 0.55 |
| D_exec / outside_closure | Declared, not reachable from the entrypoint. **Weak** | AUTHENTICATED | `closure` / the declared path | 0.25, capped at Low (34) |
| D_load / outside_closure | Declared library outside the closure (dlopen, NSS). **Weak** | AUTHENTICATED | `closure` / the declared path | 0.25, capped at Low |
| D_beh / anomalous_window | An ML-B window scored above θ_A, or beyond the range guard | INFERRED | `behaviour` / the process's executable | S_beh, capped at 59, Medium (M2; your MLB-07) |
| binding / unknown_container | No binding after the grace period (Eq. 51) | AUTHENTICATED | `binding` / the process's executable | Fixed 60, as §8 says for binding |
| binding / unverified | The binding says `verified: false` | AUTHENTICATED | `binding` | Fixed 60 (proposed) |
| binding / no_envelope | Bound and verified, but still no envelope after 300 s | AUTHENTICATED | `binding` | Fixed 60 (proposed) |

**Notes for the scorer and the alerts:**
- **`context`** is `{declared, package, depth, layer}`:
  - For the file classes, it describes the file.
  - For D_cap, D_net and D_beh, it describes the process's executable.
  - `layer` is the **index** into the envelope's `layers`, as in the envelope's `files[].layer`, so your fallback when Neo4j is down gives the same answer.
  - **ρ from §8:** `declared: false` → 1.0; declared but `package` or `depth` null → 0.5; otherwise depth/(1+depth).
  - **Binding failures have `declared: null`,** because nothing is known about the file. Their score is fixed anyway.
- **D_cap's origin** follows the envelope's capability list:
  - INFERRED if any entry is INFERRED, or the list is empty;
  - otherwise CONFIGURED if any entry is CONFIGURED;
  - otherwise AUTHENTICATED.

  With the allowlist or ML-A, it is INFERRED, so s_π = 0.5.
- **Once per container.** Binding failures are reported once per container and subclass, not per event, so one bad container gives one alert.
- **`D_beh`'s `clause.detail`** says which rule fired ("anomaly … > θ_A …", or "beyond 2x the benign maximum: …"), and gives g_I and the most unusual features.
- **Path-only.** An undeclared exec found without a runtime hash ends its detail with "; path-only: no runtime hash, so relocation was not checked". That is normal until the node has a hash source (C3).
- **`violated_clause`** in §4.5 reads well as `f"{kind}: {path} {detail}"`.

**Expected in the demo** (a root, non-privileged pod; your §8 unit tests):
- **Step 2, benign.** `sh -c 'ls /'` gives two `D_exec / outside_closure`: `/usr/bin/dash` and `/usr/bin/ls`. That is 2 Lows (34).
- **Step 3, attack.** `D_exec / undeclared` for `/tmp/.x9` (90) and `D_write / declared_file` for `/etc/passwd` (72), in one chain.
- **Step 4, in-envelope attack.** No deterministic detection. With `--mlb` and a trained model: at least one `D_beh`, capped at Medium.
- **Step 5, trust.** Nothing from the node, since the pod still conforms (PH6-07).

## 3. `bindings.json`: what the node needs from the controller

- **Key.** The full container ID as Kubernetes reports it (`status.containerStatuses[].containerID`, for example `containerd://<64 hex>`). Tetragon uses the same form. The node also matches the ID without its runtime prefix, and a unique prefix of 12 or more characters.
- **Fields the node reads:**

  | Field | How the node uses it |
  |---|---|
  | `image_digest` | Which envelope to use |
  | `verified` | `true` only if every cosign check passed. `false` gives `binding / unverified` at once. |
  | `mounts` | Absolute container paths. Include every volume mount and the files Kubernetes manages (`/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf`, `/dev/termination-log`, the service-account path). Writes under them are never D_write. |
  | `envelope_ready` | Informational for the node, which checks the envelope file itself. Role 1's attack script still waits for it. |

- **Write it atomically** (temp file, then rename), as §3.2 says. The node re-reads it whenever (mtime, size, inode) changes, checking every 0.5 s.
- **Timing (C4).** A container runs before its binding exists, so the node holds an unbound container's events for 30 s (`--grace`) before reporting `binding / unknown_container`. Write the binding as soon as the container ID appears in the pod status. If cosign verification takes longer than about 25 s on the demo PC, start the node with a larger `--grace`.
- **Remove entries when their pods go (Q5).** The node evicts an envelope once no verified container uses it. PH4-04 checks this live, scaling the demo to 5 replicas and then 0. Late events from a removed container are counted, never reported as unknown. If the controller keeps old entries, tell us; eviction then never happens.
- **`allowed_caps` (Role 2's decision 4).** The node doesn't read it. Adding it is a contract change for Roles 2, 3 and 4.

## 4. Running the node in `make demo`

```bash
kubectl logs -n kube-system ds/tetragon -c export-stdout -f \
  | tee "$PROVBIND_RUN/rec.jsonl" \
  | python -m node.run --run "$PROVBIND_RUN" --mlb [--egress egress.json]
```

The `tee` keeps a recording for replays and for Role 1's capability tests. It goes inside the run folder, which git ignores, because a recording is large and holds host details.

- **Start it before the first scenario.** There is no backfill: events from before the node started are never seen.
- **Output.**
  - Detections and events go to the run folder as they happen.
  - stdout gets one JSON summary, only when the node stops (SIGINT or SIGTERM give a clean stop); logs go to stderr.
  - Exit codes: 0 done, 2 bad arguments, 3 bad input.
- **Waits for `make demo`.**
  - attack-1's detections are written as soon as Tetragon exports its events: the node verifies each line on arrival. Only events held through a cold start wait for their binding and envelope; those are rechecked every 0.5 s.
  - attack-2's `D_beh` can take up to 30 s after the burst, until the process's window ends.
  - Wait on `detections.jsonl`, or on your alerts.
- **Policies for the demo.** Use `node/tetragon/values.yaml`, `write.yaml` and `truncate.yaml`. Add `cap.yaml` only if the ML-B model was trained with it: **the demo must use the same policy set as the ML-B data (D2).** Leave `load.yaml` and `connect.yaml` off; they add noise for no demo step.
- **Step 4 needs an ML-B model** beside the envelope, at `$PROVBIND_RUN/envelopes/<hex>.mlb/model.json`. Build it once from Role 1's D2 with `python -m node.mlb train --data ml/data/mlb/<hex> --run $PROVBIND_RUN`, then run the node with `--mlb`. Without a model the node still runs; it just raises no `D_beh`.
- **Leave the Cuckoo filter off:** don't pass `--cuckoo`. CF-05 measured it doubling the per-event latency.

## 5. Your tests that use Role 3's output

| Test | What to know |
|---|---|
| PH5-01 to PH5-05 (scoring) | Every class above; `declared: null` only on binding failures |
| PH5-09 (alert fields) | Every detection has clause, origin and time; PH4-17 checks our side |
| PH5-13 (chains) | Chain on `pid`/`ppid` and `time`, not arrival order (§2) |
| MLB-07 (S_beh against S_det) | `D_beh` is INFERRED, and its detail carries the anomaly score and g_I. Explanation §8 proposes capping S_beh at 59 (M2). |
| PH2-10 (Role 3's; no test file yet, Q2) | The cold-start window depends on how fast the controller writes the binding and the envelope appears. The node's summary reports it per container (`cold_start_s`). |

## 6. Questions for Role 4

- **Q4. Scoring the new classes:** D_load, D_cap, D_net, D_beh, binding / unverified, binding / no_envelope. Take the s_τ values above, or set your own. Also confirm the two weak classes, `context.layer` as an index, and `declared: null` on binding failures.
- **Q5.** Does the controller remove a binding when its pod is deleted?
- **Q1, for all roles.** `events.jsonl` has no fields for capability and connect events, so replays of it cannot reproduce D_cap or D_net. Do you agree to add `cap`, `granted`, `daddr`, `dport` and `protocol` to §4.3?
- **Chains.** Do you group by the detections' `time` values (recommended), or by when they arrive?

## 7. Checklist

- [ ] The scorer has values for every class in §2, with the two weak classes capped at Low and S_beh capped at Medium
- [ ] Alerts are chained on `time`, `pid` and `ppid`
- [ ] The controller writes each binding as soon as the container ID appears, atomically, with every mount
- [ ] The controller removes bindings of deleted pods, or tells Role 3 it can't
- [ ] `make demo` starts `node.run` before the scenarios, with the same policies as D2, `--mlb`, and a model beside the envelope
- [ ] `node/detection.schema.json` is considered for `check_contracts.py`
