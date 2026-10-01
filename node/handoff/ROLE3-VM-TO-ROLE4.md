# Handoff from Role 3 to Role 4: real detections from the demo VM, and what to do with them

**From:** Role 3 (node runtime). **For:** Role 4 (controller, alerts, integration). **Date:** 1 October 2026.

This follows `ROLE3-TO-ROLE4.md` (28 September), which still defines `detections.jsonl` and what the node needs from `bindings.json`. This file adds the first real detections and what they mean for scoring, chains and `make demo`.

## 1. The short version

- **Real `detections.jsonl` and `alerts.jsonl` exist** for a full scenario session: 3 rounds of benign-1, attack-1, attack-2, ph4-14 and trust-1, then tamper-1. You can now run your PH5 and MLB-07 tests on real input (§4).
- **Your controller worked:**
  - every binding was `verified: true` (with the Rekor inclusion proof);
  - it was rewritten after pod restarts;
  - old pods' entries were removed. That **answers Q5: yes**.
- **Three things affect your side:**
  - attack-2 gives **3 to 5 D_beh per run**, not one (§3.2);
  - **attack-1's payload raises a D_beh after its row ends**, so chain by `pid` and `time` (§3.3);
  - `make demo` needs two settings on VMs like this one (§5).

## 2. The data

On Role 3's VM (`~/Provbind/run/`), shared privately, not through git. Ask Role 3 for the archive; the command is in `ROLE3-VM-TO-ROLE1.md` §2.

| File | What |
|---|---|
| `detections.jsonl` | All of the node's detections. **For the scenario session, use only those from the first `ground_truth.csv` row's start on.** The earlier ones are setup: test pods and the kind hook before #20 |
| `alerts.jsonl`, `log/violations.jsonl` | Your alert engine's output for the same session. **tamper-1 has edited the log**, so `verify_log` fails at that record, as intended. Restore `log/violations.jsonl.orig` before using the log again |
| `ground_truth.csv` | 16 rows |
| `rec.jsonl` | The Tetragon recording, to replay through the node if you need detections again |
| `bindings.json`, `envelopes/` | The binding and envelope the node used |

## 3. What the node reported

### 3.1 Per scenario (from the time of each row)

| Scenario (×3) | Detections | Notes |
|---|---|---|
| benign-1 | `D_exec/outside_closure` × 3 per run: `/usr/bin/sh`, `/usr/bin/ls`, `/usr/bin/cat` | Weak class, Low; from benign-1's own `kubectl exec` |
| attack-1 | `D_exec/undeclared` `/tmp/.x9` and `D_write/declared_file` `/etc/passwd` (exe `/tmp/.x9`), once per run | Same pid, so they should chain (PH5-13) |
| attack-2 | `D_beh/anomalous_window`, exe `/usr/local/bin/python`: **3, 5 and 5** per run | No deterministic detection, so MLB-05 passes |
| ph4-14 | `D_exec/outside_closure` `/usr/bin/sh` × 1 per run | From its `kubectl exec`; the write to `/tmp/new.txt` is correctly not a detection |
| trust-1, tamper-1 | nothing from the node | Your alerts |
| between rows | 1 × `D_beh`, exe `/tmp/.x9` | §3.3 |

From the first row on there are 32 detections. The classes are `D_exec/undeclared`, `D_exec/outside_closure`, `D_write/declared_file` and `D_beh/anomalous_window`.

**Classes that didn't appear,** because their scenarios aren't scripted yet: D_hash, D_load, D_cap, D_net and binding failures. Your scores for them (Q4) are still untested on real data.

### 3.2 attack-2 gives several D_beh per run

attack-2's burst writes about 900 files in 20 s. ML-B windows close at 200 events, so one burst fills 4–5 windows, and each scored 0.838, above θ_A = 0.657, with the range guard also firing. Every D_beh carries its window's start and end in `clause.detail`.

**Suggestion:** treat consecutive D_beh from the same `container_id` and `pid` within about 60 s as **one alert, or one chain**, so the operator sees one attack-2, not five. Whether S_beh then takes the maximum or the first is your call. The cap at 59 (Medium, M2) still holds.

### 3.3 A D_beh after its scenario's row

attack-1's payload `/tmp/.x9` keeps running after attack-1's row ends. Its ML-B window (3 events) closed about 30 s later and scored 0.663, above θ_A, so it's a D_beh with exe `/tmp/.x9` and **no** ground-truth row around it.
- It's the same process as attack-1's `D_exec/undeclared` and `D_write`: **same `pid`**.
- `time` is the end of the window, as `ROLE3-TO-ROLE4.md` §2 said.
- **Chain on `pid` (and `container_id`) within your 60 s rule,** and it joins attack-1's chain. If you chain by row membership, it ends up alone.

Role 1 has been asked to end the payload or keep the row open longer, but the chain rule should handle it anyway.

### 3.4 The controller (Q5 answered)

- After a `kubectl rollout restart`, the old pod's entry was removed from `bindings.json` and the new one appeared within seconds, `verified: true`.
- A replay that used today's `bindings.json` therefore reported the old pod as `binding/unknown_container` ("end of stream"). That's an artefact of replaying with today's bindings; live, the node counts such events as `after_unbind`.
- **PH4-04 (envelope eviction at 0 replicas) can now be run live.**

## 4. What to do next, in order

1. **Run your tests on the real run folder**, on Role 3's VM or a copy of `run/`:
   ```bash
   PROVBIND_RUN=<run folder> pytest -q tests/capability/test_ph5_13_mlb_07_scenarios.py
   ```
   - **PH5-13:** attack-1's D_exec and D_write share a `chain_id`. Check that the late D_beh from §3.3 joins them.
   - **MLB-07:** no D_beh outranks a contradiction (S_beh capped at 59).
   - Run your other PH5 and E2E tests with the same `PROVBIND_RUN`.
2. **Decide how D_beh bursts become alerts** (§3.2), and add the `pid` chain rule (§3.3) if it isn't already there.
3. **Q4: confirm scores** for the classes not yet seen on real data: D_load, D_cap, D_net, D_beh, `binding/unverified` and `binding/no_envelope`.
4. **Make `make demo` work on VMs like this one** (§5).
5. **Neo4j didn't restart after a reboot.** The alert engine fell back to the envelope correctly ("using the envelope meanwhile"); worth noting in the demo notes.

## 5. `make demo` on this VM

`scripts/demo.sh` applies the **namespaced** policies by default. On Role 3's VM they load but never fire: Tetragon's policy filter couldn't match pod cgroups (`failed to find cgroup id`), and `tetra tracingpolicy list` shows NPOST 0. The demo then gets exec events only: no D_write, and no ML-B input. What works there:
```bash
POLICIES="$PROVBIND_RUN/write-all.yaml $PROVBIND_RUN/truncate-all.yaml $PROVBIND_RUN/cap-all.yaml" \
MLB=--mlb DEMO_REF=localhost:5001/demo-app@sha256:4ce219578835e2432dbfa180b096bf823fbf48609dc7c2c7c1299e7a32b566dd \
make demo
```
then `kubectl delete tracingpoliciesnamespaced -n demo --all`, so the two policy sets don't double events.

- **`MLB=--mlb` only works on Role 3's VM,** where the model for that digest lives: `run/envelopes/4ce21957….mlb/model.json`.
- **A demo-step check would catch this early:** after deploying, check `tetra tracingpolicy list` for a non-zero NPOST, or check that the node's summary has `write` events.

## 6. Checklist

- [ ] PH5-13 and MLB-07 run on the real run folder (§4.1)
- [ ] D_beh bursts grouped into one alert or chain per run (§3.2)
- [ ] Chains on `pid` + `container_id` + time, so the late D_beh joins attack-1 (§3.3)
- [ ] Q4 scores confirmed for the unseen classes
- [ ] `make demo`: the POLICIES override documented, or a check that policies fire (§5)
- [ ] PH4-04 live (Q5 is answered: the controller removes bindings)
