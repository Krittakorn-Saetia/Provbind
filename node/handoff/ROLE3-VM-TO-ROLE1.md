# Handoff from Role 3 to Role 1: demo-VM results, the data, and what to do next

**From:** Role 3 (node runtime). **For:** Role 1 (testbed and evaluation). **Date:** 1 October 2026.

This follows `ROLE3-TO-ROLE1.md` (28 September). That file still holds for the recipes; this one adds what the first real run on Role 3's demo VM produced, and what you can do with it.

## 1. The short version

- The node now runs end to end on a real cluster:
  - attack-1 and attack-2 are caught in every round;
  - benign rows raise nothing above Low;
  - 9.5 hours of `make loadgen` raised **0 detections**.
- **11 PH4 tests are `not_run` only because their scenarios have no scripts yet** (§4). That's the biggest open item, and it's yours.
- Three VM findings may affect your runs too (§5): kind's start-up hook, namespaced policies that never fire, and Neo4j not restarting.
- The data is on Role 3's VM; how to get it is in §2.

## 2. The data

### On GitHub
| PR | What |
|---|---|
| [#22](https://github.com/Krittakorn-Saetia/Provbind/pull/22) | ML-B dataset D2: `ml/data/mlb/4ce21957…/{train,validation,heldout}.jsonl`, 261 / 113 / 140 windows. **Merge [#21](https://github.com/Krittakorn-Saetia/Provbind/pull/21) first** |
| [#23](https://github.com/Krittakorn-Saetia/Provbind/pull/23) | `node/ROLE3_STATUS.md`: every result and finding below |

### On Role 3's VM (`~/Provbind/run/`), shared privately, not through git
These files hold host details (paths, node names), so they don't go into the repository. Ask Role 3 for the archive:
```bash
tar czf ~/provbind-role3-run-2026-10-01.tgz -C ~/Provbind/run \
  envelopes bindings.json ground_truth.csv detections.jsonl alerts.jsonl log results rec.jsonl d2 \
  write-all.yaml truncate-all.yaml cap-all.yaml
```

| File | What it is |
|---|---|
| `rec.jsonl` | Tetragon recording of the scenario session: 21 min, 2,967 events in `demo` |
| `ground_truth.csv` | 16 rows: 3 × benign-1, attack-1, attack-2, ph4-14, trust-1, then tamper-1 |
| `detections.jsonl` | the node's detections. **the earlier ones come from setup and from before the kind-hook fix**: use only those from the first `ground_truth.csv` row on |
| `alerts.jsonl`, `log/violations.jsonl` | Role 4's output for the same session (tamper-1 has already edited the log) |
| `results/*.json` | the recorded capability results |
| `d2/` | the ML-B recordings: `benign-1.jsonl` (4 h), `benign-1b.jsonl` (3 h), `benign-2.jsonl` (2.5 h held out), their windows and `node.run` summaries |
| `envelopes/4ce21957….json`, `envelopes/4ce21957….mlb/model.json` | the demo app's envelope and its ML-B model |
| `*-all.yaml` | the cluster-wide policies used (§5.2) |

The demo image is `localhost:5001/demo-app@sha256:4ce219578835e2432dbfa180b096bf823fbf48609dc7c2c7c1299e7a32b566dd`. It lives in the local registry on Role 3's VM.

## 3. What the run showed (your E2E view)

| Scenario (×3) | Node | Matches your expectation? |
|---|---|---|
| benign-1 | 3 × `D_exec/outside_closure` per run (`sh`, `ls`, `cat` from its `kubectl exec`), Low | ✔ "nothing above Low" |
| attack-1 | `D_exec/undeclared` `/tmp/.x9` + `D_write` `/etc/passwd`, every run | ✔ |
| attack-2 | 3, 5 and 5 `D_beh`; no deterministic detection | ✔ MLB-05 pass |
| ph4-14 | 1 × `outside_closure` `sh` (its `kubectl exec`); no detection for `/tmp/new.txt` | ✔ PH4-14 pass |
| trust-1 | nothing from the node | ✔ (the alert comes from Role 4) |

Falco was **not** captured in this session (`eval/capture_falco.sh` wasn't running), so `make compare` would have no Falco column for it.

## 4. What to do next, in order

1. **Write the missing scenario scripts.** These test IDs record `not_run` until a ground-truth row exists:

   | Scenario | Test | What it must do (harmless only, Test Plan §12.4) | Node expects |
   |---|---|---|---|
   | attack-3 | PH4-07, 09, 18 | copy a declared binary to a new path (e.g. `ls` → `/tmp/.l`) and run it | `D_exec/undeclared` now; `D_hash/relocated` once R3-T9 exists |
   | attack-4 | PH4-08 | overwrite a declared binary (e.g. `/usr/bin/ls`), then run it | `D_write` now; `D_hash/modified` with R3-T9 |
   | attack-5 | PH4-10 | run python with `LD_PRELOAD=/tmp/libx.so` (a harmless library) | `D_load/undeclared` (needs `load.yaml`) |
   | attack-6 | PH4-15 | `os.chown` a file to uid 4242 | `D_cap` (`CAP_CHOWN`), INFERRED |
   | attack-7 | PH4-16 | connect to `203.0.113.9:4444` (TEST-NET, nothing answers) | `D_net` (needs `connect.yaml` and `PROVBIND_EGRESS`) |
   | attack-9 | PH4-03 | a pod in `demo` that the controller can't verify (unsigned image) | `binding/unverified` (or `unknown_container`) |
   | benign-3 | PH4-11 | a DNS lookup from the app | `D_load/outside_closure` (weak); the DNS connect allowed |
   | benign-4 | PH4-13 | writes to a mounted volume (e.g. `/app/data`) and to `/etc/hosts` | nothing |

   - **Trigger them through the app's endpoints** (`app_curl`), like attack-1 and attack-2, **not** with `kubectl exec`. Every `kubectl exec` adds its own `sh` and `ls` execs to the row: that's where benign-1's and ph4-14's Lows come from.
   - `node/synth.py`'s `library()` has a synthetic version of each, with the expected outcome in its docstring.
   - attack-5, benign-3 (load) and attack-7 (connect) need `load.yaml` and `connect.yaml`, which the demo leaves off. Record those in a separate session, then remove the policies again, because they change ML-B's input.

2. **Keep the 40 s gap between scenarios.** ML-B windows are 30 s per process. With 40 s gaps, no window mixed two scenarios, and no benign row got a D_beh.

3. **attack-1's payload outlives its row.** `/tmp/.x9` keeps running after attack-1's row ends. Its ML-B window closed about 30 s later and scored a D_beh outside every row ("between rows" in a time-window match). Either kill the payload at the end of `attack.sh`, or keep the row open about 35 s longer. Otherwise a time-window comparison counts it as unmatched.

4. **Your ML-A labels and kind's hook (please check).** runc runs `/kind/bin/mount-product-files.sh` inside every new container, and it uses `CAP_SYS_ADMIN` (§5.1). `testbed/profiling` filters only `is_runtime_init`. Your rule "a process holding more than a default pod can is the runtime" probably removes it already. Check that no label came from a process whose exe is under `/kind/bin/` or whose parent is that script.

5. **`make scored` can now include attack-2**, but only on Role 3's VM. The ML-B model is tied to the image digest `4ce21957…`, and a rebuild gives a new digest with no model. On your own VM you'd need your own D2: `ml/data/mlb/README.md`, about 9.5 h at your app's rate (§6).

6. **Fill in `testbed/VERSIONS.md` (Demo PC column)** from Role 3's VM: Ubuntu VM on VirtualBox, kernel 6.14, cgroup v2 with systemd, kind v1.37, Tetragon 1.7.1, policies cluster-wide.

## 5. VM findings that may affect your setup

1. **kind's start-up hook was scored as the app.** One demo-app start gave 182 false detections (`D_cap CAP_SYS_ADMIN`, `D_exec`) from `/kind/bin/mount-product-files.sh` and its `mount`, `jq` and `cp`. Fixed in the node by [#20](https://github.com/Krittakorn-Saetia/Provbind/pull/20). Your VM may not have shown it, because only pods that start while the node runs are affected.
2. **The namespaced policies loaded but never fired** (`tetra tracingpolicy list`: NPOST 0) on Role 3's VM (kernel 6.14). Tetragon's policy filter couldn't match pod cgroups (`failed to find cgroup id`), and `cgidmap` made it worse. The workaround is cluster-wide copies of the same policies:
   ```bash
   kubectl delete tracingpoliciesnamespaced -n demo --all
   for f in write truncate cap; do
     sed -e 's/^kind: TracingPolicyNamespaced/kind: TracingPolicy/' -e '/^  namespace: demo$/d' \
         -e 's/name: provbind-/name: provbind-all-/' node/tetragon/$f.yaml > $PROVBIND_RUN/$f-all.yaml
   done
   kubectl apply -f $PROVBIND_RUN/write-all.yaml -f $PROVBIND_RUN/truncate-all.yaml -f $PROVBIND_RUN/cap-all.yaml
   ```
   **Check with `tetra tracingpolicy list` after `make up`:** if NPOST stays at 0 while the app writes, you need the same workaround. `make up` and `scripts/demo.sh` apply the namespaced files; pass `POLICIES="…-all.yaml …"` to `make demo` and `make scored`. A `make up` option for this would help everyone, since the Makefile is yours.
3. **Neo4j didn't come back after a reboot.** `make up` starts it without a restart policy. Suggest `--restart unless-stopped` in the `docker run` line.
4. **VirtualBox:** stop `systemd-timesyncd` before long runs, as your 30 September results say. On Role 3's VM the `vboxadd-service` unit doesn't exist under that name.

## 6. D2 at your app's rate

The demo app produces kernel events only on `/cache` requests (15% of `make loadgen`), so it makes about **53 ML-B windows per hour**. Reaching the 360 windows Test Plan §12.2 asks for took **7 h** of benign load (4 h + 3 h, one pod), plus 2.5 h held out. If you change `loadgen.sh` (for example more `/cache`), keep D2 and the demo on the same load mix.

## 7. Checklist

- [ ] Scripts for attack-3 to attack-7, attack-9, benign-3 and benign-4 (§4.1)
- [ ] attack-1: end its payload, or keep the row open longer (§4.3)
- [ ] ML-A labels checked for kind's hook (§4.4)
- [ ] `tetra tracingpolicy list` checked on your VM; a `make up` option for cluster-wide policies (§5.2)
- [ ] Neo4j restart policy (§5.3)
- [ ] `testbed/VERSIONS.md`, Demo PC column (§4.6)
- [ ] Falco capture running for the next scored session
