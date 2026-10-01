# Handoff from Role 3 to Role 2: demo-VM results, the envelope at runtime, and ML-A evidence

**From:** Role 3 (node runtime). **For:** Role 2 (evidence, compiler, ML-A). **Date:** 1 October 2026.

This follows `ROLE3-TO-ROLE2.md` (28 September), which still describes how the node reads the envelope. This file adds what the first real run on Role 3's demo VM showed about your envelope and ML-A, and what you can do with the data.

## 1. The short version

- **Your pipeline worked end to end on the VM.**
  - `make demo-app` built and signed the image, attached the SBOM, SLSA provenance and Rekor entry.
  - `compiler.compile` wrote an envelope that the node loaded straight away.
  - The controller verified everything ("the Rekor inclusion proof verifies").
- **ML-A removed every capability false positive in this run.** The ML-A envelope (`CAP_DAC_OVERRIDE`, INFERRED, p = 0.9998) gave **0 D_cap over 567 capability checks**: 508 in the scenario session and 59 in the benign runs (§3).
- **A finding about paths (PH4-01):** Tetragon reports the path a program was *started with*, not the real file. Your envelope's `symlinks` are what keeps the verdicts right; one gap is left (§4).
- MLA-07 can now be run on real data, with one more compile (§5).

## 2. The data

The demo image is `localhost:5001/demo-app@sha256:4ce219578835e2432dbfa180b096bf823fbf48609dc7c2c7c1299e7a32b566dd`, built from `main` at `7e013f0` and signed with the team key.

**The compile, on Role 3's VM:**
- 5,694 files, 506 symlinks, 5 in the closure, 109 packages (11% unresolved);
- 14 SBOM components without a purl (Simple Launcher, the `cli`/`gui` launchers);
- 9.9 s in total.

**Capabilities: from ML-A (confirmed).** The first compile, without `ml/model`, printed "caps: curated allowlist". After `python -m ml.train --data ml/data/dataset.jsonl --out ml/model` and a recompile, the envelope holds `[{"cap": "CAP_DAC_OVERRIDE", "origin": "INFERRED", "probability": 0.9998}]`: the same prediction as Role 1's result. `ml/model/` is not committed; anyone can rebuild it from `ml/data/dataset.jsonl` (Role 1's D1) in a minute.

**Files on Role 3's VM** (`~/Provbind/run/`, shared privately, not through git):
- `envelopes/4ce21957….json`: the ML-A envelope the node used;
- `rec.jsonl` and `ground_truth.csv`: the scenario session, with `cap.yaml` applied;
- `d2/benign-*.jsonl`: 9.5 h of benign load.

Ask Role 3 for the archive. The command is in `ROLE3-VM-TO-ROLE1.md` §2.

## 3. ML-A at runtime: 0 D_cap

| Recording | Capability checks (`cap_capable`) | D_cap |
|---|---|---|
| D2, first 4 h | 59 | 0 |
| Scenario session (3 rounds) | 508 | 0 |

- **Why "granted" holds up:** the node treats a check as granted only when the capability is in the process's own effective set (Tetragon `enableProcessCred`, `process.cap`). That's Role 1's fix of 30 September, now in `node/normalize.py`.
- **Before #20,** one pod start alone gave 176 D_cap (`CAP_SYS_ADMIN`). That came from kind's start-up hook, not from the app; [#20](https://github.com/Krittakorn-Saetia/Provbind/pull/20) removes it.
- **What this does and doesn't show:** with ML-A, the envelope's list covered every capability the app really used. **attack-6 (chown to uid 4242) was not run**: Role 1 has no script yet. So we've shown "no false D_cap", not "D_cap catches an attack". That's PH4-15's job, once the scenario exists.

## 4. Paths: the PH4-01 finding

- **What happens.** Tetragon 1.7.1 reports `exec` paths as invoked. In the demo image `/usr/bin/sh` is a symlink to `dash`, and every `sh` arrives as `/usr/bin/sh`. The exec event has no other path field. PH4-01's "every exe is a real path" therefore fails, on 6 of 15 exec events.
- **Why the verdicts are still right.** The node resolves runtime paths through your envelope's `symlinks` with `compiler.paths.realpath`, so `sh` became `/usr/bin/dash`: declared, outside the closure, Low. **Keep `symlinks` complete and keep `realpath`'s interface.**
- **The gap.** The node resolves symlinks as they were in the image. If an attacker repoints one inside the running container (for example `/usr/bin/sh` → `/tmp/evil`, then runs `sh`), it resolves to `dash` and scores Low.
  - No policy sees it: making a symlink isn't a write, and nothing hooks symlink, rename or unlink.
  - The fix is R3-T9, runtime hashing: the hash of the file actually executed won't match `files["/usr/bin/dash"].sha256`. **So `files[].sha256` for every executable becomes load-bearing.** It's already there; please keep it for every regular file.
- **`CLAUDE.md`'s rule** "paths inside containers are real absolute paths" holds for the envelope's keys, which is your side, and was right. It doesn't hold for Tetragon's events. A proposed update-log entry is in `node/ROLE3_STATUS.md`; whether it goes in is the team's call.

## 5. What to do next, in order

1. **Run MLA-07 on the real data.** It compares D_cap per benign scenario between the ML-A envelope (the one on the VM) and an allowlist envelope, which needs a second compile of the same image in a separate run folder:
   ```bash
   PROVBIND_CAPS_MODEL=none python -m compiler.compile "$DEMO_REF" --run ~/mla07-allowlist
   PROVBIND_RUN=~/Provbind/run PROVBIND_RECORDING=~/Provbind/run/rec.jsonl \
   PROVBIND_MLA07_ENVELOPES="$HOME/Provbind/run/envelopes/<hex>.json,$HOME/mla07-allowlist/envelopes/<hex>.json" \
     pytest -q tests/capability/test_mla_07_dcap_per_method.py
   ```
   Run it on Role 3's VM, or on a copy of the run folder: it needs `bindings.json` and `ground_truth.csv` from there.
2. **Record the envelope's counts** from the archive copy:
   ```bash
   python -c "import json; e=json.load(open('envelopes/<hex>.json')); print(e['capabilities']); print(len(e['files']), 'files', len(e['symlinks']), 'symlinks', len(e['packages']), 'packages')"
   ```
   The capability list is `CAP_DAC_OVERRIDE` (INFERRED, 0.9998).
3. **Unresolved packages.** 11% of packages have no depth, and 14 components have no purl. Detections in those files get `context.depth: null`, so Role 4 scores ρ = 0.5. Nothing in this run hit one, but it's worth a look if it's cheap.
4. **Decisions still open with you** (unchanged from 28 September):
   - `allowed_caps` (decision 4);
   - egress in the envelope (M8, MLA-08). Without it, D_net has nothing to check without an operator list, and PH4-16 stays blocked.
5. **R3-T9 (Role 3) will lean on `files[].sha256`.** If the compiler ever skips hashing large files or special cases, tell Role 3 first.

## 6. Checklist

- [ ] MLA-07 run with the ML-A and allowlist envelopes on the real recording (§5.1)
- [ ] Envelope counts recorded (§5.2); the capability source is confirmed: ML-A
- [ ] `symlinks`, `files[].sha256` and `compiler.paths.realpath` kept as they are (§4)
- [ ] Decisions: `allowed_caps`, egress (§5.4)
