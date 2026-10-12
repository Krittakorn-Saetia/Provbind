# Next experiments: what to run on the VM (October 2026)

The supervisor asked for 3–4 experiments PROVBIND wins, with 7–8 tested in total. This page is the run
guide for the new ones. The plan is in the experiment-plan note of 12 October 2026, and the paper changes
are in the test plan, Section 10.

| # | Experiment | Status | Compared against |
|---|---|---|---|
| E1 | Supply-chain attacks caught, false alarms (19 scenarios × 5 runs) | done (`run-final`) | Falco, DeSFAM-E, Confine-E, signature check |
| E2 | Package, layer and dependency named in alerts | done | Falco, DeSFAM-E, Confine-E |
| E3 | Trust withdrawn while a workload runs | done | Falco, DeSFAM-E, Confine-E, signature check |
| E4 | Time to protect a new image | done | Falco, Confine-E, DeSFAM-E |
| E5 | Runtime cost on application requests | done (`opt5`) | no monitoring, Falco, Tetragon alone |
| E6 | Check time per event | done | — |
| **E7** | **Ryu et al. [17] rebuilt as Ryu-E** (joins E1) | **new, no new runs** | a 2026 journal detector |
| **E8** | **Her et al.'s network test** (100,000 UDP sends) | **new, about 30 min** | Falco, no monitoring, Her et al.'s published numbers |
| extra | Her et al.'s "time to apply a new policy" | optional, about 40 min | Falco, Her et al.'s published numbers |
| extra | 60 more benign runs (tighter false-alarm bound) | optional, about 3 h | every system, as in E1 |

Nothing already measured has to be run again: E1–E6 come from the final runs (detection 9 October, cost
8 October) and nothing has changed since.

## 0. Before you start

1. Start the VM and wait two minutes, then check the cluster:
   ```bash
   docker ps --format '{{.Names}}: {{.Status}}'   # kind-control-plane and kind-registry are Up
   kubectl get pods -A | grep -v Running          # only the header line is left
   ```
   If a container is missing, run `docker start <name>`.
2. Get the code and the Python environment:
   ```bash
   cd ~/Provbind && git checkout main && git pull
   source .venv/bin/activate && pip install -r requirements.txt
   ```
3. Set the demo image the final run used, and check it:
   ```bash
   export DEMO_REF=$(kubectl -n demo get deploy demo-app -o jsonpath='{.spec.template.spec.containers[0].image}')
   echo "$DEMO_REF"                               # .../demo-app@sha256:<64 hex characters>
   ls run-final/results/COMPARISON.json run-final/traces/baseline/benign-*.txt
   ```

Do not type in the terminal, run `kubectl exec`, or take a snapshot while a test runs.

## 1. E7: Ryu-E (no new runs, about 5–15 minutes)

It reads the system-call traces the final run recorded for DeSFAM-E and Confine-E:

```bash
python3 -m eval.baselines.ryu_estimate --run run-final
```

It prints a table with Ryu-E beside PROVBIND, Falco, DeSFAM-E, Confine-E and the signature check, and
writes `run-final/results/ryu.json` and `RYU.md`. How it works is in the module's help
(`python3 -m eval.baselines.ryu_estimate --help`):
- It is trained, like Ryu et al.'s detector, on labelled examples, but only on what is known before an
  attack: the normal-traffic recordings and the known attacks rk-2 and rk-3.
- Every run is scored without having been trained on.
- It also reports Ryu et al.'s own 70:30 protocol, for comparison with their published accuracy.

Optional second variant, with every window of an attack run labelled as the attack (exactly as Ryu et al.
label their malware containers):

```bash
python3 -m eval.baselines.ryu_estimate --run run-final --labels run \
  --out run-final/results/ryu-runlabels.json --summary run-final/results/RYU-runlabels.md
```

## 2. E8: Her et al.'s network test (about 30 minutes)

The same cost harness as `opt5`, with only the network workload: 100,000 UDP sends, timed 10 times, in
each configuration (no monitoring, Falco, Tetragon with PROVBIND's policies, PROVBIND), three rounds:

```bash
POLICY_SET=opt WORKLOADS=udp SKIP_PREP=1 PROVBIND_RUN=./run-final OUT_RUN=./run-network \
  scripts/overhead-run.sh 2>&1 | tee run-network.log
```

The report is `run-network/results/OVERHEAD.md`, with a section "Network test against Her et al." that
puts their published numbers beside ours. Check our Falco against theirs first (+19.9% in their paper): it
shows how far our setup reproduces theirs. Unlike their program, ours sends to a socket inside the pod,
not to a public DNS server, so no packet leaves the VM.

## 3. Optional: time to apply a new policy (about 40 minutes)

```bash
scripts/policy-update-test.sh 2>&1 | tee run-policy.log
```

- **Falco:** measured as Her et al. do. Falco gets one extra rule through `helm upgrade` 10 times, and
  each time we measure until the rule fires. After every run Falco is rolled back to its original
  settings.
- **PROVBIND:** each run deploys the demo app fresh and measures until its envelope is in force. PROVBIND
  holds the new pod's events until then and checks them afterwards.
- It needs the internet for Helm.
- If it is interrupted, the script rolls Falco back by itself. If that fails, it prints the
  `helm rollback` command to run.
- The report is `run-policy/results/POLICY-UPDATE.md`.

`SYSTEMS=falco` or `SYSTEMS=provbind` runs one half.

## 4. Optional: 60 more benign runs (about 3 hours)

These tighten "0 false alarms in 30 benign runs" (at most 10% at 95% confidence) to 90 runs (at most
3.3%). They run in a fresh run folder with the same settings as `run-final`, including its ML-B model.
bpftrace asks for the sudo password once. A-B1 signs its own image, so export the signing password first,
in your own terminal only (never paste it into a chat):

```bash
export COSIGN_PASSWORD=...        # your own terminal only
mkdir -p run-benign/envelopes && cp -r run-final/envelopes/*.mlb run-benign/envelopes/
POLICY_SET=opt MLB=1 ROUNDS=10 BASELINE_CYCLES=0 PROVBIND_RUN=./run-benign \
  ONLY="benign-1 benign-traffic ph4-14 benign-3 benign-4 ab-1" \
  scripts/comparison-run.sh 2>&1 | tee run-benign.log
```

Then score the estimated systems with the final run's normal-traffic recordings and the final run's
known attacks (for Ryu-E's training):

```bash
cp -r run-final/traces/baseline run-final/traces/binaries run-benign/traces/
PROVBIND_RUN=./run-benign scripts/rerun-estimators.sh
python3 -m eval.baselines.ryu_estimate --run run-benign \
  $(for f in run-final/traces/rk-2-*.txt run-final/traces/rk-3-*.txt run-benign/traces/*.txt; do echo --trace "$f"; done)
```

The false alarms per system are in `run-benign/results/COMPARISON.md` and `RYU.md`.

## 5. Send the results back

Only aggregate files, never a whole run folder, alerts, traces or keys:

```bash
mkdir -p docs/results/2026-10-next
cp run-final/results/ryu.json run-final/results/RYU.md docs/results/2026-10-next/
cp run-network/results/OVERHEAD.json docs/results/2026-10-next/network-OVERHEAD.json
cp run-network/results/OVERHEAD.md docs/results/2026-10-next/network-OVERHEAD.md
# if you ran them:
cp run-policy/results/POLICY-UPDATE.* docs/results/2026-10-next/ 2>/dev/null || true
cp run-benign/results/COMPARISON.json docs/results/2026-10-next/benign-COMPARISON.json 2>/dev/null || true
cp run-benign/results/COMPARISON.md docs/results/2026-10-next/benign-COMPARISON.md 2>/dev/null || true
cp run-benign/results/RYU.md docs/results/2026-10-next/benign-RYU.md 2>/dev/null || true
git checkout -b role1-next-results
git add docs/results/2026-10-next && git commit -m "Results of the next experiments (E7, E8)"
git push -u origin role1-next-results
```

## If something fails

| Message | Fix |
|---|---|
| `ryu_estimate: no normal-traffic recordings` | the run folder has no `traces/baseline/benign-*.txt`: use `--run run-final` |
| `No module named 'sklearn'` | `pip install -r requirements.txt` in the active environment |
| `overhead-run: ... exists; move ... aside first` | a previous attempt left `run-network`: `mv run-network run-network-old` |
| `the app's events do not reach Tetragon's stream` | restart Tetragon, wait a minute, run again (as for `opt5`) |
| `could not roll Falco back` | run the `helm rollback falco <revision> -n falco` command it prints |
| anything else | send the last 30 lines of the `.log` file |
