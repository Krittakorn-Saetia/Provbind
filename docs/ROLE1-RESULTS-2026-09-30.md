# PROVBIND first scored run: Role 1 results, 30 September 2026

**From:** Role 1 (testbed and evaluation) · **For:** the team and the supervisor
**Run:** `make scored` with `ROUNDS=5`, on the demo VM (see Setup). The raw run folders are kept off git
(CLAUDE.md); they are in the results bundle `provbind-results-20260930-1003.tar.gz`.

## 1. Headline

20 scored runs, balanced: 10 malicious (attack-1 ×5, trust-1 ×5) and 10 benign (benign-1 ×5, ph4-14 ×5).
"Detected" means a PROVBIND alert above Low, or any Falco rule (Sprint Handoff §5).

| System | TP | FP | FN | TN | Precision | Recall | F1 | FPR | Accuracy |
|---|---|---|---|---|---|---|---|---|---|
| **PROVBIND** | 10 | 2 | 0 | 8 | 0.83 | 1.00 | **0.91** | 0.20 | 0.90 |
| PROVBIND w/o D_cap (ablation) | 10 | 0 | 0 | 10 | 1.00 | 1.00 | 1.00 | 0.00 | 1.00 |
| **Falco** | 5 | 5 | 5 | 5 | 0.50 | 0.50 | **0.50** | 0.50 | 0.50 |

Runtime scenarios only (trust-1 left out, since Falco has no supply-chain check; 5 malicious and 10 benign):
PROVBIND F1 0.83 (FPR 0.20), PROVBIND w/o D_cap F1 1.00, Falco F1 0.67 (FPR 0.50).

| Scenario | Truth | Runs | PROVBIND | w/o D_cap | Falco |
|---|---|---|---|---|---|
| benign-1 | benign | 5 | 1/5 | 0/5 | 5/5 ("Terminal shell in container") |
| attack-1 | malicious | 5 | 5/5 | 5/5 | 5/5 ("Drop and execute new binary") |
| trust-1 | malicious | 5 | 5/5 | 5/5 | 0/5 |
| ph4-14 | benign | 5 | 1/5 | 0/5 | 0/5 |
| tamper-1 | integrity check, not counted | 1 | `verify_log` passed before the edit and failed after it | | |

**Reading it:**
- PROVBIND detected every malicious run. Falco missed every trust-1 run: it has no notion of an advisory
  against a dependency.
- On the runtime attack (attack-1) both detected 5/5: the payload drops and runs a new binary, which is
  exactly Falco's rule. PROVBIND's added value there is attribution: each alert names the package
  (`pkg:pypi/requestz-helper@0.1.0`), its image layer and the builder, and D_exec and D_write share one chain.
- PROVBIND's two false positives are both D_cap (Section 3.2). Falco's five are its shell rule firing on
  a routine `kubectl exec`, which is what benign-1 was designed to show.

## 2. What worked end to end (Sprint Handoff §8, all seven "done when" checks)

Signed and attested image (cosign signature, CycloneDX SBOM with 87 dependency entries, SLSA provenance,
Rekor entry) → controller binding and envelope → Tetragon → node → alerts:
D_exec undeclared `/tmp/.x9` (90), D_write `/etc/passwd` (72) in the same chain, two benign Lows, a trust
alert naming the component (70), and a hash-chained violation log that `verify_log` rejects after a
one-character edit.

## 3. Findings

### 3.1 Bugs that only real deployment showed (all fixed on `claude/zen-hypatia-pyrg25`)

| Commit | Part | Bug and effect |
|---|---|---|
| `fd5866c` | node/tetragon (R3) | `returnArgAction: "Post"` is rejected by Tetragon 1.7.1, so every policy was in `load_error`: **no write or capability events at all** (no D_write, no ML-B input) |
| `5bf4716` | node (R3) | runc (1.2+) re-executes itself from a memfd for `kubectl exec`: `/proc/self/fd/7 init` scored as a CRITICAL D_exec in benign-1. Only that exact shape (memfd path, argument `init`, runc/crun parent) is dropped; a memfd exec by a container process is still verified |
| `55d9ef3` | node (R3) | Tetragon names capability 1 `DAC_OVERRIDE` (no `CAP_`), so it could never match the envelope |
| `d073953` | scripts/demo.sh (R4) | `kubectl apply -f a b` put two files after one `-f`; `make demo` stopped at step 0 |
| `6974a58` | Makefile (R1) | `make up` applied the policies before the Tetragon operator had installed the CRD |
| `f880171` | testbed/demo-app (R1) | `pip install --no-index` needs `--no-build-isolation` (the base image ships setuptools) |
| `6583ef6` | eval/report.py (R1) | `make report` warned on `results/SCORING.json` |

### 3.2 D_cap is not trustworthy on this setup

- On kernel 7.0 with Tetragon 1.7.1, `cap_capable` returned 0 ("granted") for `CAP_SYS_ADMIN` (234 times)
  and `CAP_DAC_READ_SEARCH` (14 times) in the app's `python`, while the process's `CapEff` was
  `0x00000000a80425fb` (the default container set, which has neither). The reported return value
  therefore cannot be read as "granted" here.
- Independently, without ML-A profiling the envelope lists no capabilities, so every real capability
  use (for example `CAP_DAC_OVERRIDE`) is a D_cap (ROLE1-READINESS §3).
- Hence the ablation row. **Proposal for Role 3:** decide "granted" from the process's effective set
  (Tetragon `enableProcessCred`) instead of the return value, then re-measure.

### 3.3 Falco's clock drifts inside a VirtualBox VM

The first scored run (`run-scored1-falco-drift` in the bundle) reported Falco at FPR 0.00. The check
showed Falco's timestamps late by +11 s in round 1, growing about 2 s per round (≈ 1 s per minute), so
each benign-1 shell alert slid into the following attack-1 window. Tetragon's timestamps were within
0.6 s throughout. With VirtualBox's time sync stopped (`vboxadd-service`, `systemd-timesyncd`) and
Falco restarted, the offset held at 1.0 s over 5 minutes, and the rerun above counted all five.
**Anyone comparing tools by time window on a VM must check each tool's clock against the scenario
windows**; the snapshot pauses made it worse (≈ 72 s after two snapshots).

## 4. Limitations

1. **Shortened run.** ML-A profiling and ML-B training (D2) were skipped: attack-2 is not tested, and
   D_cap had no learned capabilities.
2. **Scale.** One demo application, four scored scenarios, five repetitions each: a proof of concept.
3. **Dataset (D6).** Datadog's dataset was used only as behaviour references and package names
   (`testbed/behaviours.md`); no real malicious sample was run (Test Plan §12.4).
4. **Environment.** VirtualBox VM, kernel 7.0 (the team tested on 6.8), kind; the clock and capability
   findings above are specific to it until reproduced elsewhere.

## 5. Next steps

1. Full run with `make profile` (≈ 2.5 h) and D2 (`make loadgen`, 4 h + the held-out hour), then attack-2.
2. D_cap from the effective capability set (3.2), then re-score.
3. More scenarios from the Datadog behaviour map, still without real samples.
4. Roles 3 and 4 review the fixes to their code (3.1).

## 6. Setup and how to reproduce

Windows host, VirtualBox 7.2 with Hyper-V off (VT-x), Ubuntu 24.04.5, kernel 7.0.0-34-generic, kind
v0.33.0, kubectl v1.37.1, helm v3.22.0, Tetragon v1.7.1, Falco (modern eBPF), cosign, syft 1.52.0,
Python 3.11.16. Demo image `localhost:5001/demo-app@sha256:0da2781ec5d2a645f40bae62a93db22c6b1b0f586873256229ed9eea2629439f`.

```bash
make up                                     # cluster, registry, Tetragon + policies, Falco, Neo4j
make demo-app                               # prints DEMO_REF
sudo systemctl stop vboxadd-service systemd-timesyncd      # VM only: stop clock adjustments
kubectl rollout restart ds/falco -n falco                  # and restart Falco after any VM pause
DEMO_REF=<ref@digest> ROUNDS=5 make scored  # in a fresh run folder; writes results/SCORING.md
```
