# PROVBIND live demo: briefing and likely questions

A refresher on the whole project, the demo in technical detail, what we compare against, what the demo
leaves out and why, and the questions you may get. The steps are in `docs/LIVE-DEMO-CHEATSHEET.md`.
Every number here comes from the final evaluation (`docs/PROVBIND-Capability-Test-Plan.md` §10.3,
`docs/ROLE1-SUPERVISOR-QUESTIONS-2026-10-05.md`).

## 1. The project in one minute

**One sentence.** PROVBIND checks a running container against the signed record of what was built into
it, and raises an alert when the two disagree.

**The problem.** A supply-chain attack comes in through something already trusted: a dependency, a base
image or a build step. The payload is signed by the right identities and passes the same checks as
legitimate software. The 2024 xz-utils backdoor was correctly signed and built from the real repository,
and was found by accident. A signature proves where software came from, not what it does when it runs.

**The gap.** Build-time evidence (the SBOM, the build provenance, the layer digests) is checked once at
deployment and then ignored. Runtime monitors (Falco, learned anomaly detectors) work from rules or
from what they have seen before. They can say an event is unusual, but not which signed claim it breaks,
so they raise false alarms and cannot say where a bad file came from.

**The idea.** Keep the evidence after deployment and compile it into an **envelope**:
- the declared files, with their hashes and the image layers that introduced them;
- the package graph, with each package's dependency depth;
- the programs and libraries the entrypoint can reach (the *execution closure*).

Then ask of every kernel event: *does this contradict what was signed?*

**The claim.** Checking against a signed specification gives far fewer false alarms than learned anomaly
detection, and every alert names the clause it breaks, the package and the layer.

**The four contributions (C1 to C4 in the paper):**

| | Contribution | In one line |
|---|---|---|
| C1 | Specification compilation | the envelope is compiled from signed evidence in seconds, with no training |
| C2 | Runtime verification | every program start, code load, file write, capability use and connection is checked against the envelope |
| C3 | Attribution | alerts name the image layer, the package and its dependency path |
| C4 | Trust re-evaluation | trust is withdrawn when a key, builder or package goes bad, even after deployment |

The project is SF9-26, a senior project at SIIT, Thammasat University; the advisor is Aj Ohm.

## 2. How the whole system works

| Phase | Part (folder, role) | What goes in, what comes out |
|---|---|---|
| 1 | Pipeline (`pipeline/`, Role 2) | Build the image, push it, generate the SBOM (syft, CycloneDX) and the build provenance (SLSA v1: builder, commit). Sign the image and attest both with cosign; the signature is recorded in Sigstore's public transparency log, Rekor |
| 2 | Controller (`controller/`, Role 4) | For each pod, read the digest it really runs (never a tag) and verify: signature, SBOM attestation, provenance attestation, Rekor inclusion proof, key not revoked. Any failure means *not verified* (it fails closed). Writes `bindings.json` and `contexts/<digest>.json` |
| 3 | Compiler (`compiler/`, Role 2) | Verified evidence plus the image layers become the envelope, `envelopes/<digest>.json`: files (path, hash, layer), packages and depth, the execution closure, expected capabilities, the image's identity (builder, commit, Rekor entry) |
| 4 | Node (`node/`, Role 3) | Tetragon (eBPF in the kernel) reports program starts and, through hooks, file writes and truncation, capability checks, code loads and TCP connections. The node holds a container's events until its envelope is ready, then checks each one and writes `detections.jsonl` |
| 5 | Alerts (`alerts/`, Role 4) | Score each detection, attribute it (layer, package, depth, dependency path), chain related detections into one incident, write `alerts.jsonl` and the hash-chained log `log/violations.jsonl` |
| 6 | Trust loop (`alerts/trust.py`, Role 4) | Watches advisories (OSV format), the key's status, a builder denylist and the transparency records. Withdraws trust and raises a TRUST alert, while the runtime state can stay *conforming* |

You are Role 1: the test app, the scenarios, the evaluation and this demo.

**The detections the node can raise**

| Class | Meaning | Severity |
|---|---|---|
| `D_exec` undeclared | a program that is in no layer of the signed image ran | Critical, 90 |
| `D_load` undeclared | code that is in no layer was loaded for execution | Critical, 84 |
| `D_write` declared file | a file the image declares was modified | High, 72 |
| `D_exec` / `D_load` outside the closure | in the signed image, but outside what the entrypoint reaches | Low (at most 34): logged, not an alert |
| `D_cap` | a capability the envelope does not expect | |
| `D_net` | a connection to an address outside the egress allow list | |
| `D_beh` | ML-B: unusual behaviour that stays inside the envelope | |
| binding | the image failed verification, or a container has no binding or no envelope | High, 60 |
| trust | trust withdrawn (advisory, key, builder, transparency) | High, 70 |

Detections of the same container join one incident when a process is related to one already in it (same
process or its parent) and they come within 60 s of each other.

**The two models**
- **ML-A** (in the compiler, LightGBM) predicts the capabilities an image needs where the evidence is
  silent; those expectations are labelled INFERRED. It is a feasibility result, and the paper's claims
  about it are softened.
- **ML-B** (in the node, Isolation Forest) screens windows of events that already passed the deterministic
  checks, to catch attackers who stay inside the envelope. It was trained on 7 hours of normal traffic and
  caught attack-2 (a burst inside the envelope) in all 5 runs.

**The tools:** kind (Kubernetes in Docker) with a local registry; Tetragon 1.7.1 as the sensor; cosign,
Sigstore and Rekor for signing; syft for SBOMs; Neo4j for the attribution graph (optional); Falco 0.45
for comparison; Python 3.11.

## 3. The demo, technically

**Setup.** One Ubuntu VM in VirtualBox runs everything: the kind cluster, the local registry, Tetragon
with the optimised (rate-limited) policies of the final runs, Falco, and the demo app. The demo app is a
small Python web app whose dependency, `requestz-helper`, is our harmless stand-in for a compromised
package. Our pipeline built and signed it: 8 layers, 5,695 files, 109 packages.

**The two screens**
- **Presenter terminal:** `make live-demo` (`scripts/live-demo.sh`).
- **Audience screen:** `make live-demo-view` (`eval/demo_view.py`). It shows one card per alert as it
  arrives, and a dim line for each Low record.

**What one `make live-demo` does before the acts**
1. Stops the previous run's services and moves `run-demo` aside as `run-demo.<date-time>` (the backup
   recording).
2. Applies the sensor policies.
3. Checks once per app start that Tetragon sees writes in the app, and restarts the app if not. After a
   reboot the app can start before Tetragon is ready, and Tetragon only applies its write checks to pods it
   saw start.
4. Starts five services: the controller, the node (fed by Tetragon's event stream), the alert engine, the
   trust loop and the Falco capture.

**The acts**

| Act | What triggers it | What the sensor and PROVBIND do | What you see |
|---|---|---|---|
| envelope | PROVBIND starts while the signed app runs | The controller lists the running pod and verifies 5 checks (about 5 s); the compiler builds the envelope (4 to 8 s) | `SBOM ok, provenance ok, signature ok, transparency log ok, signer trusted ok`, then `envelope compiled in N s`, the counts, the builder, commit and Rekor entry |
| shell | `kubectl exec` runs `sh -c "ls /; cat /etc/hostname"` inside the container | Tetragon reports 3 program starts (`sh`, `ls`, `cat`). They are in the signed image but outside the app's closure: 3 Low records, logged, no alert. Falco's "Terminal shell in container" rule fires | `PROVBIND: 0 alerts; 3 Low records`, then Falco's alert |
| trust | An OSV advisory, `MAL-2026-9001` for PyPI `requestz-helper` 0.1.0, is written to the trust loop's feed (`run-demo/advisories/`) | Within 2 s the trust loop matches it against `pkg:pypi/requestz-helper@0.1.0` in the envelope and raises a TRUST alert with the package, depth and layer. The runtime state stays CONFORMING | `trust withdrawn: component advisory`, `raised N s after`, `CONFORMING` |
| attack | `GET /update` through a port-forward | The app calls `requestz_helper.check_update()`, which writes an embedded static program to `/tmp/.x9` and runs it; it appends an inert line to `/etc/passwd` and sleeps 20 s. Tetragon reports the code load, the program start and the write | `CRITICAL 84` code loaded, `CRITICAL 90` program executed (both `/tmp/.x9`, in no layer), `HIGH 72` `/etc/passwd` modified with its layer, all one incident. Falco: "Drop and execute new binary in container" |
| log | `tamper.sh` | `verify_log` recomputes the SHA-256 chain (OK), one letter in a middle record changes (still valid JSON), `verify_log` stops at that record, and the original is restored | `log check: OK: N records`, then `BROKEN at record k=…` |

**Harmless by design.** Every attack is our own test code, and it acts only inside the throwaway demo
container. The line it adds to `/etc/passwd` has `/bin/false` as its shell, so it is no usable account.
Nothing is sent out. Real malicious samples are never downloaded or run (Test Plan §12.4). The attacks
re-create behaviours reported in the Datadog malicious-packages dataset. For example, attack-1 is the
drop-and-execute of litellm 1.82.7 and 1.82.8, which downloaded `/tmp/pglog` and ran it.

## 4. What we compare against

| System | How it took part | How it works |
|---|---|---|
| **Falco** | measured live, default rules | generic runtime rules (shell in a container, file writes under `/etc`, …), not tied to the image |
| **DeSFAM-E** | estimated: its published rules applied to our recorded system-call traces | a system-call allow list from about 30 minutes of profiling, plus an Isolation Forest over 15-call windows |
| **Confine-E** | estimated, the same way | a static allow list of the system calls the image's programs can make |
| **Ryu-E** | estimated, the same way | Ryu et al.'s detector: 5-call windows and a decision tree trained on normal traffic and known attacks |
| **Signature only** | derived from PROVBIND's own admission records | check the signature at deployment, nothing else |

DeSFAM, Confine and Ryu et al. have no usable public code for our setup. They are always labelled
*estimated*. Confine and DeSFAM guard the kernel boundary, not the supply chain, so the paper calls them
complementary.

**The final comparison** (`run-final`, 9 October): 19 scenarios, 5 runs each, 95 runs in all (65 attack,
30 normal).

| System | Attacks caught | False alarms | F1 |
|---|---|---|---|
| **PROVBIND** | **50 of 65** | **0 of 30** | **0.87** (precision 1.00, recall 0.77) |
| Ryu-E | 35 of 65 | 20 of 30 | 0.58 |
| DeSFAM-E | 34 of 65 | 23 of 30 | 0.56 |
| Falco | 25 of 65 | 10 of 30 | 0.50 |
| Signature only | 5 of 65 | 0 of 30 | 0.14 |
| Confine-E | 0 of 65 | 5 of 30 | - |

**By contribution**

| Contribution | Result |
|---|---|
| C1, time to protect a new image | PROVBIND 4.38 s; Confine-E 32.8 s; DeSFAM-E 30.5 min of profiling; Falco has only generic rules |
| C2, runtime attacks (40 runs) | PROVBIND 25 caught with 0 false alarms (F1 0.77; 20 without ML-B); DeSFAM-E 34 and Ryu-E 35, but with 23 and 20 false alarms out of 30. The claim is precision, not higher recall |
| C3, attribution | the layer is named in 15 of 15 alerts about image content, the package and dependency path in 10 of 15; none of Falco's 55 alerts names a package or layer |
| C4, trust (25 runs) | 25 of 25, at deployment or by the trust loop; median reaction 1.7 s (advisory) and 1.1 s (key). Signature only 5 of 25; the runtime detectors 0 of 25, because nothing in the container changes |
| Cost | requests: within 5% of Falco, worst +9.9% against no monitoring. Monitor CPU 0.2% of a core against Falco's 8.2%. 2.0 µs per event (median). Her et al.'s network test: +1.0% against Falco's +22.6% |

**The shell act matches the data:** in the shell scenario (benign-1), Falco, DeSFAM-E, Ryu-E and Confine-E
each flagged 5 of 5 runs; PROVBIND flagged none.

## 5. The full system compared with the demo

| Phase | In the full system | In the demo |
|---|---|---|
| 1 Build and sign | runs in CI for every commit | done beforehand (`make demo-app`); its evidence is verified in the envelope act |
| 2 Admission | Kyverno admits or rejects; the controller verifies the evidence beside it | the controller verifies; nothing is rejected. The optional `unsigned` act shows a failed verification |
| 3 Compiler | runs for every new image | shown live (envelope act) |
| 4 Runtime | program starts, code loads, writes, capabilities, connections, ML-B | program start, code load and write by default; connections with `ATTACK=egress`. Capabilities and ML-B are not shown |
| 5 Alerts | scoring, attribution (graph in Neo4j), incidents, hash-chained log, signed log checkpoints (opt-in) | all of it, except Neo4j (off: the same answer comes from the envelope) and the signed checkpoints |
| 6 Trust | advisory feeds, a real key service, builder denylist, transparency | a local advisory file, or the key's status in a file (`TRUST=key`) |
| Evaluation | 95 runs against five other systems | on the slides |

## 6. What the demo leaves out, and why

| Left out | Why |
|---|---|
| Building and signing (Phase 1) | It is standard tooling (docker, syft, cosign), and PROVBIND's own code starts at Phase 2. It takes minutes, needs the internet (Rekor) and the private signing key. Its evidence is checked live in the envelope act |
| Blocking at deployment | Kyverno enforcement was out of scope for the 4-day prototype ("say so plainly in the talk", Sprint Handoff §1.3). The prototype verifies and flags; it does not reject pods. Say "fails verification", never "blocked" |
| A real key service | Also out of scope; the key's status is simulated in `run/keystatus.json` |
| ML-B | Needs a model trained on 7 hours of traffic; its result (attack-2 caught 5 of 5) is on the slides |
| The measurements | They need the full 95-run test with the other systems side by side. One live run is a demonstration, not a measurement |
| Neo4j | Off in the demo: attribution from the envelope gives the same answer, and loading each run's graph made alerts wait |
| The three missed scenarios | PROVBIND does not catch them, so the screen would show nothing (see Q9) |

Also out of scope in the team's plan: overhead numbers on bare metal, the full SynthChain reconstruction,
the low-and-slow mimicry attack, and ML-A accuracy beyond a feasibility result.

## 7. Questions you may get

### About the idea

**Q1. Isn't signing images enough?**
A signature proves who built the image, not what it does. The xz-utils backdoor was signed. In our test,
the signature check alone caught 5 of 65 attacks: only the unsigned image.

**Q2. What exactly is in the envelope?**
Every file with its hash and layer; the packages and their dependency depth from the SBOM; the programs
and libraries the entrypoint can reach; the expected capabilities; and the image's identity (builder,
commit, Rekor entry). For our app: 8 layers, 5,695 files, 109 packages, 5 programs and libraries in the
closure.

**Q3. Why does it need no training?**
The rulebook is compiled from the evidence; nothing is learned. A new image is protected in 4.4 s, against
DeSFAM's 30 minutes of profiling.

**Q4. How do you know the evidence is genuine?**
At deployment PROVBIND checks:
- the signature;
- both attestations (SBOM and provenance);
- the inclusion proof of the signature's entry in Rekor;
- that the signing key is not revoked.

Any failure means *not verified*.

### Against other tools

**Q5. Why not just use Falco?**
Falco's rules do not know what the image should contain. It flagged the operator's shell in 5 of 5 runs
and every clean deployment in 5 of 5 runs (10 of 30 false alarms). None of its 55 alerts named a package
or layer. PROVBIND had 0 false alarms and named the layer in every alert about image content. F1 0.87
against 0.50.

**Q6. Don't the learned detectors catch more attacks?**
On runtime attacks, yes: DeSFAM-E caught 34 and Ryu-E 35 of 40, against our 25. But they flagged 23 and
20 of the 30 normal runs, and PROVBIND flagged none. Our claim is precision. Overall F1 is 0.87 against
0.56 and 0.58, partly because the 25 admission and trust problems are invisible to any runtime detector.

**Q7. What does "-E" (estimated) mean?**
DeSFAM, Confine and Ryu et al. have no usable public code for our setup. We applied their published
decision rules to system-call traces recorded from our own scenarios. Falco was measured live.

**Q8. Is that fair to Confine and DeSFAM?**
They guard the kernel boundary (privilege escalation, escapes), not the supply chain. We included a
kernel-exploit-shaped scenario (rk-2), which PROVBIND misses, and the paper calls them complementary.

### Limits

**Q9. What does PROVBIND not catch?**
Malicious code that is declared in the SBOM, stays inside the envelope and behaves like the app; the
threat model puts this out of scope. In our tests it missed 15 of 65 runs, from three scenarios:
- **ru-5:** a program only reads a credential file.
- **rk-2:** the system-call shape of a kernel exploit.
- **au-2:** a build step adds an undeclared program before signing; when it runs, it is only a Low record.

**Q10. What if the attacker only uses programs already in the image?**
They pass the deterministic checks because they are declared. A program outside the app's closure is
logged as Low. ML-B screens behaviour inside the envelope, and caught attack-2's burst in 5 of 5 runs.
Code that truly behaves like the app is out of scope.

**Q11. Does it stop the attack?**
No. It detects and alerts, within about a second. Rejecting pods at deployment (Kyverno) was out of scope
for the prototype.

**Q12. Can someone erase the evidence?**
Changing any record breaks the hash chain at that record, as the demo shows. Someone who can rewrite the
whole file could recompute the chain; signed checkpoints close that gap. They are implemented but opt-in,
and off in the demo.

**Q13. What does it cost?**
On requests, worst +9.9% against no monitoring and within 5% of Falco. Monitor CPU is 0.2% of a core,
against Falco's 8.2%, and each event takes 2 µs to check. Network test (UDP): +1.0% against Falco's
+22.6%. Weak spots: starting many programs costs +119% (Falco +16%), and memory is 409 MB against
Falco's 119 MB.

**Q14. Does it check network traffic?**
Only TCP connections, through a hook on `tcp_connect`. UDP sends are not checked, which is also why the
UDP test costs almost nothing.

**Q15. Does it check file hashes at run time?**
No. Tetragon reports paths, not hashes, so there is no runtime hash source. An overwritten program is
caught by the write itself: the `overwrite` attack gives a `D_write`.

### How it works

**Q16. How does PROVBIND know which image a process belongs to?**
Tetragon tags each event with its pod and container. The controller maps the container to the digest it
really runs, read from the running container and never from a tag, so a moved tag cannot redirect the
evidence. The digest leads to the envelope.

**Q17. Why is the operator's shell Low, not an alert?**
`ls` and `cat` are in the signed image, just outside the app's execution closure. That is unusual, but it
contradicts nothing that was signed, so it is logged for audit without an alarm. A program in no layer at
all, like `/tmp/.x9`, is Critical.

**Q18. Why three alerts for one attack?**
The dropped file was loaded as code (84), executed (90), and then the program changed `/etc/passwd` (72).
Detections from the same process tree within 60 s form one incident.

**Q19. Why does the `/etc/passwd` alert name a layer but no package?**
The file is created during the base image's setup, so no SBOM package claims it. The layer still proves it
belongs to the signed image.

**Q20. How does the trust loop work?**
Every 2 s it checks whether its inputs changed: advisories, the key's status, the builder denylist and the
transparency records. Every 5 minutes it checks everything again. Only a malicious-package advisory
(`MAL-…`) withdraws trust; an ordinary CVE is reported and trust stays.

**Q21. Is the key revocation real?**
It is simulated: the key's status is kept in a file. A real key service was out of scope.

**Q22. What do "transparency log ok" and the Rekor entry mean?**
The signature is recorded in Sigstore's public log, Rekor, and PROVBIND verifies its inclusion proof.
A signature therefore cannot be hidden or back-dated.

### About the demo

**Q23. Is this live?**
Yes. It runs on real Kubernetes (kind) on this VM, with the real kernel sensor (Tetragon), real signatures
and a real Rekor entry. The attack is our own harmless code, re-creating behaviour from real cases such as
litellm 1.82.7 and 1.82.8.

**Q24. Is requestz-helper a real package?**
No. It is our harmless stand-in for a compromised dependency. No real malicious sample is downloaded or
run anywhere.

**Q25. Why does it still say CONFORMING after trust is withdrawn?**
These are two separate states. The behaviour is still exactly as signed, but trust in the evidence is
gone. Keeping them apart is the point of C4.

**Q26. Why did you not build and sign the image live?**
It takes minutes, needs the internet and the private key, and it is standard tooling. PROVBIND starts at
Phase 2. The builder, commit and Rekor entry on the envelope card are the evidence that it happened.

**Q27. Why is the trust delay sometimes 0.1 s and sometimes 1.7 s?**
The loop checks every 2 s, so the delay depends on where in that cycle the advisory arrives.

**Q28. What would you do next?**
- Enforce at deployment with Kyverno, and use a real key service.
- Add a runtime hash source (for example IMA) and UDP coverage.
- Turn the signed log checkpoints on by default.
- Run more normal scenarios for a tighter false-alarm bound: 90 runs would bound it at 3.3% at 95% confidence.
