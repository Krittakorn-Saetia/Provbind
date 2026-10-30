# Fixes for the report draft DS3

For whoever edits the report (`Provbind_DS3.pdf`, compiled 30 October 2026, 16 pages). Checked against this
repository's results (`docs/figures/data/final-2026-10-09/`, `docs/results/2026-10-next/`) and code. Each fix
says where it goes and why, quotes the current text, and gives the replacement, ready to paste into the LaTeX
source. Test plan Section 10.4 records the same changes.

- **M**: must fix before submitting
- **S**: should fix; a reviewer would ask
- **P**: polish

## Already correct

- Every result number: detection counts and F1 over all 65 attack runs and over the 40 runtime attack runs,
  the known/unknown split, the three misses, the behavioural-path ablation (45/65, 20/40), the Ryu et al.
  variants (0.45 to 0.74; accuracy 0.79 against the published 0.98), the check time per event (2.0 and
  9.1 µs), the compile times, and the trust and cost tables.
- Table III (scoring parameters) matches `alerts/score.py`, and low-severity detections are left out of the
  detection counts, as Section V-D says (`eval/compare.py`).
- Every component in Table IV exists: the Neo4j graph, the Cuckoo filter, opt-in signed checkpoints, chain
  grouping, and the trust loop with ΔR = 300 s plus a 2 s input check.
- Table V: all 19 scenarios, their known/unknown labels and the expected mechanisms.
- Every table, figure, algorithm and equation reference resolves, and no reference prints as "?". The only
  wrong pointer is the one in M1.

## Must fix before submitting

### M1. The limitations that Section V-C points to are missing

**Where:** Section V-C and Section VII.

**Why:** V-C ends "implementation simplifications are discussed in Section VII", but Section VII does not
discuss them. The caveat that matters most went missing with the old Limitations section: our DeSFAM
re-implementation leaves out the parts that suppress false alarms, and without false alarms it would beat
PROVBIND on the runtime attacks (F1 0.92 against 0.77). PROVBIND's runtime win over DeSFAM rests on
DeSFAM's 23 false alarms, so without the caveat the report overstates. Test plan Section 10.3 asks for it.

(a) In Section V-C, replace `without its autoencoder stage;` with:

```latex
without its autoencoder, benign-pattern filter, or moving threshold;
```

(b) In Section VII, replace the paragraph that starts "The evaluation is limited to one application and
re-implemented baselines, while coverage remains constrained by ..." with:

```latex
The evaluation is limited to one application and to re-implemented
baselines. Our DeSFAM* omits its autoencoder, benign-pattern filter, and
moving threshold, the components that suppress false alarms; without any
false alarm, its runtime-only $F_1$ would be 0.92, above PROVBIND's 0.77,
so a closer re-implementation could narrow or reverse the runtime
comparison, although not the trust results. Ryu et al.* uses only its
host-based detector. Each scenario was repeated five times against one
service, so zero alerts in 30 benign runs bounds the false-positive rate
only below about 10\% at 95\% confidence. The trust experiments covered
key revocation and malicious-package advisories, not the builder and
transparency checks. Coverage remains constrained by SBOM completeness,
UDP support, and attacks that mimic permitted behavior. Process-intensive
workloads also incur higher overhead, and burst-induced event loss was not
evaluated.
```

### M2. E3 promises a comparison that is not shown

**Where:** Section VI-C.

**Why:** Table VI says E3 compares with "Falco; others by design", and the text says the re-implemented
baselines "are reported", but Table VII shows only PROVBIND.

Replace "Falco identifies the affected container, process, and triggering rule but does not provide package,
image-layer, or dependency-path attribution. The re-implemented baselines are reported according to the
attribution supported by their published designs." with:

```latex
All 55 of Falco's alerts identify the affected container, process, and
triggering rule, but none provides package, image-layer, or
dependency-path attribution. Following their published designs, DeSFAM*
attributes an alert to a container, a process, and an attack technique,
Ryu et al.* names the attack class that a container resembles, and
Confine* blocks system calls without raising alerts; none names a
package, layer, or dependency path.
```

### M3. Table VII claims a correctness check that the results do not show

**Where:** Table VII and Section VI-C.

**Why:** they say each attribution was checked against build-time ground truth. The exported results
(`figures.json`, `c3_attribution`) count only the alerts that *name* each field: the layer in 15 of 15, the
package and dependency path in 10 of 15. If nobody compared the 15 alerts with the build, either do that
check now (the attack files come from known Dockerfile steps), or make these changes:

- Delete the "Correct/Resolved" column of Table VII and the sentence "Correctness is measured against
  controlled build-time ground truth."
- Replace "PROVBIND correctly identifies the ground-truth introducing layer in all 15" with:

  ```latex
  PROVBIND names the introducing layer in all 15
  ```

- Replace "and all 10 resolved attributions match the ground truth" with:

  ```latex
  and PROVBIND names both for all 10
  ```

- Replace "Thus, PROVBIND achieves complete layer-attribution accuracy for applicable alerts and complete
  package/dependency accuracy when the required SBOM relationships are available," with:

  ```latex
  Thus, PROVBIND attributes every applicable alert to its image layer, and
  to its package and dependency path when the SBOM records them,
  ```

### M4. Reference [28] is never cited

**Where:** the bibliography.

**Why:** [28] (RFID authentication in physical supply chains) is listed but never cited, and it is off-topic
(test plan Section 10.3). Delete its `\bibitem` (key `b28`); the later references renumber automatically.

### M5. The abstract claims builder checks that no experiment tested

**Where:** the abstract.

**Why:** no experiment changed a builder, and the team agreed to soften untested claims in the abstract
(test plan Section 10.3).

Replace "detects post-admission changes in signing-key, builder, or component trust without requiring a runtime
deviation." with:

```latex
detects post-admission changes in signing-key or component trust without
requiring a runtime deviation.
```

## Should fix

### S1. The in-kernel rate limits are not described

**Where:** Section V-A; optionally Section VI-E.

**Why:** the overhead and detection results were measured with the rate limits in `node/tetragon/opt/`
(test plan Section 10.1, "Collection"), and they mean a repetition within a minute raises no new alert. The
report mentions only the namespace filter.

After "filtered in the kernel to the monitored namespace." add:

```latex
To reduce overhead, the collector reports a repeated identical write,
truncation, or capability event at most once per minute per process, and
an executable library mapping at most once per minute; the write,
truncation, and mapping hooks use no return probes. The first occurrence
of every event is always reported, but a repetition within the minute
raises no new alert.
```

Optionally, in Section VI-E after "...rather than PROVBIND's verification.", add this, since the supervisor
asked about the optimisation:

```latex
Without this filtering, the p95 latency of file-writing requests rose by
378\%.
```

### S2. The learned baselines also flag every normal-traffic run

**Where:** Section VI-B.

**Why:** DeSFAM-E and Ryu-E each flag all 5 normal-traffic runs (scenario `benign-traffic`, B2). The current
sentence suggests their false alarms come only from unusual activity.

Replace "Their false positives include legitimate but infrequent activity such as an operator shell,
DNS-triggered library loading, and creation of a file under /tmp." with:

```latex
Their false positives include every normal-traffic run as well as
legitimate but infrequent activity such as an operator shell,
DNS-triggered library loading, and creation of a file under \texttt{/tmp}.
```

### S3. The runs are repeats, not independent samples

**Where:** Section V-B. Replace "each executed independently five times" with:

```latex
each run five times
```

### S4. Scenario 6 was not traced either

**Where:** Section V-C.

**Why:** scenario 6 (build-generated execution, `au-2`) has no traces, so the trace-based baselines could not
see it. Every system misses it, so the ranking does not change.

Replace "Admission-stage scenarios are not traced, so trace-based baselines cannot observe them." with:

```latex
Admission-stage scenarios and scenario 6 were not traced, so trace-based
baselines cannot observe them; every system, PROVBIND included, misses
scenario 6.
```

### S5. The prototype signs no single bundle commitment

**Where:** Phase 1, Step 3.

**Why:** the prototype signs the image and attests the SBOM and the provenance separately, each bound to the
digest (`pipeline/build-and-attest.sh`). Property 1's argument still holds.

After Eq. (6) add:

```latex
In the prototype, $h_I$ and $\sigma_I$ are realized by Cosign signatures
over $d_I$, which commits to $M_I$ and $C_I$, and over in-toto
attestations of $B_I$ and $P_I$ whose subject is $d_I$.
```

### S6. Give a source for the split of the 4.38 s

**Where:** Section VI-A.

**Why:** "about 2.3 s ... about 0.7 s ... about 0.1 s" is not in the exported results. The compiler records
stage times in each envelope's `timings_ms` on the VM. Keep the sentence if the numbers come from there, as
medians of the same five compiles; otherwise delete "Most of this time is spent ... about 0.1 s."

## Polish

- **P1.** Use one name for the signature baseline. The text says "signature-only admission" and
  "signature-only verification"; Fig. 4 and Table VIII say "Signature check".
- **P2.** The abstract and Section VI-A say 4.38 s, Section VII says 4.4 s. Pick one.
- **P3.** The report renumbers the experiments. Report E1 (compile time) is the results pack's E4, E2
  (detection) is E1, E3 (attribution) is E2, E4 (trust) is E3, and E5 (cost) keeps its number. Say so if the
  supervisor compares the report with the results pack.

## Still to check by hand

- Reference [31] (SynthChain): its six authors came from a search result, because arxiv.org could not be
  reached from the cloud session. Compare them with the arXiv page; the newest arXiv version may carry a new
  title.
